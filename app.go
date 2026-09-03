package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"singbox-gui/backend/config"
	"singbox-gui/backend/node"
	"singbox-gui/backend/singbox"
	"singbox-gui/backend/sysproxy"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx        context.Context
	nodeStore  *node.Store
	cfgManager *config.Manager
	sbProcess  *singbox.Process
	proxy      *sysproxy.Manager
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// if startup itself panics, record it instead of dying silently
	defer func() {
		if r := recover(); r != nil {
			appendCrashLog(fmt.Sprintf("===== %s | startup panic: %v =====\n%s\n",
				time.Now().Format("2006-01-02 15:04:05"), r, debug.Stack()))
		}
	}()

	// init data dir
	dataDir := getDataDir()
	os.MkdirAll(dataDir, 0755)

	// SQLite 节点存储
	a.nodeStore = node.NewStore(filepath.Join(dataDir, "nodes.db"))
	a.cfgManager = config.NewManager(filepath.Join(dataDir, "settings.json"))
	a.sbProcess = singbox.NewProcess()
	a.proxy = sysproxy.NewManager()

	a.nodeStore.Load()
	a.cfgManager.Load()
}

func (a *App) shutdown(ctx context.Context) {
	// cleanup on exit: kill singbox if running
	a.sbProcess.Stop()
	// close node database
	if a.nodeStore != nil {
		a.nodeStore.Close()
	}
}

func getDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

// ─── Crash guard ──────────────────────────────────────────────────────────────
// Wails bindings run on their own goroutines — an unrecovered panic there kills
// the whole process with no visible output (GUI build). These wrappers recover
// panics, append the full stack to data/crash.log, and turn the panic into a
// normal error the frontend can show.

func crashLogPath() string {
	return filepath.Join(getDataDir(), "crash.log")
}

func appendCrashLog(content string) {
	f, err := os.OpenFile(crashLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[crash] cannot write crash.log:", err)
		return
	}
	defer f.Close()
	f.WriteString(content)
}

func writeCrash(name string, r interface{}) {
	appendCrashLog(fmt.Sprintf("===== %s | [%s] panic: %v =====\n%s\n",
		time.Now().Format("2006-01-02 15:04:05"), name, r, debug.Stack()))
}

// guardP wraps a binding returning a plain value.
func guardP[T any](name string, fn func() T) (result T) {
	defer func() {
		if r := recover(); r != nil {
			writeCrash(name, r)
			var zero T
			result = zero
		}
	}()
	return fn()
}

// guardE wraps a binding returning only an error.
func guardE(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			writeCrash(name, r)
			err = fmt.Errorf("内部错误: %v (详情见 data/crash.log)", r)
		}
	}()
	return fn()
}

// guardR wraps a binding returning (value, error).
func guardR[T any](name string, fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			writeCrash(name, r)
			var zero T
			result, err = zero, fmt.Errorf("内部错误: %v (详情见 data/crash.log)", r)
		}
	}()
	return fn()
}

// ─── Node APIs ───────────────────────────────────────────────────────────────

func (a *App) GetNodes() []node.Node {
	return guardP("GetNodes", func() []node.Node {
		return a.nodeStore.GetAll()
	})
}

func (a *App) ImportNodes(content, groupID string) (int, error) {
	return guardR("ImportNodes", func() (int, error) {
		nodes, err := node.ParseContent(content)
		if err != nil {
			return 0, err
		}
		gid := node.DefaultGroupID
		if a.nodeStore.GroupExists(groupID) {
			gid = groupID
		}
		for i := range nodes {
			nodes[i].GroupID = gid
		}
		a.nodeStore.AddMany(nodes)
		return len(nodes), a.nodeStore.Save()
	})
}

func (a *App) FetchSubscription(url, groupID string) (int, error) {
	return guardR("FetchSubscription", func() (int, error) {
		nodes, err := node.FetchSubscription(url)
		if err != nil {
			return 0, err
		}
		gid := node.DefaultGroupID
		if a.nodeStore.GroupExists(groupID) {
			gid = groupID
		}
		for i := range nodes {
			nodes[i].GroupID = gid
		}
		a.nodeStore.AddMany(nodes)
		if err := a.nodeStore.Save(); err != nil {
			return 0, err
		}
		// save sub url
		a.cfgManager.Settings.Subscriptions = appendUnique(a.cfgManager.Settings.Subscriptions, url)
		a.cfgManager.Save()
		return len(nodes), nil
	})
}

func (a *App) ClearNodes() error {
	return guardE("ClearNodes", func() error {
		a.nodeStore.Clear()
		return a.nodeStore.Save()
	})
}

func (a *App) DeleteNode(id string) error {
	return guardE("DeleteNode", func() error {
		a.nodeStore.Delete(id)
		return a.nodeStore.Save()
	})
}

func (a *App) UpdateNode(n node.Node) error {
	return guardE("UpdateNode", func() error {
		a.nodeStore.Update(n)
		return a.nodeStore.Save()
	})
}

// ApplyNode: replace the "proxy" outbound in config file with this node
func (a *App) ApplyNode(id string) error {
	return guardE("ApplyNode", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		n := a.nodeStore.Get(id)
		if n == nil {
			return fmt.Errorf("节点不存在")
		}
		return config.ApplyNodeToConfig(cfgPath, *n)
	})
}

// ExportNodeURI converts a node back to its share URI (e.g. vless://...)
func (a *App) ExportNodeURI(id string) (string, error) {
	return guardR("ExportNodeURI", func() (string, error) {
		n := a.nodeStore.Get(id)
		if n == nil {
			return "", fmt.Errorf("节点不存在")
		}
		return node.NodeToURI(*n)
	})
}

// MoveNodeUp moves the node one position up within its group
func (a *App) MoveNodeUp(id string) error {
	return guardE("MoveNodeUp", func() error {
		if !a.nodeStore.Move(id, -1) {
			return fmt.Errorf("已在顶部")
		}
		return a.nodeStore.Save()
	})
}

// MoveNodeDown moves the node one position down within its group
func (a *App) MoveNodeDown(id string) error {
	return guardE("MoveNodeDown", func() error {
		if !a.nodeStore.Move(id, 1) {
			return fmt.Errorf("已在底部")
		}
		return a.nodeStore.Save()
	})
}

// ─── Config file APIs ────────────────────────────────────────────────────────

func (a *App) GetSettings() config.Settings {
	return guardP("GetSettings", func() config.Settings {
		if a.cfgManager == nil {
			return config.Settings{}
		}
		return a.cfgManager.Settings
	})
}

// SelectConfigFile opens the native file dialog. Hardened: nil-context safe,
// user-cancel returns ("", nil), and any panic is recovered by guardR.
func (a *App) SelectConfigFile() (string, error) {
	return guardR("SelectConfigFile", func() (string, error) {
		if a.ctx == nil {
			return "", fmt.Errorf("应用尚未初始化完成，请稍后重试")
		}
		if a.cfgManager == nil {
			return "", fmt.Errorf("设置尚未就绪，请重启应用")
		}
		path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
			Title: "选择 sing-box 配置文件",
			Filters: []runtime.FileFilter{
				{DisplayName: "JSON 配置文件", Pattern: "*.json"},
				{DisplayName: "所有文件", Pattern: "*.*"},
			},
		})
		if err != nil {
			// dialog failure must not kill the app — report it as a normal error
			return "", fmt.Errorf("打开文件对话框失败: %v", err)
		}
		if path == "" {
			return "", nil // user cancelled
		}
		a.cfgManager.Settings.ConfigPath = path
		if err := a.cfgManager.Save(); err != nil {
			return "", fmt.Errorf("保存设置失败: %v", err)
		}
		return path, nil
	})
}

func (a *App) GetSubscriptions() []string {
	return guardP("GetSubscriptions", func() []string {
		if a.cfgManager == nil {
			return []string{}
		}
		return a.cfgManager.Settings.Subscriptions
	})
}

func (a *App) RemoveSubscription(url string) error {
	return guardE("RemoveSubscription", func() error {
		subs := a.cfgManager.Settings.Subscriptions
		newSubs := []string{}
		for _, s := range subs {
			if s != url {
				newSubs = append(newSubs, s)
			}
		}
		a.cfgManager.Settings.Subscriptions = newSubs
		return a.cfgManager.Save()
	})
}

func (a *App) RefreshSubscription(url, groupID string) (int, error) {
	return guardR("RefreshSubscription", func() (int, error) {
		nodes, err := node.FetchSubscription(url)
		if err != nil {
			return 0, err
		}
		gid := node.DefaultGroupID
		if a.nodeStore.GroupExists(groupID) {
			gid = groupID
		}
		// remove old nodes from this sub, add new
		a.nodeStore.RemoveBySubscription(url)
		for i := range nodes {
			nodes[i].SubURL = url
			nodes[i].GroupID = gid
		}
		a.nodeStore.AddMany(nodes)
		return len(nodes), a.nodeStore.Save()
	})
}

// ─── Group APIs ────────────────────────────────────────────────────────────────

func (a *App) GetGroups() []node.Group {
	return guardP("GetGroups", func() []node.Group {
		return a.nodeStore.GetGroups()
	})
}

// AddGroup creates a new group right after afterID ("": append at end)
func (a *App) AddGroup(name, afterID string) (node.Group, error) {
	return guardR("AddGroup", func() (node.Group, error) {
		return a.nodeStore.AddGroup(name, afterID)
	})
}

func (a *App) RenameGroup(id, name string) error {
	return guardE("RenameGroup", func() error {
		return a.nodeStore.RenameGroup(id, name)
	})
}

// DeleteGroup removes a group; its nodes move into the 默认 group
func (a *App) DeleteGroup(id string) error {
	return guardE("DeleteGroup", func() error {
		return a.nodeStore.DeleteGroup(id)
	})
}

// ─── TUN APIs ────────────────────────────────────────────────────────────────

func (a *App) EnableTun() error {
	return guardE("EnableTun", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		return config.SetTun(cfgPath, true)
	})
}

func (a *App) DisableTun() error {
	return guardE("DisableTun", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		return config.SetTun(cfgPath, false)
	})
}

// ─── System Proxy APIs ───────────────────────────────────────────────────────

func (a *App) EnableSystemProxy() error {
	return guardE("EnableSystemProxy", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		if err := config.SetMixedInbound(cfgPath, true); err != nil {
			return err
		}
		return a.proxy.Enable("127.0.0.1", 2080)
	})
}

func (a *App) DisableSystemProxy() error {
	return guardE("DisableSystemProxy", func() error {
		return a.proxy.Disable()
	})
}

// ─── SingBox process APIs ─────────────────────────────────────────────────────

func (a *App) StartSingBox() error {
	return guardE("StartSingBox", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		binPath := getSingBoxBin()
		return a.sbProcess.Start(binPath, cfgPath)
	})
}

func (a *App) StopSingBox() error {
	return guardE("StopSingBox", func() error {
		return a.sbProcess.Stop()
	})
}

func (a *App) GetSingBoxStatus() singbox.Status {
	return guardP("GetSingBoxStatus", func() singbox.Status {
		return a.sbProcess.GetStatus()
	})
}

func (a *App) GetSingBoxLog() []string {
	return guardP("GetSingBoxLog", func() []string {
		return a.sbProcess.GetLog()
	})
}

func getSingBoxBin() string {
	exe, err := os.Executable()
	if err != nil {
		return "bin/sing-box.exe"
	}
	return filepath.Join(filepath.Dir(exe), "bin", "sing-box.exe")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func (a *App) ShowMessage(title, msg string) {
	defer func() {
		if r := recover(); r != nil {
			writeCrash("ShowMessage", r)
		}
	}()
	runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Type:    runtime.InfoDialog,
		Title:   title,
		Message: msg,
	})
}

// GetConfigPreview returns formatted JSON of current config for display
func (a *App) GetConfigPreview() (string, error) {
	return guardR("GetConfigPreview", func() (string, error) {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return "", fmt.Errorf("未选择配置文件")
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return "", err
		}
		var obj interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			return "", err
		}
		pretty, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return "", err
		}
		return string(pretty), nil
	})
}
