package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
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
	// configs 目录(与 data 同级, 存放 sing-box 配置 json)
	os.MkdirAll(getConfigsDir(), 0755)

	// SQLite 节点存储
	a.nodeStore = node.NewStore(filepath.Join(dataDir, "nodes.db"))
	a.cfgManager = config.NewManager(filepath.Join(dataDir, "settings.json"))
	a.proxy = sysproxy.NewManager()

	a.nodeStore.Load()
	a.cfgManager.Load()

	// sing-box 进程（日志上限取自设置）
	a.sbProcess = singbox.NewProcess(a.cfgManager.Settings.LogMaxLines)
}

func (a *App) shutdown(ctx context.Context) {
	// 退出时按设置还原系统代理（需在杀掉 sing-box 前执行，避免残留）
	if a.cfgManager != nil && a.cfgManager.Settings.ExitDisableProxy && a.proxy != nil {
		a.proxy.Disable()
	}
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

// getConfigsDir returns the configs directory next to the executable
// (same level as the data dir). It holds sing-box config json files.
func getConfigsDir() string {
	return filepath.Join(filepath.Dir(getDataDir()), "configs")
}

// ensureConfigsDir creates the configs dir if missing.
func ensureConfigsDir() {
	os.MkdirAll(getConfigsDir(), 0755)
}

// GetConfigFiles lists *.json files in the configs directory (sorted by name).
// The directory is created on demand.
func (a *App) GetConfigFiles() []string {
	return guardP("GetConfigFiles", func() []string {
		ensureConfigsDir()
		entries, err := os.ReadDir(getConfigsDir())
		if err != nil {
			return []string{}
		}
		var files []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(e.Name()), ".json") {
				files = append(files, e.Name())
			}
		}
		sort.Strings(files)
		if files == nil {
			files = []string{}
		}
		return files
	})
}

// SelectConfigFile selects a config from the configs directory by filename.
// (Replaces the native file dialog: the dropdown lists configs/*.json.)
func (a *App) SelectConfigFile(name string) (string, error) {
	return guardR("SelectConfigFile", func() (string, error) {
		if a.cfgManager == nil {
			return "", fmt.Errorf("设置尚未就绪，请重启应用")
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return "", fmt.Errorf("未指定配置文件")
		}
		// 安全检查: 只允许纯文件名, 禁止路径穿越
		if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || filepath.Base(name) != name {
			return "", fmt.Errorf("非法文件名: %s", name)
		}
		full := filepath.Join(getConfigsDir(), name)
		if st, err := os.Stat(full); err != nil || st.IsDir() {
			return "", fmt.Errorf("配置文件不存在: %s", name)
		}
		a.cfgManager.Settings.ConfigPath = full
		if err := a.cfgManager.Save(); err != nil {
			return "", fmt.Errorf("保存设置失败: %v", err)
		}
		return full, nil
	})
}

// OpenConfigsDir opens the configs directory in Windows Explorer.
func (a *App) OpenConfigsDir() error {
	return guardE("OpenConfigsDir", func() error {
		ensureConfigsDir()
		return exec.Command("explorer.exe", getConfigsDir()).Start()
	})
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
		nodes, err := node.FetchSubscription(url,
			a.cfgManager.Settings.SubUserAgent,
			a.cfgManager.Settings.SubTimeoutSec)
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
// 若核心正在运行，则先停核心、改配置、再拉起（保证新节点即时生效）
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
		wasRunning := a.sbProcess.GetStatus().Running
		if wasRunning {
			if err := a.sbProcess.Stop(); err != nil {
				return fmt.Errorf("停止核心失败: %v", err)
			}
		}
		if err := config.ApplyNodeToConfig(cfgPath, *n); err != nil {
			return err
		}
		if wasRunning {
			if err := a.sbProcess.Start(getSingBoxBin(), cfgPath); err != nil {
				return fmt.Errorf("节点已写入配置，但核心重启失败: %v（请手动启动核心）", err)
			}
		}
		return nil
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

// GetSettings returns the full settings object.
func (a *App) GetSettings() config.Settings {
	return guardP("GetSettings", func() config.Settings {
		if a.cfgManager == nil {
			return config.Defaults()
		}
		return a.cfgManager.Settings
	})
}

// SaveSettings validates and persists the full settings object.
// 部分设置（日志上限）立即生效；代理/TUN 相关设置在下次开启时生效。
func (a *App) SaveSettings(s config.Settings) error {
	return guardE("SaveSettings", func() error {
		if a.cfgManager == nil {
			return fmt.Errorf("设置尚未就绪，请重启应用")
		}
		s.ProxyListen = strings.TrimSpace(s.ProxyListen)
		s.SubUserAgent = strings.TrimSpace(s.SubUserAgent)
		s.Normalize()
		if err := s.Validate(); err != nil {
			return err
		}
		a.cfgManager.Settings = s
		if err := a.cfgManager.Save(); err != nil {
			return fmt.Errorf("保存设置失败: %v", err)
		}
		// 立即生效的设置
		a.sbProcess.SetMaxLog(s.LogMaxLines)
		return nil
	})
}

// GetAppliedNodeID 找出配置文件中当前 "proxy" outbound 对应的节点 ID。
// 无匹配（含未选配置/手工改配置）返回 ""。
func (a *App) GetAppliedNodeID() string {
	return guardP("GetAppliedNodeID", func() string {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return ""
		}
		return config.FindAppliedNodeID(cfgPath, a.nodeStore.GetAll())
	})
}

// The old native file dialog has been replaced by the configs-dir dropdown:
// see GetConfigFiles / SelectConfigFile(name) / OpenConfigsDir.

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
		nodes, err := node.FetchSubscription(url,
			a.cfgManager.Settings.SubUserAgent,
			a.cfgManager.Settings.SubTimeoutSec)
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
		s := a.cfgManager.Settings
		return config.SetTun(cfgPath, true, s.TunStack, s.TunMTU, s.TunStrictRoute)
	})
}

func (a *App) DisableTun() error {
	return guardE("DisableTun", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		return config.SetTun(cfgPath, false, "", 0, false)
	})
}

// ─── System Proxy APIs ───────────────────────────────────────────────────────

func (a *App) EnableSystemProxy() error {
	return guardE("EnableSystemProxy", func() error {
		cfgPath := a.cfgManager.Settings.ConfigPath
		if cfgPath == "" {
			return fmt.Errorf("未选择配置文件")
		}
		s := a.cfgManager.Settings
		if err := config.SetMixedInbound(cfgPath, true, s.ProxyListen, s.ProxyPort); err != nil {
			return err
		}
		// Windows 系统代理地址固定为 127.0.0.1（监听地址可以是 0.0.0.0/::，但注册表里不能）
		return a.proxy.Enable("127.0.0.1", s.ProxyPort)
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
