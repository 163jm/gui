package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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

	// init data dir
	dataDir := getDataDir()
	os.MkdirAll(dataDir, 0755)

	a.nodeStore = node.NewStore(filepath.Join(dataDir, "nodes.json"))
	a.cfgManager = config.NewManager(filepath.Join(dataDir, "settings.json"))
	a.sbProcess = singbox.NewProcess()
	a.proxy = sysproxy.NewManager()

	a.nodeStore.Load()
	a.cfgManager.Load()
}

func (a *App) shutdown(ctx context.Context) {
	// cleanup on exit: kill singbox if running
	a.sbProcess.Stop()
}

func getDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

// ─── Node APIs ───────────────────────────────────────────────────────────────

func (a *App) GetNodes() []node.Node {
	return a.nodeStore.GetAll()
}

func (a *App) ImportNodes(content string) (int, error) {
	nodes, err := node.ParseContent(content)
	if err != nil {
		return 0, err
	}
	a.nodeStore.AddMany(nodes)
	return len(nodes), a.nodeStore.Save()
}

func (a *App) FetchSubscription(url string) (int, error) {
	nodes, err := node.FetchSubscription(url)
	if err != nil {
		return 0, err
	}
	a.nodeStore.AddMany(nodes)
	if err := a.nodeStore.Save(); err != nil {
		return 0, err
	}
	// save sub url
	a.cfgManager.Settings.Subscriptions = appendUnique(a.cfgManager.Settings.Subscriptions, url)
	a.cfgManager.Save()
	return len(nodes), nil
}

func (a *App) ClearNodes() error {
	a.nodeStore.Clear()
	return a.nodeStore.Save()
}

func (a *App) DeleteNode(id string) error {
	a.nodeStore.Delete(id)
	return a.nodeStore.Save()
}

func (a *App) UpdateNode(n node.Node) error {
	a.nodeStore.Update(n)
	return a.nodeStore.Save()
}

// ApplyNode: replace the "proxy" outbound in config file with this node
func (a *App) ApplyNode(id string) error {
	cfgPath := a.cfgManager.Settings.ConfigPath
	if cfgPath == "" {
		return fmt.Errorf("未选择配置文件")
	}
	n := a.nodeStore.Get(id)
	if n == nil {
		return fmt.Errorf("节点不存在")
	}
	return config.ApplyNodeToConfig(cfgPath, *n)
}

// ─── Config file APIs ────────────────────────────────────────────────────────

func (a *App) GetSettings() config.Settings {
	return a.cfgManager.Settings
}

func (a *App) SelectConfigFile() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 sing-box 配置文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON 配置文件", Pattern: "*.json"},
			{DisplayName: "所有文件", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	a.cfgManager.Settings.ConfigPath = path
	a.cfgManager.Save()
	return path, nil
}

func (a *App) GetSubscriptions() []string {
	return a.cfgManager.Settings.Subscriptions
}

func (a *App) RemoveSubscription(url string) error {
	subs := a.cfgManager.Settings.Subscriptions
	newSubs := []string{}
	for _, s := range subs {
		if s != url {
			newSubs = append(newSubs, s)
		}
	}
	a.cfgManager.Settings.Subscriptions = newSubs
	return a.cfgManager.Save()
}

func (a *App) RefreshSubscription(url string) (int, error) {
	nodes, err := node.FetchSubscription(url)
	if err != nil {
		return 0, err
	}
	// remove old nodes from this sub, add new
	a.nodeStore.RemoveBySubscription(url)
	for i := range nodes {
		nodes[i].SubURL = url
	}
	a.nodeStore.AddMany(nodes)
	return len(nodes), a.nodeStore.Save()
}

// ─── TUN APIs ────────────────────────────────────────────────────────────────

func (a *App) EnableTun() error {
	cfgPath := a.cfgManager.Settings.ConfigPath
	if cfgPath == "" {
		return fmt.Errorf("未选择配置文件")
	}
	return config.SetTun(cfgPath, true)
}

func (a *App) DisableTun() error {
	cfgPath := a.cfgManager.Settings.ConfigPath
	if cfgPath == "" {
		return fmt.Errorf("未选择配置文件")
	}
	return config.SetTun(cfgPath, false)
}

// ─── System Proxy APIs ───────────────────────────────────────────────────────

func (a *App) EnableSystemProxy() error {
	cfgPath := a.cfgManager.Settings.ConfigPath
	if cfgPath == "" {
		return fmt.Errorf("未选择配置文件")
	}
	if err := config.SetMixedInbound(cfgPath, true); err != nil {
		return err
	}
	return a.proxy.Enable("127.0.0.1", 2080)
}

func (a *App) DisableSystemProxy() error {
	return a.proxy.Disable()
}

// ─── SingBox process APIs ─────────────────────────────────────────────────────

func (a *App) StartSingBox() error {
	cfgPath := a.cfgManager.Settings.ConfigPath
	if cfgPath == "" {
		return fmt.Errorf("未选择配置文件")
	}
	binPath := getSingBoxBin()
	return a.sbProcess.Start(binPath, cfgPath)
}

func (a *App) StopSingBox() error {
	return a.sbProcess.Stop()
}

func (a *App) GetSingBoxStatus() singbox.Status {
	return a.sbProcess.GetStatus()
}

func (a *App) GetSingBoxLog() []string {
	return a.sbProcess.GetLog()
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
	runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Type:    runtime.InfoDialog,
		Title:   title,
		Message: msg,
	})
}

// GetConfigPreview returns formatted JSON of current config for display
func (a *App) GetConfigPreview() (string, error) {
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
}
