package config

import (
	"encoding/json"
	"os"
	"sync"
)

type Settings struct {
	ConfigPath    string   `json:"config_path"`
	Subscriptions []string `json:"subscriptions"`
}

type Manager struct {
	mu       sync.RWMutex
	Settings Settings
	path     string
}

func NewManager(path string) *Manager {
	return &Manager{path: path}
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			m.Settings = Settings{Subscriptions: []string{}}
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &m.Settings)
}

func (m *Manager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, err := json.MarshalIndent(m.Settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}
