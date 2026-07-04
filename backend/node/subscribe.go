package node

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FetchSubscription fetches and parses a subscription URL
func FetchSubscription(rawURL string) ([]Node, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clash.meta")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	nodes, err := ParseContent(string(body))
	if err != nil {
		return nil, fmt.Errorf("解析失败: %v", err)
	}
	// tag all nodes with sub url
	for i := range nodes {
		nodes[i].SubURL = rawURL
	}
	return nodes, nil
}

// ─── sing-box JSON ────────────────────────────────────────────────────────────

type singboxOutbound struct {
	Type     string `json:"type"`
	Tag      string `json:"tag"`
	Server   string `json:"server"`
	ServerPort int  `json:"server_port"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	// add more fields as needed for identification
}

type singboxConfig struct {
	Outbounds []singboxOutbound `json:"outbounds"`
}

func parseSingBoxJSON(content string) ([]Node, error) {
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, "{") {
		return nil, fmt.Errorf("not json")
	}
	var cfg singboxConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	var nodes []Node
	skipTypes := map[string]bool{
		"direct": true, "block": true, "dns": true,
		"selector": true, "urltest": true, "": true,
	}
	for _, ob := range cfg.Outbounds {
		if skipTypes[ob.Type] {
			continue
		}
		if ob.Server == "" {
			continue
		}
		n := Node{
			ID:       newID(),
			Name:     ob.Tag,
			Address:  ob.Server,
			Port:     ob.ServerPort,
			Protocol: ob.Type,
		}
		switch ob.Type {
		case "vmess":
			n.VMess = &VMessConfig{UUID: ob.UUID}
		case "vless":
			n.VLESS = &VLESSConfig{UUID: ob.UUID}
		case "trojan":
			n.Trojan = &TrojanConfig{Password: ob.Password}
		case "shadowsocks":
			n.Protocol = "ss"
			n.SS = &SSConfig{Password: ob.Password}
		case "hysteria2":
			n.Hysteria2 = &Hysteria2Config{Password: ob.Password}
		case "tuic":
			n.TUIC = &TUICConfig{UUID: ob.UUID, Password: ob.Password}
		}
		if n.Name == "" {
			n.Name = fmt.Sprintf("%s-%s:%d", ob.Type, ob.Server, ob.ServerPort)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// ─── Clash YAML ───────────────────────────────────────────────────────────────

type clashConfig struct {
	Proxies []map[string]interface{} `yaml:"proxies"`
}

func parseClashYAML(content string) ([]Node, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies")
	}
	var nodes []Node
	for _, p := range cfg.Proxies {
		n, err := clashProxyToNode(p)
		if err != nil {
			continue
		}
		nodes = append(nodes, *n)
	}
	return nodes, nil
}

func clashProxyToNode(p map[string]interface{}) (*Node, error) {
	t, _ := p["type"].(string)
	name, _ := p["name"].(string)
	server, _ := p["server"].(string)
	port := toInt(p["port"])

	if server == "" || port == 0 {
		return nil, fmt.Errorf("invalid proxy")
	}

	n := &Node{
		ID:      newID(),
		Name:    name,
		Address: server,
		Port:    port,
	}

	switch t {
	case "vmess":
		uuid, _ := p["uuid"].(string)
		alterId := toInt(p["alterId"])
		cipher, _ := p["cipher"].(string)
		network, _ := p["network"].(string)
		tls, _ := p["tls"].(bool)
		wsPath, _ := p["ws-path"].(string)
		wsOpts, _ := p["ws-opts"].(map[string]interface{})
		if wsPath == "" && wsOpts != nil {
			wsPath, _ = wsOpts["path"].(string)
		}
		n.Protocol = "vmess"
		n.VMess = &VMessConfig{
			UUID:     uuid,
			AlterID:  alterId,
			Security: orDefault(cipher, "auto"),
			Network:  orDefault(network, "tcp"),
			TLS:      tls,
			Path:     wsPath,
		}
	case "vless":
		uuid, _ := p["uuid"].(string)
		network, _ := p["network"].(string)
		tls, _ := p["tls"].(bool)
		n.Protocol = "vless"
		n.VLESS = &VLESSConfig{
			UUID:    uuid,
			Network: orDefault(network, "tcp"),
			TLS:     tls,
		}
	case "trojan":
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		n.Protocol = "trojan"
		n.Trojan = &TrojanConfig{
			Password: password,
			Network:  "tcp",
			SNI:      sni,
		}
	case "ss", "shadowsocks":
		cipher, _ := p["cipher"].(string)
		password, _ := p["password"].(string)
		n.Protocol = "ss"
		n.SS = &SSConfig{
			Method:   cipher,
			Password: password,
		}
	case "hysteria2", "hy2":
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		n.Protocol = "hysteria2"
		n.Hysteria2 = &Hysteria2Config{
			Password: password,
			SNI:      sni,
		}
	case "tuic":
		uuid, _ := p["uuid"].(string)
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		n.Protocol = "tuic"
		n.TUIC = &TUICConfig{
			UUID:     uuid,
			Password: password,
			SNI:      sni,
		}
	default:
		return nil, fmt.Errorf("unsupported clash proxy type: %s", t)
	}
	return n, nil
}
