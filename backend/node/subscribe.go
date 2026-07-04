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

// FetchSubscription fetches and parses a subscription URL.
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
	for i := range nodes {
		nodes[i].SubURL = rawURL
	}
	return nodes, nil
}

// ─── sing-box JSON ────────────────────────────────────────────────────────────

type singboxOutbound struct {
	Type       string      `json:"type"`
	Tag        string      `json:"tag"`
	Server     string      `json:"server"`
	ServerPort int         `json:"server_port"`
	UUID       string      `json:"uuid,omitempty"`
	Password   string      `json:"password,omitempty"`
	Method     string      `json:"method,omitempty"`
}

type singboxConfig struct {
	Outbounds []singboxOutbound `json:"outbounds"`
}

var skipOutboundTypes = map[string]bool{
	"direct": true, "block": true, "dns": true,
	"selector": true, "urltest": true, "": true,
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
	for _, ob := range cfg.Outbounds {
		if skipOutboundTypes[ob.Type] || ob.Server == "" {
			continue
		}
		n := Node{
			ID: newID(), Name: ob.Tag,
			Address: ob.Server, Port: ob.ServerPort,
			Protocol: ob.Type,
		}
		switch ob.Type {
		case "vmess":
			n.VMess = &VMessConfig{UUID: ob.UUID, Security: "auto"}
		case "vless":
			n.VLESS = &VLESSConfig{UUID: ob.UUID}
		case "trojan":
			n.Trojan = &TrojanConfig{Password: ob.Password}
		case "shadowsocks":
			n.Protocol = "ss"
			n.SS = &SSConfig{Method: ob.Method, Password: ob.Password}
		case "hysteria2":
			n.Hysteria2 = &Hysteria2Config{Password: ob.Password}
		case "tuic":
			n.TUIC = &TUICConfig{UUID: ob.UUID, Password: ob.Password, CongestionControl: "cubic"}
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

	n := &Node{ID: newID(), Name: name, Address: server, Port: port}

	switch t {
	case "vmess":
		uuid, _ := p["uuid"].(string)
		cipher, _ := p["cipher"].(string)
		alterId := toInt(p["alterId"])
		tls, _ := p["tls"].(bool)
		sni, _ := p["servername"].(string)
		network, _ := p["network"].(string)
		transport := clashBuildTransport(normalizeNetwork(network), p)
		n.Protocol = "vmess"
		n.VMess = &VMessConfig{
			UUID:      uuid,
			AlterID:   alterId,
			Security:  orDefault(cipher, "auto"),
			TLS:       tls,
			SNI:       sni,
			Transport: transport,
		}

	case "vless":
		uuid, _ := p["uuid"].(string)
		network, _ := p["network"].(string)
		tls, _ := p["tls"].(bool)
		sni, _ := p["servername"].(string)
		flow, _ := p["flow"].(string)
		fp, _ := p["client-fingerprint"].(string)
		transport := clashBuildTransport(normalizeNetwork(network), p)
		// Reality
		var pubKey, shortID string
		if ro, ok := p["reality-opts"].(map[string]interface{}); ok {
			pubKey, _ = ro["public-key"].(string)
			shortID, _ = ro["short-id"].(string)
			tls = true
		}
		n.Protocol = "vless"
		n.VLESS = &VLESSConfig{
			UUID: uuid, Flow: flow, TLS: tls, SNI: sni,
			Fingerprint: fp, PublicKey: pubKey, ShortID: shortID,
			Transport: transport,
		}

	case "trojan":
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		network, _ := p["network"].(string)
		transport := clashBuildTransport(normalizeNetwork(network), p)
		n.Protocol = "trojan"
		n.Trojan = &TrojanConfig{Password: password, SNI: sni, Transport: transport}

	case "ss", "shadowsocks":
		cipher, _ := p["cipher"].(string)
		password, _ := p["password"].(string)
		plugin, _ := p["plugin"].(string)
		var pluginOpts string
		if po, ok := p["plugin-opts"].(map[string]interface{}); ok {
			// convert map to k=v;k=v string
			var parts []string
			for k, v := range po {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
			pluginOpts = strings.Join(parts, ";")
		}
		n.Protocol = "ss"
		n.SS = &SSConfig{Method: cipher, Password: password, Plugin: plugin, PluginOpts: pluginOpts}

	case "hysteria2", "hy2":
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		insecure, _ := p["skip-cert-verify"].(bool)
		obfs, _ := p["obfs"].(string)
		obfsPass, _ := p["obfs-password"].(string)
		n.Protocol = "hysteria2"
		n.Hysteria2 = &Hysteria2Config{
			Password: password, SNI: sni, Insecure: insecure,
			Obfs: obfs, ObfsPassword: obfsPass,
		}

	case "tuic":
		uuid, _ := p["uuid"].(string)
		password, _ := p["password"].(string)
		sni, _ := p["sni"].(string)
		cc, _ := p["congestion-controller"].(string)
		udpMode, _ := p["udp-relay-mode"].(string)
		insecure, _ := p["skip-cert-verify"].(bool)
		n.Protocol = "tuic"
		n.TUIC = &TUICConfig{
			UUID: uuid, Password: password, SNI: sni,
			CongestionControl: orDefault(cc, "cubic"),
			UDPRelayMode: udpMode, Insecure: insecure,
		}

	default:
		return nil, fmt.Errorf("unsupported clash proxy type: %s", t)
	}
	return n, nil
}

// clashBuildTransport parses Clash proxy map transport opts into a TransportConfig.
// Clash uses per-network "*-opts" blocks:
//   ws-opts:        { path, headers: {Host}, max-early-data, early-data-header-name }
//   h2-opts:        { host: [], path }
//   grpc-opts:      { grpc-service-name }
//   httpupgrade-opts: { path, host }
func clashBuildTransport(network string, p map[string]interface{}) *TransportConfig {
	if network == "" {
		return nil
	}
	t := &TransportConfig{Type: network}
	switch network {
	case "ws":
		if opts, ok := p["ws-opts"].(map[string]interface{}); ok {
			t.Path, _ = opts["path"].(string)
			if hdrs, ok := opts["headers"].(map[string]interface{}); ok {
				t.Host, _ = hdrs["Host"].(string)
				if t.Host == "" {
					t.Host, _ = hdrs["host"].(string)
				}
			}
			if ed := toInt(opts["max-early-data"]); ed > 0 {
				t.MaxEarlyData = ed
				t.EarlyDataHeaderName = orDefault(
					stringVal(opts["early-data-header-name"]),
					"Sec-WebSocket-Protocol",
				)
			}
		}
	case "http":
		if opts, ok := p["h2-opts"].(map[string]interface{}); ok {
			t.Path, _ = opts["path"].(string)
			// h2-opts.host is []string
			if hosts, ok := opts["host"].([]interface{}); ok && len(hosts) > 0 {
				t.Host, _ = hosts[0].(string)
			}
		}
	case "grpc":
		if opts, ok := p["grpc-opts"].(map[string]interface{}); ok {
			t.ServiceName, _ = opts["grpc-service-name"].(string)
		}
	case "httpupgrade":
		if opts, ok := p["httpupgrade-opts"].(map[string]interface{}); ok {
			t.Path, _ = opts["path"].(string)
			t.Host, _ = opts["host"].(string)
		}
	}
	return t
}

func stringVal(v interface{}) string {
	s, _ := v.(string)
	return s
}
