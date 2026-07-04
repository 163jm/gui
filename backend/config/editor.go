package config

import (
	"encoding/json"
	"fmt"
	"os"

	"singbox-gui/backend/node"
)

// loadJSON reads and parses a sing-box config file
func loadJSON(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}
	return cfg, nil
}

// saveJSON writes a config map back to file
func saveJSON(path string, cfg map[string]interface{}) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// getInbounds returns the inbounds slice from config
func getInbounds(cfg map[string]interface{}) []interface{} {
	v, _ := cfg["inbounds"].([]interface{})
	return v
}

// getOutbounds returns the outbounds slice from config
func getOutbounds(cfg map[string]interface{}) []interface{} {
	v, _ := cfg["outbounds"].([]interface{})
	return v
}

// ─── Apply Node ───────────────────────────────────────────────────────────────

// ApplyNodeToConfig replaces or creates the "proxy" tagged outbound
func ApplyNodeToConfig(cfgPath string, n node.Node) error {
	cfg, err := loadJSON(cfgPath)
	if err != nil {
		return err
	}

	outbound, err := nodeToSingBoxOutbound(n)
	if err != nil {
		return err
	}

	outbounds := getOutbounds(cfg)
	replaced := false
	for i, ob := range outbounds {
		if m, ok := ob.(map[string]interface{}); ok {
			if m["tag"] == "proxy" {
				outbound["tag"] = "proxy"
				outbounds[i] = outbound
				replaced = true
				break
			}
		}
	}
	if !replaced {
		outbound["tag"] = "proxy"
		outbounds = append(outbounds, outbound)
	}
	cfg["outbounds"] = outbounds

	return saveJSON(cfgPath, cfg)
}

// nodeToSingBoxOutbound converts a Node to sing-box outbound map
func nodeToSingBoxOutbound(n node.Node) (map[string]interface{}, error) {
	ob := map[string]interface{}{
		"tag":         "proxy",
		"server":      n.Address,
		"server_port": n.Port,
	}

	switch n.Protocol {
	case "vmess":
		if n.VMess == nil {
			return nil, fmt.Errorf("VMess config is nil")
		}
		ob["type"] = "vmess"
		ob["uuid"] = n.VMess.UUID
		ob["alter_id"] = n.VMess.AlterID
		ob["security"] = n.VMess.Security
		addTransport(ob, n.VMess.Network, n.VMess.Path, n.VMess.Host)
		if n.VMess.TLS {
			addTLS(ob, n.VMess.SNI, n.VMess.ALPN, false, "")
		}

	case "vless":
		if n.VLESS == nil {
			return nil, fmt.Errorf("VLESS config is nil")
		}
		ob["type"] = "vless"
		ob["uuid"] = n.VLESS.UUID
		if n.VLESS.Flow != "" {
			ob["flow"] = n.VLESS.Flow
		}
		addTransport(ob, n.VLESS.Network, n.VLESS.Path, n.VLESS.Host)
		if n.VLESS.TLS {
			if n.VLESS.PublicKey != "" {
				// Reality
				addReality(ob, n.VLESS.SNI, n.VLESS.PublicKey, n.VLESS.ShortID, n.VLESS.Fingerprint)
			} else {
				addTLS(ob, n.VLESS.SNI, n.VLESS.ALPN, false, n.VLESS.Fingerprint)
			}
		}

	case "trojan":
		if n.Trojan == nil {
			return nil, fmt.Errorf("Trojan config is nil")
		}
		ob["type"] = "trojan"
		ob["password"] = n.Trojan.Password
		addTransport(ob, n.Trojan.Network, "", "")
		addTLS(ob, n.Trojan.SNI, n.Trojan.ALPN, false, "")

	case "ss":
		if n.SS == nil {
			return nil, fmt.Errorf("SS config is nil")
		}
		ob["type"] = "shadowsocks"
		ob["method"] = n.SS.Method
		ob["password"] = n.SS.Password

	case "hysteria2":
		if n.Hysteria2 == nil {
			return nil, fmt.Errorf("Hysteria2 config is nil")
		}
		ob["type"] = "hysteria2"
		ob["password"] = n.Hysteria2.Password
		tlsCfg := map[string]interface{}{}
		if n.Hysteria2.SNI != "" {
			tlsCfg["server_name"] = n.Hysteria2.SNI
		}
		if n.Hysteria2.Insecure {
			tlsCfg["insecure"] = true
		}
		if len(n.Hysteria2.ALPN) > 0 {
			tlsCfg["alpn"] = n.Hysteria2.ALPN
		}
		if len(tlsCfg) > 0 {
			ob["tls"] = tlsCfg
		}
		if n.Hysteria2.Obfs != "" {
			ob["obfs"] = map[string]interface{}{
				"type":     n.Hysteria2.Obfs,
				"password": n.Hysteria2.ObfsPassword,
			}
		}

	case "tuic":
		if n.TUIC == nil {
			return nil, fmt.Errorf("TUIC config is nil")
		}
		ob["type"] = "tuic"
		ob["uuid"] = n.TUIC.UUID
		ob["password"] = n.TUIC.Password
		ob["congestion_control"] = orDefault(n.TUIC.CongestionControl, "bbr")
		tlsCfg := map[string]interface{}{"enabled": true}
		if n.TUIC.SNI != "" {
			tlsCfg["server_name"] = n.TUIC.SNI
		}
		if n.TUIC.Insecure {
			tlsCfg["insecure"] = true
		}
		if len(n.TUIC.ALPN) > 0 {
			tlsCfg["alpn"] = n.TUIC.ALPN
		}
		ob["tls"] = tlsCfg

	default:
		return nil, fmt.Errorf("不支持的协议: %s", n.Protocol)
	}

	return ob, nil
}

func addTransport(ob map[string]interface{}, network, path, host string) {
	if network == "" || network == "tcp" {
		return
	}
	transport := map[string]interface{}{
		"type": network,
	}
	switch network {
	case "ws":
		if path != "" {
			transport["path"] = path
		}
		if host != "" {
			transport["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
	case "grpc":
		if path != "" {
			transport["service_name"] = path
		}
	case "http":
		if path != "" {
			transport["path"] = []string{path}
		}
		if host != "" {
			transport["host"] = []string{host}
		}
	}
	ob["transport"] = transport
}

func addTLS(ob map[string]interface{}, sni string, alpn []string, insecure bool, fingerprint string) {
	tls := map[string]interface{}{"enabled": true}
	if sni != "" {
		tls["server_name"] = sni
	}
	if insecure {
		tls["insecure"] = true
	}
	if len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	ob["tls"] = tls
}

func addReality(ob map[string]interface{}, sni, publicKey, shortID, fingerprint string) {
	tls := map[string]interface{}{
		"enabled": true,
		"reality": map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   shortID,
		},
	}
	if sni != "" {
		tls["server_name"] = sni
	}
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	ob["tls"] = tls
}

// ─── TUN ──────────────────────────────────────────────────────────────────────

var tunInbound = map[string]interface{}{
	"type":           "tun",
	"tag":            "tun-in",
	"interface_name": "singbox_tun",
	"address":        []string{"172.18.0.1/30"},
	"mtu":            9000,
	"auto_route":     true,
	"strict_route":   true,
	"stack":          "gvisor",
}

func SetTun(cfgPath string, enable bool) error {
	cfg, err := loadJSON(cfgPath)
	if err != nil {
		return err
	}

	inbounds := getInbounds(cfg)

	// remove existing tun
	newInbounds := []interface{}{}
	for _, ib := range inbounds {
		if m, ok := ib.(map[string]interface{}); ok {
			if m["type"] == "tun" {
				continue
			}
		}
		newInbounds = append(newInbounds, ib)
	}

	if enable {
		newInbounds = append(newInbounds, tunInbound)
	}

	cfg["inbounds"] = newInbounds
	return saveJSON(cfgPath, cfg)
}

// ─── Mixed Inbound ────────────────────────────────────────────────────────────

const MixedPort = 2080

func SetMixedInbound(cfgPath string, enable bool) error {
	cfg, err := loadJSON(cfgPath)
	if err != nil {
		return err
	}

	inbounds := getInbounds(cfg)

	// remove existing mixed
	newInbounds := []interface{}{}
	for _, ib := range inbounds {
		if m, ok := ib.(map[string]interface{}); ok {
			if m["type"] == "mixed" {
				continue
			}
		}
		newInbounds = append(newInbounds, ib)
	}

	if enable {
		mixed := map[string]interface{}{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": MixedPort,
		}
		newInbounds = append(newInbounds, mixed)
	}

	cfg["inbounds"] = newInbounds
	return saveJSON(cfgPath, cfg)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
