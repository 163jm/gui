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

// saveJSON writes a config map back to file (pretty-printed)
func saveJSON(path string, cfg map[string]interface{}) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func getInbounds(cfg map[string]interface{}) []interface{} {
	v, _ := cfg["inbounds"].([]interface{})
	return v
}

func getOutbounds(cfg map[string]interface{}) []interface{} {
	v, _ := cfg["outbounds"].([]interface{})
	return v
}

// ─── Apply Node ───────────────────────────────────────────────────────────────

// ApplyNodeToConfig replaces or creates the "proxy" tagged outbound in a sing-box config file.
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

// nodeToSingBoxOutbound converts a Node to a sing-box outbound object.
// Field names and required fields are taken directly from the official sing-box documentation.
func nodeToSingBoxOutbound(n node.Node) (map[string]interface{}, error) {
	ob := map[string]interface{}{
		"tag":         "proxy",
		"server":      n.Address,
		"server_port": n.Port,
	}

	switch n.Protocol {

	// ── VMess ──────────────────────────────────────────────────────────────────
	// Required: server, server_port, uuid
	// Docs: https://sing-box.sagernet.org/configuration/outbound/vmess/
	case "vmess":
		if n.VMess == nil {
			return nil, fmt.Errorf("VMess 配置为空")
		}
		ob["type"] = "vmess"
		ob["uuid"] = n.VMess.UUID
		// alter_id: 0 = AEAD (recommended), 1 = legacy VMess
		ob["alter_id"] = n.VMess.AlterID
		// security: auto | none | zero | aes-128-gcm | chacha20-poly1305 | aes-128-ctr(legacy)
		// Must not be empty; default to "auto"
		ob["security"] = orDefault(n.VMess.Security, "auto")
		// transport (ws / grpc / http / httpupgrade / quic)
		addTransport(ob, n.VMess.Network, n.VMess.Path, n.VMess.Host)
		// TLS is optional for VMess
		if n.VMess.TLS {
			addTLS(ob, n.VMess.SNI, n.VMess.ALPN, false, "")
		}

	// ── VLESS ──────────────────────────────────────────────────────────────────
	// Required: server, server_port, uuid
	// Docs: https://sing-box.sagernet.org/configuration/outbound/vless/
	case "vless":
		if n.VLESS == nil {
			return nil, fmt.Errorf("VLESS 配置为空")
		}
		ob["type"] = "vless"
		ob["uuid"] = n.VLESS.UUID
		// flow: only "xtls-rprx-vision" is supported; omit if empty
		if n.VLESS.Flow != "" {
			ob["flow"] = n.VLESS.Flow
		}
		addTransport(ob, n.VLESS.Network, n.VLESS.Path, n.VLESS.Host)
		if n.VLESS.TLS {
			if n.VLESS.PublicKey != "" {
				// Reality TLS
				addReality(ob, n.VLESS.SNI, n.VLESS.PublicKey, n.VLESS.ShortID, n.VLESS.Fingerprint)
			} else {
				addTLS(ob, n.VLESS.SNI, n.VLESS.ALPN, false, n.VLESS.Fingerprint)
			}
		}

	// ── Trojan ─────────────────────────────────────────────────────────────────
	// Required: server, server_port, password
	// TLS is not listed as Required in the schema but is practically always needed.
	// Docs: https://sing-box.sagernet.org/configuration/outbound/trojan/
	case "trojan":
		if n.Trojan == nil {
			return nil, fmt.Errorf("Trojan 配置为空")
		}
		ob["type"] = "trojan"
		ob["password"] = n.Trojan.Password
		addTransport(ob, n.Trojan.Network, n.Trojan.Path, n.Trojan.Host)
		// Trojan almost always uses TLS; always emit the tls block
		addTLS(ob, n.Trojan.SNI, n.Trojan.ALPN, false, "")

	// ── Shadowsocks ────────────────────────────────────────────────────────────
	// Required: server, server_port, method, password
	// Docs: https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
	case "ss":
		if n.SS == nil {
			return nil, fmt.Errorf("Shadowsocks 配置为空")
		}
		ob["type"] = "shadowsocks"
		ob["method"] = n.SS.Method
		ob["password"] = n.SS.Password
		// SIP003 plugin support (obfs-local, v2ray-plugin)
		if n.SS.Plugin != "" {
			ob["plugin"] = n.SS.Plugin
			if n.SS.PluginOpts != "" {
				ob["plugin_opts"] = n.SS.PluginOpts
			}
		}

	// ── Hysteria2 ──────────────────────────────────────────────────────────────
	// Required: server, server_port, tls (tls is ==Required== per docs)
	// Docs: https://sing-box.sagernet.org/configuration/outbound/hysteria2/
	case "hysteria2":
		if n.Hysteria2 == nil {
			return nil, fmt.Errorf("Hysteria2 配置为空")
		}
		ob["type"] = "hysteria2"
		// password is optional (for anonymous servers) but almost always present
		if n.Hysteria2.Password != "" {
			ob["password"] = n.Hysteria2.Password
		}
		// bandwidth limits in Mbps; omit if 0 (sing-box will use BBR CC instead)
		if n.Hysteria2.UpMbps > 0 {
			ob["up_mbps"] = n.Hysteria2.UpMbps
		}
		if n.Hysteria2.DownMbps > 0 {
			ob["down_mbps"] = n.Hysteria2.DownMbps
		}
		// obfs: only "salamander" type is currently supported
		if n.Hysteria2.Obfs != "" {
			ob["obfs"] = map[string]interface{}{
				"type":     n.Hysteria2.Obfs, // "salamander"
				"password": n.Hysteria2.ObfsPassword,
			}
		}
		// tls is ==Required== for hysteria2
		tlsCfg := map[string]interface{}{"enabled": true}
		if n.Hysteria2.SNI != "" {
			tlsCfg["server_name"] = n.Hysteria2.SNI
		}
		if n.Hysteria2.Insecure {
			tlsCfg["insecure"] = true
		}
		if len(n.Hysteria2.ALPN) > 0 {
			tlsCfg["alpn"] = n.Hysteria2.ALPN
		}
		ob["tls"] = tlsCfg

	// ── TUIC ───────────────────────────────────────────────────────────────────
	// Required: server, server_port, uuid, tls (tls is ==Required== per docs)
	// Docs: https://sing-box.sagernet.org/configuration/outbound/tuic/
	case "tuic":
		if n.TUIC == nil {
			return nil, fmt.Errorf("TUIC 配置为空")
		}
		ob["type"] = "tuic"
		ob["uuid"] = n.TUIC.UUID
		// password is optional per docs but almost always needed
		if n.TUIC.Password != "" {
			ob["password"] = n.TUIC.Password
		}
		// congestion_control: cubic (default) | new_reno | bbr
		// Official default is "cubic", not "bbr"
		ob["congestion_control"] = orDefault(n.TUIC.CongestionControl, "cubic")
		// udp_relay_mode: native (default) | quic
		if n.TUIC.UDPRelayMode != "" {
			ob["udp_relay_mode"] = n.TUIC.UDPRelayMode
		}
		// tls is ==Required== for TUIC
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

// ─── Transport helpers ────────────────────────────────────────────────────────
// Covers: ws, grpc, http, httpupgrade
// Docs: https://sing-box.sagernet.org/configuration/shared/v2ray-transport/

func addTransport(ob map[string]interface{}, network, path, host string) {
	if network == "" || network == "tcp" || network == "raw" {
		return
	}
	transport := map[string]interface{}{
		"type": network,
	}
	switch network {
	case "ws":
		// WebSocket transport
		// path: URL path, host: Host header override
		if path != "" {
			transport["path"] = path
		}
		if host != "" {
			transport["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
	case "grpc":
		// gRPC transport
		// service_name maps to the gRPC path (without leading slash)
		if path != "" {
			transport["service_name"] = path
		}
	case "http":
		// HTTP/1.1 transport
		// host is a list, path is a list in sing-box
		if host != "" {
			transport["host"] = []string{host}
		}
		if path != "" {
			transport["path"] = path
		}
	case "httpupgrade":
		// HTTPUpgrade transport (common with Xray/v2ray configs)
		if path != "" {
			transport["path"] = path
		}
		if host != "" {
			transport["host"] = host
		}
	case "quic":
		// QUIC transport: no extra fields needed for basic usage
	}
	ob["transport"] = transport
}

// ─── TLS helpers ─────────────────────────────────────────────────────────────
// Outbound TLS fields:
//   enabled, server_name, insecure, alpn, utls.{enabled,fingerprint},
//   reality.{enabled,public_key,short_id}
// Docs: https://sing-box.sagernet.org/configuration/shared/tls/

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
	// uTLS fingerprint (optional, for browser impersonation)
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	ob["tls"] = tls
}

// addReality builds a Reality TLS block.
// Reality fields: enabled, public_key (required), short_id (required)
func addReality(ob map[string]interface{}, sni, publicKey, shortID, fingerprint string) {
	tls := map[string]interface{}{
		"enabled":     true,
		"server_name": sni, // SNI sent to destination (the camouflage domain)
		"reality": map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   shortID,
		},
	}
	// uTLS fingerprint is recommended when using Reality
	fp := orDefault(fingerprint, "chrome")
	tls["utls"] = map[string]interface{}{
		"enabled":     true,
		"fingerprint": fp,
	}
	ob["tls"] = tls
}

// ─── TUN inbound ─────────────────────────────────────────────────────────────

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

	// Remove any existing tun inbound
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

// ─── Mixed (system proxy) inbound ────────────────────────────────────────────

const MixedPort = 2080

func SetMixedInbound(cfgPath string, enable bool) error {
	cfg, err := loadJSON(cfgPath)
	if err != nil {
		return err
	}

	inbounds := getInbounds(cfg)

	// Remove any existing mixed inbound
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
