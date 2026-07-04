package config

import (
	"encoding/json"
	"fmt"
	"os"

	"singbox-gui/backend/node"
)

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

// nodeToSingBoxOutbound converts a Node to a sing-box outbound map.
// All field names match the official sing-box documentation exactly.
func nodeToSingBoxOutbound(n node.Node) (map[string]interface{}, error) {
	ob := map[string]interface{}{
		"tag":         "proxy",
		"server":      n.Address,
		"server_port": n.Port,
	}

	switch n.Protocol {

	// ── VMess ─────────────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/vmess/
	case "vmess":
		if n.VMess == nil {
			return nil, fmt.Errorf("VMess 配置为空")
		}
		ob["type"] = "vmess"
		ob["uuid"] = n.VMess.UUID
		ob["alter_id"] = n.VMess.AlterID
		// security must NOT be empty string — default to "auto"
		ob["security"] = orDefault(n.VMess.Security, "auto")
		if t := buildTransport(n.VMess.Transport); t != nil {
			ob["transport"] = t
		}
		if n.VMess.TLS {
			ob["tls"] = buildTLS(n.VMess.SNI, n.VMess.ALPN, false, "")
		}

	// ── VLESS ─────────────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/vless/
	case "vless":
		if n.VLESS == nil {
			return nil, fmt.Errorf("VLESS 配置为空")
		}
		ob["type"] = "vless"
		ob["uuid"] = n.VLESS.UUID
		if n.VLESS.Flow != "" {
			ob["flow"] = n.VLESS.Flow
		}
		if t := buildTransport(n.VLESS.Transport); t != nil {
			ob["transport"] = t
		}
		if n.VLESS.TLS {
			if n.VLESS.PublicKey != "" {
				ob["tls"] = buildRealityTLS(n.VLESS.SNI, n.VLESS.PublicKey, n.VLESS.ShortID, n.VLESS.Fingerprint)
			} else {
				ob["tls"] = buildTLS(n.VLESS.SNI, n.VLESS.ALPN, false, n.VLESS.Fingerprint)
			}
		}

	// ── Trojan ────────────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/trojan/
	case "trojan":
		if n.Trojan == nil {
			return nil, fmt.Errorf("Trojan 配置为空")
		}
		ob["type"] = "trojan"
		ob["password"] = n.Trojan.Password
		if t := buildTransport(n.Trojan.Transport); t != nil {
			ob["transport"] = t
		}
		// Trojan always uses TLS
		ob["tls"] = buildTLS(n.Trojan.SNI, n.Trojan.ALPN, false, "")

	// ── Shadowsocks ───────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
	case "ss":
		if n.SS == nil {
			return nil, fmt.Errorf("Shadowsocks 配置为空")
		}
		ob["type"] = "shadowsocks"
		ob["method"] = n.SS.Method
		ob["password"] = n.SS.Password
		if n.SS.Plugin != "" {
			ob["plugin"] = n.SS.Plugin
			if n.SS.PluginOpts != "" {
				ob["plugin_opts"] = n.SS.PluginOpts
			}
		}

	// ── Hysteria2 ─────────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/hysteria2/
	// tls is ==Required==
	case "hysteria2":
		if n.Hysteria2 == nil {
			return nil, fmt.Errorf("Hysteria2 配置为空")
		}
		ob["type"] = "hysteria2"
		if n.Hysteria2.Password != "" {
			ob["password"] = n.Hysteria2.Password
		}
		if n.Hysteria2.UpMbps > 0 {
			ob["up_mbps"] = n.Hysteria2.UpMbps
		}
		if n.Hysteria2.DownMbps > 0 {
			ob["down_mbps"] = n.Hysteria2.DownMbps
		}
		if n.Hysteria2.Obfs != "" {
			ob["obfs"] = map[string]interface{}{
				"type":     n.Hysteria2.Obfs,
				"password": n.Hysteria2.ObfsPassword,
			}
		}
		// tls Required — always include with enabled:true
		tls := map[string]interface{}{"enabled": true}
		if n.Hysteria2.SNI != "" {
			tls["server_name"] = n.Hysteria2.SNI
		}
		if n.Hysteria2.Insecure {
			tls["insecure"] = true
		}
		if len(n.Hysteria2.ALPN) > 0 {
			tls["alpn"] = n.Hysteria2.ALPN
		}
		ob["tls"] = tls

	// ── TUIC ──────────────────────────────────────────────────────────────────
	// Docs: https://sing-box.sagernet.org/configuration/outbound/tuic/
	// tls is ==Required==
	case "tuic":
		if n.TUIC == nil {
			return nil, fmt.Errorf("TUIC 配置为空")
		}
		ob["type"] = "tuic"
		ob["uuid"] = n.TUIC.UUID
		if n.TUIC.Password != "" {
			ob["password"] = n.TUIC.Password
		}
		// congestion_control: cubic(default) | new_reno | bbr
		ob["congestion_control"] = orDefault(n.TUIC.CongestionControl, "cubic")
		// udp_relay_mode: native(default) | quic — omit to use default
		if n.TUIC.UDPRelayMode != "" {
			ob["udp_relay_mode"] = n.TUIC.UDPRelayMode
		}
		// tls Required — always include with enabled:true
		tls := map[string]interface{}{"enabled": true}
		if n.TUIC.SNI != "" {
			tls["server_name"] = n.TUIC.SNI
		}
		if n.TUIC.Insecure {
			tls["insecure"] = true
		}
		if len(n.TUIC.ALPN) > 0 {
			tls["alpn"] = n.TUIC.ALPN
		}
		ob["tls"] = tls

	default:
		return nil, fmt.Errorf("不支持的协议: %s", n.Protocol)
	}
	return ob, nil
}

// ─── Transport builder ────────────────────────────────────────────────────────
// Converts our TransportConfig into the sing-box "transport" object.
//
// sing-box transport field reference:
//
//   ws:
//     type, path, headers{}, max_early_data, early_data_header_name
//     NOTE: Host goes inside headers["Host"], NOT a top-level "host" field.
//
//   http (h2/h3):
//     type, host[], path, method, headers{}, idle_timeout, ping_timeout
//     NOTE: host is a []string array. path is a plain string.
//     With tls.alpn=["h3"] the transport uses HTTP/3 instead of HTTP/2.
//
//   grpc:
//     type, service_name, idle_timeout, ping_timeout, permit_without_stream
//
//   httpupgrade:
//     type, host, path, headers{}
//     NOTE: host is a TOP-LEVEL string field, NOT inside headers.
//     (See sing-box issue #1841 — putting host in headers["Host"] does NOT work)
//
//   quic:
//     type  (no other user-facing fields)

func buildTransport(t *node.TransportConfig) map[string]interface{} {
	if t == nil || t.Type == "" {
		return nil
	}
	m := map[string]interface{}{"type": t.Type}

	switch t.Type {
	case "ws":
		if t.Path != "" {
			m["path"] = t.Path
		}
		// Host goes into headers["Host"] for WebSocket
		if t.Host != "" {
			m["headers"] = map[string]interface{}{"Host": t.Host}
		}
		// Early data support
		if t.MaxEarlyData > 0 {
			m["max_early_data"] = t.MaxEarlyData
			m["early_data_header_name"] = orDefault(t.EarlyDataHeaderName, "Sec-WebSocket-Protocol")
		}

	case "http":
		// path: plain string (NOT an array)
		if t.Path != "" {
			m["path"] = t.Path
		}
		// host: []string array
		if t.Host != "" {
			m["host"] = []string{t.Host}
		}

	case "grpc":
		if t.ServiceName != "" {
			m["service_name"] = t.ServiceName
		}

	case "httpupgrade":
		if t.Path != "" {
			m["path"] = t.Path
		}
		// host: TOP-LEVEL string field (NOT headers["Host"] — that is the WebSocket behavior)
		if t.Host != "" {
			m["host"] = t.Host
		}

	case "quic":
		// no user-facing fields

	}
	return m
}

// ─── TLS builders ─────────────────────────────────────────────────────────────
// sing-box outbound TLS fields:
//   enabled(req), server_name, insecure, alpn[],
//   utls.{enabled, fingerprint},
//   reality.{enabled, public_key(req), short_id(req)}

func buildTLS(sni string, alpn []string, insecure bool, fingerprint string) map[string]interface{} {
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
	// uTLS fingerprint for browser impersonation
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	return tls
}

// buildRealityTLS builds the TLS block for VLESS+Reality.
// Reality requires: public_key, short_id, and a uTLS fingerprint (default "chrome").
func buildRealityTLS(sni, publicKey, shortID, fingerprint string) map[string]interface{} {
	tls := map[string]interface{}{
		"enabled": true,
		"reality": map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   shortID,
		},
		"utls": map[string]interface{}{
			"enabled":     true,
			"fingerprint": orDefault(fingerprint, "chrome"),
		},
	}
	if sni != "" {
		tls["server_name"] = sni
	}
	return tls
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
	newInbounds := []interface{}{}
	for _, ib := range inbounds {
		if m, ok := ib.(map[string]interface{}); ok && m["type"] == "tun" {
			continue
		}
		newInbounds = append(newInbounds, ib)
	}
	if enable {
		newInbounds = append(newInbounds, tunInbound)
	}
	cfg["inbounds"] = newInbounds
	return saveJSON(cfgPath, cfg)
}

// ─── Mixed inbound ────────────────────────────────────────────────────────────

const MixedPort = 2080

func SetMixedInbound(cfgPath string, enable bool) error {
	cfg, err := loadJSON(cfgPath)
	if err != nil {
		return err
	}
	inbounds := getInbounds(cfg)
	newInbounds := []interface{}{}
	for _, ib := range inbounds {
		if m, ok := ib.(map[string]interface{}); ok && m["type"] == "mixed" {
			continue
		}
		newInbounds = append(newInbounds, ib)
	}
	if enable {
		newInbounds = append(newInbounds, map[string]interface{}{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": MixedPort,
		})
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
