package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ParseContent tries to parse nodes from raw content.
// Priority: sing-box JSON → Clash YAML → base64-decoded URI list → raw URI list
func ParseContent(content string) ([]Node, error) {
	content = strings.TrimSpace(content)

	if nodes, err := parseSingBoxJSON(content); err == nil && len(nodes) > 0 {
		return nodes, nil
	}
	if nodes, err := parseClashYAML(content); err == nil && len(nodes) > 0 {
		return nodes, nil
	}
	if decoded, err := base64Decode(content); err == nil {
		if nodes, err := parseURILines(splitLines(decoded)); err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}
	return parseURILines(splitLines(content))
}

func splitLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func parseURILines(lines []string) ([]Node, error) {
	var nodes []Node
	for _, line := range lines {
		n, err := ParseURI(line)
		if err != nil {
			continue
		}
		nodes = append(nodes, *n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("没有找到可解析的节点")
	}
	return nodes, nil
}

// ParseURI parses a single proxy URI into a Node.
func ParseURI(uri string) (*Node, error) {
	uri = strings.TrimSpace(uri)
	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return parseVMess(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseVLESS(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojan(uri)
	case strings.HasPrefix(uri, "ss://"):
		return parseSS(uri)
	case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
		return parseHysteria2(uri)
	case strings.HasPrefix(uri, "tuic://"):
		return parseTUIC(uri)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", uri[:min(20, len(uri))])
	}
}

func newID() string { return uuid.New().String() }

func base64Decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	pad := len(s) % 4
	if pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// normalizeNetwork maps URI "type" / vmess-json "net" values to sing-box transport type names.
// sing-box does NOT use "h2" — it uses "http" for HTTP/2.
// sing-box does NOT have "tcp" transport — omit transport block when tcp/raw/"".
func normalizeNetwork(net string) string {
	switch strings.ToLower(net) {
	case "h2", "http":
		return "http"
	case "ws":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "httpupgrade":
		return "httpupgrade"
	case "quic":
		return "quic"
	default:
		return "" // tcp / raw / "" → no transport block
	}
}

// ─── VMess (legacy base64-JSON format) ───────────────────────────────────────

type vmessJSON struct {
	V    string      `json:"v"`
	PS   string      `json:"ps"`
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	ID   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`   // header type (not used in sing-box)
	Host string      `json:"host"`   // ws Host / http host / grpc authority
	Path string      `json:"path"`   // ws path / http path / grpc service name
	TLS  string      `json:"tls"`    // "tls" | ""
	SNI  string      `json:"sni"`
	ALPN string      `json:"alpn"`
	FP   string      `json:"fp"`     // uTLS fingerprint (newer vmess QR)
	// early data (some exporters)
	ED  interface{} `json:"ed"`     // max_early_data
}

func parseVMess(uri string) (*Node, error) {
	encoded := strings.TrimPrefix(uri, "vmess://")
	// strip fragment
	if idx := strings.Index(encoded, "#"); idx >= 0 {
		encoded = encoded[:idx]
	}
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("vmess decode error: %v", err)
	}
	var v vmessJSON
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("vmess json error: %v", err)
	}

	network := normalizeNetwork(v.Net)
	transport := buildTransportFromVMessJSON(network, v)

	n := &Node{
		ID:       newID(),
		Name:     v.PS,
		Protocol: "vmess",
		Address:  v.Add,
		Port:     toInt(v.Port),
		VMess: &VMessConfig{
			UUID:      v.ID,
			AlterID:   toInt(v.Aid),
			Security:  orDefault(v.Scy, "auto"),
			TLS:       v.TLS == "tls",
			SNI:       orEmpty(v.SNI, v.Host), // SNI falls back to host for older links
			ALPN:      parseALPN(v.ALPN),
			Transport: transport,
		},
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("VMess-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

func buildTransportFromVMessJSON(network string, v vmessJSON) *TransportConfig {
	if network == "" {
		return nil
	}
	t := &TransportConfig{Type: network}
	switch network {
	case "ws":
		t.Path = v.Path
		t.Host = v.Host
		if ed := toInt(v.ED); ed > 0 {
			t.MaxEarlyData = ed
			t.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
	case "http":
		t.Path = v.Path
		t.Host = v.Host
	case "grpc":
		// vmess JSON uses "path" for gRPC service name
		t.ServiceName = v.Path
	case "httpupgrade":
		t.Path = v.Path
		t.Host = v.Host
	}
	return t
}

// ─── VLESS (URI format) ───────────────────────────────────────────────────────
// Reference: https://github.com/XTLS/Xray-core/discussions/716
// Key query params: type, security, sni, fp, alpn, flow, path, host,
//   serviceName (grpc), ed (ws early data), pbk (reality pubkey), sid, spx

func parseVLESS(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	network := normalizeNetwork(q.Get("type"))
	transport := buildTransportFromQuery(network, q)

	security := q.Get("security")
	hasTLS := security == "tls" || security == "reality"

	cfg := &VLESSConfig{
		UUID:        u.User.Username(),
		Flow:        q.Get("flow"),
		TLS:         hasTLS,
		SNI:         q.Get("sni"),
		ALPN:        parseALPN(q.Get("alpn")),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		Transport:   transport,
	}

	n := &Node{
		ID: newID(), Name: name, Protocol: "vless",
		Address: u.Hostname(), Port: port, VLESS: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("VLESS-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Trojan (URI format) ──────────────────────────────────────────────────────

func parseTrojan(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	network := normalizeNetwork(q.Get("type"))
	transport := buildTransportFromQuery(network, q)

	cfg := &TrojanConfig{
		Password:  u.User.Username(),
		SNI:       q.Get("sni"),
		ALPN:      parseALPN(q.Get("alpn")),
		Transport: transport,
	}
	n := &Node{
		ID: newID(), Name: name, Protocol: "trojan",
		Address: u.Hostname(), Port: port, Trojan: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("Trojan-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Shadowsocks (URI format) ─────────────────────────────────────────────────
// Format 1: ss://BASE64(method:password)@host:port#name
// Format 2: ss://BASE64(method:password@host:port)#name  (legacy)

func parseSS(uri string) (*Node, error) {
	raw := strings.TrimPrefix(uri, "ss://")
	var name string
	if idx := strings.Index(raw, "#"); idx >= 0 {
		name, _ = url.QueryUnescape(raw[idx+1:])
		raw = raw[:idx]
	}
	// Strip query string (plugin opts sometimes encoded here)
	var query string
	if idx := strings.Index(raw, "?"); idx >= 0 {
		query = raw[idx+1:]
		raw = raw[:idx]
	}

	var method, password, host string
	var port int

	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		userinfo := parts[0]
		// userinfo may be base64(method:password) or plain method:password
		if decoded, err := base64Decode(userinfo); err == nil && strings.Contains(decoded, ":") {
			userinfo = decoded
		}
		mp := strings.SplitN(userinfo, ":", 2)
		if len(mp) == 2 {
			method, password = mp[0], mp[1]
		}
		// host:port part
		if u, err := url.Parse("ss://" + parts[1]); err == nil {
			host = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
		}
	} else {
		// entire payload is base64
		decoded, err := base64Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("ss decode error: %v", err)
		}
		if u, err := url.Parse("ss://" + decoded); err == nil {
			method = u.User.Username()
			password, _ = u.User.Password()
			host = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
		}
	}

	cfg := &SSConfig{Method: method, Password: password}
	// SIP003 plugin via query string
	if query != "" {
		q, _ := url.ParseQuery(query)
		cfg.Plugin = q.Get("plugin")
		cfg.PluginOpts = q.Get("plugin-opts")
	}

	n := &Node{
		ID: newID(), Name: name, Protocol: "ss",
		Address: host, Port: port, SS: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("SS-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Hysteria2 (URI format) ───────────────────────────────────────────────────

func parseHysteria2(uri string) (*Node, error) {
	uri = strings.Replace(uri, "hy2://", "hysteria2://", 1)
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	insecure, _ := strconv.ParseBool(q.Get("insecure"))

	cfg := &Hysteria2Config{
		Password:     u.User.Username(),
		SNI:          q.Get("sni"),
		Insecure:     insecure,
		ALPN:         parseALPN(q.Get("alpn")),
		Obfs:         q.Get("obfs"),
		ObfsPassword: q.Get("obfs-password"),
	}
	n := &Node{
		ID: newID(), Name: name, Protocol: "hysteria2",
		Address: u.Hostname(), Port: port, Hysteria2: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("Hysteria2-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── TUIC (URI format) ────────────────────────────────────────────────────────

func parseTUIC(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	insecure, _ := strconv.ParseBool(q.Get("allow_insecure"))
	password, _ := u.User.Password()

	cfg := &TUICConfig{
		UUID:              u.User.Username(),
		Password:          password,
		SNI:               q.Get("sni"),
		ALPN:              parseALPN(q.Get("alpn")),
		Insecure:          insecure,
		CongestionControl: orDefault(q.Get("congestion_control"), "cubic"),
		UDPRelayMode:      q.Get("udp_relay_mode"),
	}
	n := &Node{
		ID: newID(), Name: name, Protocol: "tuic",
		Address: u.Hostname(), Port: port, TUIC: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("TUIC-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Transport builder from URI query params ──────────────────────────────────
// Used by VLESS, Trojan (and any future URI-format protocol).
// URI params:
//   ws/httpupgrade: path, host
//   ws only:        ed (max_early_data), eh (early_data_header_name)
//   http (h2):      path, host
//   grpc:           serviceName (primary), path (fallback)

func buildTransportFromQuery(network string, q url.Values) *TransportConfig {
	if network == "" {
		return nil
	}
	t := &TransportConfig{Type: network}
	switch network {
	case "ws":
		t.Path = q.Get("path")
		t.Host = q.Get("host")
		if ed := toInt(q.Get("ed")); ed > 0 {
			t.MaxEarlyData = ed
			t.EarlyDataHeaderName = orDefault(q.Get("eh"), "Sec-WebSocket-Protocol")
		}
	case "http":
		t.Path = q.Get("path")
		t.Host = q.Get("host")
	case "grpc":
		// URI uses "serviceName"; some exporters use "path" as fallback
		t.ServiceName = orDefault(q.Get("serviceName"), q.Get("path"))
	case "httpupgrade":
		t.Path = q.Get("path")
		t.Host = q.Get("host")
	case "quic":
		// no extra fields
	}
	return t
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func parseALPN(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(val)
		return n
	}
	return 0
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// orEmpty returns s if non-empty, else fallback — used for optional fallback fields.
func orEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
