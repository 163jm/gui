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

// ParseContent tries to parse nodes from raw content (base64, uri list, sing-box json, clash yaml)
func ParseContent(content string) ([]Node, error) {
	content = strings.TrimSpace(content)

	// Try sing-box JSON
	if nodes, err := parseSingBoxJSON(content); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	// Try Clash YAML
	if nodes, err := parseClashYAML(content); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	// Try base64 decode
	if decoded, err := base64Decode(content); err == nil {
		lines := splitLines(decoded)
		if len(lines) > 0 {
			return parseURILines(lines)
		}
	}

	// Try direct URI lines
	lines := splitLines(content)
	return parseURILines(lines)
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
			continue // skip unparseable lines
		}
		nodes = append(nodes, *n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("没有找到可解析的节点")
	}
	return nodes, nil
}

// ParseURI parses a single node URI
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

func newID() string {
	return uuid.New().String()
}

func base64Decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	// try standard and url-safe
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	// try with padding
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

// ─── VMess ────────────────────────────────────────────────────────────────────

type vmessJSON struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port interface{} `json:"port"`
	ID   string `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
}

func parseVMess(uri string) (*Node, error) {
	encoded := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("vmess decode error: %v", err)
	}
	var v vmessJSON
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("vmess json error: %v", err)
	}
	port := toInt(v.Port)
	aid := toInt(v.Aid)
	alpn := parseALPN(v.ALPN)
	n := &Node{
		ID:       newID(),
		Name:     v.PS,
		Protocol: "vmess",
		Address:  v.Add,
		Port:     port,
		VMess: &VMessConfig{
			UUID:     v.ID,
			AlterID:  aid,
			Security: orDefault(v.Scy, "auto"),
			Network:  orDefault(v.Net, "tcp"),
			TLS:      v.TLS == "tls",
			SNI:      v.SNI,
			Path:     v.Path,
			Host:     v.Host,
			ALPN:     alpn,
		},
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("VMess-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── VLESS ────────────────────────────────────────────────────────────────────

func parseVLESS(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)

	cfg := &VLESSConfig{
		UUID:        u.User.Username(),
		Flow:        q.Get("flow"),
		Network:     orDefault(q.Get("type"), "tcp"),
		SNI:         q.Get("sni"),
		Path:        q.Get("path"),
		Host:        q.Get("host"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		SpiderX:     q.Get("spx"),
		Fingerprint: q.Get("fp"),
		ALPN:        parseALPN(q.Get("alpn")),
	}
	security := q.Get("security")
	cfg.TLS = security == "tls" || security == "reality"

	n := &Node{
		ID:       newID(),
		Name:     name,
		Protocol: "vless",
		Address:  u.Hostname(),
		Port:     port,
		VLESS:    cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("VLESS-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Trojan ───────────────────────────────────────────────────────────────────

func parseTrojan(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)

	cfg := &TrojanConfig{
		Password: u.User.Username(),
		Network:  orDefault(q.Get("type"), "tcp"),
		SNI:      q.Get("sni"),
		ALPN:     parseALPN(q.Get("alpn")),
	}
	n := &Node{
		ID:       newID(),
		Name:     name,
		Protocol: "trojan",
		Address:  u.Hostname(),
		Port:     port,
		Trojan:   cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("Trojan-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Shadowsocks ──────────────────────────────────────────────────────────────

func parseSS(uri string) (*Node, error) {
	// ss://BASE64(method:password)@host:port#name
	// or ss://BASE64(method:password@host:port)#name
	raw := strings.TrimPrefix(uri, "ss://")

	var name string
	if idx := strings.Index(raw, "#"); idx >= 0 {
		name, _ = url.QueryUnescape(raw[idx+1:])
		raw = raw[:idx]
	}

	var method, password, host string
	var port int

	if strings.Contains(raw, "@") {
		// userinfo@host:port
		parts := strings.SplitN(raw, "@", 2)
		userinfo := parts[0]
		// userinfo might be base64
		if decoded, err := base64Decode(userinfo); err == nil && strings.Contains(decoded, ":") {
			userinfo = decoded
		}
		mp := strings.SplitN(userinfo, ":", 2)
		if len(mp) == 2 {
			method = mp[0]
			password = mp[1]
		}
		u, err := url.Parse("ss://" + parts[1])
		if err == nil {
			host = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
		}
	} else {
		// entire payload is base64
		decoded, err := base64Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("ss decode error: %v", err)
		}
		u, err := url.Parse("ss://" + decoded)
		if err != nil {
			return nil, err
		}
		method = u.User.Username()
		password, _ = u.User.Password()
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
	}

	n := &Node{
		ID:       newID(),
		Name:     name,
		Protocol: "ss",
		Address:  host,
		Port:     port,
		SS: &SSConfig{
			Method:   method,
			Password: password,
		},
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("SS-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Hysteria2 ────────────────────────────────────────────────────────────────

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
		Password: u.User.Username(),
		SNI:      q.Get("sni"),
		Insecure: insecure,
		ALPN:     parseALPN(q.Get("alpn")),
		Obfs:     q.Get("obfs"),
		ObfsPassword: q.Get("obfs-password"),
	}
	n := &Node{
		ID:        newID(),
		Name:      name,
		Protocol:  "hysteria2",
		Address:   u.Hostname(),
		Port:      port,
		Hysteria2: cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("Hysteria2-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── TUIC ─────────────────────────────────────────────────────────────────────

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
		CongestionControl: orDefault(q.Get("congestion_control"), "bbr"),
	}
	n := &Node{
		ID:       newID(),
		Name:     name,
		Protocol: "tuic",
		Address:  u.Hostname(),
		Port:     port,
		TUIC:     cfg,
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("TUIC-%s:%d", n.Address, n.Port)
	}
	return n, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func parseALPN(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
