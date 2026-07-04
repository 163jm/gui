package node

// Node represents a proxy node parsed from a URI or subscription.
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // vmess | vless | trojan | ss | hysteria2 | tuic
	Address  string `json:"address"`
	Port     int    `json:"port"`
	SubURL   string `json:"sub_url,omitempty"`

	VMess     *VMessConfig     `json:"vmess,omitempty"`
	VLESS     *VLESSConfig     `json:"vless,omitempty"`
	Trojan    *TrojanConfig    `json:"trojan,omitempty"`
	SS        *SSConfig        `json:"ss,omitempty"`
	Hysteria2 *Hysteria2Config `json:"hysteria2,omitempty"`
	TUIC      *TUICConfig      `json:"tuic,omitempty"`
}

// TransportConfig holds V2Ray transport settings shared by VMess/VLESS/Trojan.
// sing-box transport types: ws | http | grpc | httpupgrade | quic
// URI "type" / vmess-json "net" values map to these as follows:
//
//	ws          → ws
//	h2 / http   → http  (h2 is the URI alias, sing-box uses "http")
//	grpc        → grpc
//	httpupgrade → httpupgrade
//	quic        → quic
//	tcp / ""    → (no transport block)
type TransportConfig struct {
	Type string `json:"type"` // ws | http | grpc | httpupgrade | quic

	// ws / http / httpupgrade
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"` // for ws: goes into headers["Host"]; for http/httpupgrade: top-level "host"

	// ws only
	MaxEarlyData        int    `json:"max_early_data,omitempty"`         // ws early data size (Xray: earlyData / ed)
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"` // usually "Sec-WebSocket-Protocol"

	// grpc only
	ServiceName string `json:"service_name,omitempty"` // URI: serviceName / path
}

// ── VMess ─────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), security, alter_id, network, tls, transport
// security: auto(default) | none | zero | aes-128-gcm | chacha20-poly1305 | aes-128-ctr(legacy)
type VMessConfig struct {
	UUID     string           `json:"uuid"`
	AlterID  int              `json:"alter_id"` // 0=AEAD (recommended), ≥1=legacy
	Security string           `json:"security"` // default "auto"; must NOT be empty string
	TLS      bool             `json:"tls"`
	SNI      string           `json:"sni,omitempty"`
	ALPN     []string         `json:"alpn,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`
}

// ── VLESS ─────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), flow, network, tls, transport
// flow: "" | "xtls-rprx-vision"
type VLESSConfig struct {
	UUID        string           `json:"uuid"`
	Flow        string           `json:"flow,omitempty"`        // "xtls-rprx-vision" or ""
	TLS         bool             `json:"tls"`
	SNI         string           `json:"sni,omitempty"`
	ALPN        []string         `json:"alpn,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"` // uTLS fingerprint
	// Reality fields (TLS must be true)
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`
}

// ── Trojan ────────────────────────────────────────────────────────────────────
// sing-box fields: password(req), tls, transport
type TrojanConfig struct {
	Password string           `json:"password"`
	SNI      string           `json:"sni,omitempty"`
	ALPN     []string         `json:"alpn,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`
}

// ── Shadowsocks ───────────────────────────────────────────────────────────────
// sing-box fields: method(req), password(req), plugin, plugin_opts
// Common methods: 2022-blake3-aes-128-gcm | 2022-blake3-aes-256-gcm |
//   2022-blake3-chacha20-poly1305 | aes-128-gcm | aes-256-gcm |
//   chacha20-ietf-poly1305 | xchacha20-ietf-poly1305 | none
type SSConfig struct {
	Method     string `json:"method"`
	Password   string `json:"password"`
	Plugin     string `json:"plugin,omitempty"`      // obfs-local | v2ray-plugin
	PluginOpts string `json:"plugin_opts,omitempty"` // SIP003 plugin options
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────
// sing-box fields: password, up_mbps, down_mbps, obfs.{type,password}, tls(Required)
// obfs.type: "salamander" (only supported value)
type Hysteria2Config struct {
	Password     string   `json:"password"`
	SNI          string   `json:"sni,omitempty"`
	Insecure     bool     `json:"insecure,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	UpMbps       int      `json:"up_mbps,omitempty"`       // 0 = BBR CC (no limit)
	DownMbps     int      `json:"down_mbps,omitempty"`     // 0 = BBR CC (no limit)
	Obfs         string   `json:"obfs,omitempty"`          // "salamander"
	ObfsPassword string   `json:"obfs_password,omitempty"`
}

// ── TUIC ──────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), password, congestion_control, udp_relay_mode, tls(Required)
// congestion_control: cubic(default) | new_reno | bbr
// udp_relay_mode: native(default) | quic
type TUICConfig struct {
	UUID              string   `json:"uuid"`
	Password          string   `json:"password,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	Insecure          bool     `json:"insecure,omitempty"`
	CongestionControl string   `json:"congestion_control,omitempty"` // default "cubic"
	UDPRelayMode      string   `json:"udp_relay_mode,omitempty"`     // default "native"
}
