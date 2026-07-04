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

// ── VMess ─────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), security, alter_id, network, tls, transport
// security values: auto | none | zero | aes-128-gcm | chacha20-poly1305 | aes-128-ctr(legacy)
type VMessConfig struct {
	UUID     string   `json:"uuid"`
	AlterID  int      `json:"alter_id"`  // 0=AEAD, 1=legacy
	Security string   `json:"security"`  // default: "auto"
	Network  string   `json:"network"`   // tcp | ws | grpc | http | httpupgrade | quic
	TLS      bool     `json:"tls"`
	SNI      string   `json:"sni,omitempty"`
	Path     string   `json:"path,omitempty"`  // ws path / grpc service_name / http path
	Host     string   `json:"host,omitempty"`  // ws Host header / http host
	ALPN     []string `json:"alpn,omitempty"`
}

// ── VLESS ─────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), flow, network, tls, transport
// flow values: "" | "xtls-rprx-vision"
type VLESSConfig struct {
	UUID        string   `json:"uuid"`
	Flow        string   `json:"flow,omitempty"`         // "xtls-rprx-vision" or ""
	Network     string   `json:"network"`
	TLS         bool     `json:"tls"`
	SNI         string   `json:"sni,omitempty"`
	Path        string   `json:"path,omitempty"`
	Host        string   `json:"host,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // uTLS fingerprint
	// Reality fields
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

// ── Trojan ────────────────────────────────────────────────────────────────────
// sing-box fields: password(req), network, tls, transport
type TrojanConfig struct {
	Password string   `json:"password"`
	Network  string   `json:"network"` // tcp | ws | grpc
	SNI      string   `json:"sni,omitempty"`
	ALPN     []string `json:"alpn,omitempty"`
	Path     string   `json:"path,omitempty"`
	Host     string   `json:"host,omitempty"`
}

// ── Shadowsocks ───────────────────────────────────────────────────────────────
// sing-box fields: method(req), password(req), plugin, plugin_opts
// method values: 2022-blake3-aes-128-gcm | 2022-blake3-aes-256-gcm |
//   2022-blake3-chacha20-poly1305 | none | aes-128-gcm | aes-192-gcm |
//   aes-256-gcm | chacha20-ietf-poly1305 | xchacha20-ietf-poly1305
//   legacy: aes-128-ctr | aes-192-ctr | aes-256-ctr | aes-128-cfb |
//   aes-192-cfb | aes-256-cfb | rc4-md5 | chacha20-ietf | xchacha20
type SSConfig struct {
	Method     string `json:"method"`
	Password   string `json:"password"`
	Plugin     string `json:"plugin,omitempty"`      // obfs-local | v2ray-plugin
	PluginOpts string `json:"plugin_opts,omitempty"` // SIP003 plugin options string
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────
// sing-box fields: password, up_mbps, down_mbps, obfs.{type,password}, tls(req)
// tls is ==Required== — always emit with enabled:true
// obfs.type: "salamander" (only supported value currently)
type Hysteria2Config struct {
	Password     string   `json:"password"`
	SNI          string   `json:"sni,omitempty"`
	Insecure     bool     `json:"insecure,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	UpMbps       int      `json:"up_mbps,omitempty"`   // 0 = use BBR CC (recommended)
	DownMbps     int      `json:"down_mbps,omitempty"` // 0 = use BBR CC (recommended)
	Obfs         string   `json:"obfs,omitempty"`          // obfs type: "salamander"
	ObfsPassword string   `json:"obfs_password,omitempty"` // obfs password
}

// ── TUIC ──────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), password, congestion_control, udp_relay_mode,
//   zero_rtt_handshake, heartbeat, tls(req)
// tls is ==Required== — always emit with enabled:true
// congestion_control: cubic (default) | new_reno | bbr
// udp_relay_mode: native (default) | quic
type TUICConfig struct {
	UUID               string   `json:"uuid"`
	Password           string   `json:"password,omitempty"`
	SNI                string   `json:"sni,omitempty"`
	ALPN               []string `json:"alpn,omitempty"`
	Insecure           bool     `json:"insecure,omitempty"`
	CongestionControl  string   `json:"congestion_control,omitempty"` // cubic|new_reno|bbr, default cubic
	UDPRelayMode       string   `json:"udp_relay_mode,omitempty"`     // native|quic, default native
}
