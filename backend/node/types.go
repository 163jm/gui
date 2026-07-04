package node

// Node represents a proxy node
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // vmess, vless, trojan, ss, hysteria2, tuic
	Address  string `json:"address"`
	Port     int    `json:"port"`
	SubURL   string `json:"sub_url,omitempty"`

	// Common fields
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`

	// VMess specific
	VMess *VMessConfig `json:"vmess,omitempty"`

	// VLESS specific
	VLESS *VLESSConfig `json:"vless,omitempty"`

	// Trojan specific
	Trojan *TrojanConfig `json:"trojan,omitempty"`

	// Shadowsocks specific
	SS *SSConfig `json:"ss,omitempty"`

	// Hysteria2 specific
	Hysteria2 *Hysteria2Config `json:"hysteria2,omitempty"`

	// TUIC specific
	TUIC *TUICConfig `json:"tuic,omitempty"`
}

type VMessConfig struct {
	UUID     string `json:"uuid"`
	AlterID  int    `json:"alter_id"`
	Security string `json:"security"` // auto, aes-128-gcm, chacha20-poly1305, none
	Network  string `json:"network"`  // tcp, ws, grpc, http
	TLS      bool   `json:"tls"`
	SNI      string `json:"sni,omitempty"`
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
	ALPN     []string `json:"alpn,omitempty"`
}

type VLESSConfig struct {
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	Network    string `json:"network"`
	TLS        bool   `json:"tls"`
	XTLS       bool   `json:"xtls,omitempty"`
	SNI        string `json:"sni,omitempty"`
	Path       string `json:"path,omitempty"`
	Host       string `json:"host,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`  // reality
	ShortID    string `json:"short_id,omitempty"`    // reality
	SpiderX    string `json:"spider_x,omitempty"`    // reality
	Fingerprint string `json:"fingerprint,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
}

type TrojanConfig struct {
	Password string `json:"password"`
	Network  string `json:"network"`
	SNI      string `json:"sni,omitempty"`
	ALPN     []string `json:"alpn,omitempty"`
}

type SSConfig struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Plugin   string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
}

type Hysteria2Config struct {
	Password string `json:"password"`
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	ALPN     []string `json:"alpn,omitempty"`
	UpMbps   int    `json:"up_mbps,omitempty"`
	DownMbps int    `json:"down_mbps,omitempty"`
	Obfs     string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
}

type TUICConfig struct {
	UUID        string `json:"uuid"`
	Password    string `json:"password"`
	SNI         string `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
}
