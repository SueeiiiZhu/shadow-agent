// Package kernel defines the shared NodeSpec contract and per-kernel config
// generators. The JSON tags here MUST stay identical to the control plane
// (shadow-panel) so that NodeSpec round-trips losslessly over the REST API.
package kernel

// UserSpec is a single account provisioned on a node. SpeedLimitMbps and
// IPLimit are carried for forward compatibility; plain Xray/Hysteria2 have no
// native per-user bandwidth/IP cap, so they are currently informational (see
// docs) rather than enforced by the kernel.
type UserSpec struct {
	ID             string `json:"id"`
	Password       string `json:"password"`
	Email          string `json:"email"`
	Level          int    `json:"level"`
	SpeedLimitMbps int    `json:"speedLimitMbps,omitempty"`
	IPLimit        int    `json:"ipLimit,omitempty"`
}

// TLSSpec describes TLS settings for a stream.
type TLSSpec struct {
	SNI           string   `json:"sni"`
	ALPN          []string `json:"alpn"`
	CertFile      string   `json:"certFile"`
	KeyFile       string   `json:"keyFile"`
	AllowInsecure bool     `json:"allowInsecure"`
}

// RealitySpec describes Xray REALITY settings.
type RealitySpec struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

// WSSpec describes WebSocket transport settings.
type WSSpec struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

// StreamSpec describes the transport/security layer of an inbound.
type StreamSpec struct {
	Network  string       `json:"network"`  // tcp|ws|grpc
	Security string       `json:"security"` // none|tls|reality
	TLS      *TLSSpec     `json:"tls,omitempty"`
	Reality  *RealitySpec `json:"reality,omitempty"`
	WS       *WSSpec      `json:"ws,omitempty"`
}

// OutboundSpec describes an upstream proxy hop. When DialerProxyTag is set the
// underlying TCP connection of this outbound is dialed through the outbound
// whose tag equals DialerProxyTag, enabling dialer-proxy chains.
type OutboundSpec struct {
	Protocol       string `json:"protocol"` // freedom|socks|http|vless|vmess|trojan|shadowsocks
	Address        string `json:"address"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Pass           string `json:"pass"`
	UUID           string `json:"uuid"`
	Security       string `json:"security"`
	Tag            string `json:"tag"`
	DialerProxyTag string `json:"dialerProxyTag"`
}

// NodeSpec is the full provisioning request for a single node/inbound.
type NodeSpec struct {
	Tag      string         `json:"tag"`
	Kernel   string         `json:"kernel"`   // xray|hysteria2|singbox|naive
	Protocol string         `json:"protocol"` // vless|vmess|trojan|shadowsocks|hysteria2|naive
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	APIPort  int            `json:"apiPort"` // 0 => port+30000
	Users    []UserSpec     `json:"users"`
	Stream   *StreamSpec    `json:"stream,omitempty"`
	Outbound *OutboundSpec  `json:"outbound,omitempty"` // nil => freedom direct
	Dialer   []OutboundSpec `json:"dialerChain,omitempty"`
}

// NodeState is the runtime status of a node as reported back to the panel.
type NodeState struct {
	Tag           string `json:"tag"`
	Running       bool   `json:"running"`
	PID           int    `json:"pid"`
	Kernel        string `json:"kernel"`
	Port          int    `json:"port"`
	ConfigPath    string `json:"configPath"`
	Error         string `json:"error"`
	UplinkBytes   int64  `json:"uplinkBytes"`
	DownlinkBytes int64  `json:"downlinkBytes"`
}

// EffectiveAPIPort returns the API port, defaulting to port+30000 when unset.
func (s *NodeSpec) EffectiveAPIPort() int {
	if s.APIPort > 0 {
		return s.APIPort
	}
	return s.Port + 30000
}

// EffectiveListen returns the bind address, defaulting to 0.0.0.0.
func (s *NodeSpec) EffectiveListen() string {
	if s.Listen == "" {
		return "0.0.0.0"
	}
	return s.Listen
}
