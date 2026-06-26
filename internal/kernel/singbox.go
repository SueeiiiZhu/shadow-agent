package kernel

import (
	"encoding/json"
	"fmt"
)

// sing-box config: inbounds + outbounds with detour chaining. We support the
// common multi-user inbound shapes and map upstream/dialer hops to sing-box
// outbounds linked via "detour" (sing-box's dialer-proxy equivalent).
func marshalSingbox(spec *NodeSpec) ([]byte, string, error) {
	inbound, err := singboxInbound(spec)
	if err != nil {
		return nil, "", err
	}
	outbounds := singboxOutbounds(spec)

	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{inbound},
		"outbounds": outbounds,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return data, "json", nil
}

func singboxInbound(spec *NodeSpec) (map[string]any, error) {
	base := map[string]any{
		"tag":         spec.Tag,
		"listen":      spec.EffectiveListen(),
		"listen_port": spec.Port,
	}

	switch spec.Protocol {
	case "vless":
		base["type"] = "vless"
		users := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			users = append(users, map[string]any{"name": u.Email, "uuid": u.ID})
		}
		base["users"] = users
	case "vmess":
		base["type"] = "vmess"
		users := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			users = append(users, map[string]any{"name": u.Email, "uuid": u.ID})
		}
		base["users"] = users
	case "trojan":
		base["type"] = "trojan"
		users := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			users = append(users, map[string]any{"name": u.Email, "password": u.Password})
		}
		base["users"] = users
	case "shadowsocks":
		base["type"] = "shadowsocks"
		base["method"] = "aes-128-gcm"
		if len(spec.Users) > 0 {
			base["password"] = spec.Users[0].Password
		}
		users := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			users = append(users, map[string]any{"name": u.Email, "password": u.Password})
		}
		base["users"] = users
	case "hysteria2":
		base["type"] = "hysteria2"
		users := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			users = append(users, map[string]any{"name": u.Email, "password": u.Password})
		}
		base["users"] = users
	default:
		return nil, fmt.Errorf("singbox: unsupported inbound protocol %q", spec.Protocol)
	}

	if tls := singboxInboundTLS(spec.Stream); tls != nil {
		base["tls"] = tls
	}
	return base, nil
}

func singboxInboundTLS(s *StreamSpec) map[string]any {
	if s == nil || s.TLS == nil {
		return nil
	}
	if s.TLS.CertFile == "" && s.TLS.KeyFile == "" && s.TLS.SNI == "" {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if s.TLS.SNI != "" {
		tls["server_name"] = s.TLS.SNI
	}
	if len(s.TLS.ALPN) > 0 {
		tls["alpn"] = s.TLS.ALPN
	}
	if s.TLS.CertFile != "" {
		tls["certificate_path"] = s.TLS.CertFile
	}
	if s.TLS.KeyFile != "" {
		tls["key_path"] = s.TLS.KeyFile
	}
	return tls
}

// singboxOutbounds builds the outbound list. The main outbound (upstream proxy
// or direct) plus dialer-chain hops, linked through "detour".
func singboxOutbounds(spec *NodeSpec) []any {
	if spec.Outbound == nil && len(spec.Dialer) == 0 {
		return []any{map[string]any{"type": "direct", "tag": "direct"}}
	}

	outbounds := make([]any, 0, len(spec.Dialer)+2)

	var mainSpec OutboundSpec
	var chain []OutboundSpec
	if spec.Outbound != nil {
		mainSpec = *spec.Outbound
		chain = spec.Dialer
	} else {
		mainSpec = spec.Dialer[0]
		chain = spec.Dialer[1:]
	}
	if mainSpec.Tag == "" {
		mainSpec.Tag = "proxy"
	}

	mainDetour := mainSpec.DialerProxyTag
	if mainDetour == "" && len(chain) > 0 {
		mainDetour = chainTag(chain, 0)
	}
	outbounds = append(outbounds, singboxOutbound(mainSpec, mainDetour))

	for i := range chain {
		hop := chain[i]
		if hop.Tag == "" {
			hop.Tag = chainTag(chain, i)
		}
		detour := hop.DialerProxyTag
		if detour == "" && i+1 < len(chain) {
			detour = chainTag(chain, i+1)
		}
		outbounds = append(outbounds, singboxOutbound(hop, detour))
	}
	// Always provide a direct outbound for final fallback.
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	return outbounds
}

func singboxOutbound(spec OutboundSpec, detour string) map[string]any {
	ob := map[string]any{"tag": spec.Tag}
	switch spec.Protocol {
	case "", "freedom":
		ob["type"] = "direct"
	case "socks":
		ob["type"] = "socks"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		ob["version"] = "5"
		if spec.User != "" {
			ob["username"] = spec.User
		}
		if spec.Pass != "" {
			ob["password"] = spec.Pass
		}
	case "http":
		ob["type"] = "http"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		if spec.User != "" {
			ob["username"] = spec.User
		}
		if spec.Pass != "" {
			ob["password"] = spec.Pass
		}
	case "shadowsocks":
		ob["type"] = "shadowsocks"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		ob["method"] = firstNonEmpty(spec.Security, "aes-128-gcm")
		ob["password"] = spec.Pass
	case "trojan":
		ob["type"] = "trojan"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		ob["password"] = spec.Pass
	case "vless":
		ob["type"] = "vless"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		ob["uuid"] = spec.UUID
	case "vmess":
		ob["type"] = "vmess"
		ob["server"] = spec.Address
		ob["server_port"] = spec.Port
		ob["uuid"] = spec.UUID
	default:
		ob["type"] = "direct"
	}
	if detour != "" {
		ob["detour"] = detour
	}
	return ob
}
