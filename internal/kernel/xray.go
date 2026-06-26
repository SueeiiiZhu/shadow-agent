package kernel

import (
	"fmt"
)

// xrayConfig is the top-level Xray config object. We model it with ordered,
// explicit Go structs that marshal to the exact JSON shape Xray expects.
type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	API       xrayAPI        `json:"api"`
	Stats     map[string]any `json:"stats"`
	Policy    xrayPolicy     `json:"policy"`
	Inbounds  []any          `json:"inbounds"`
	Outbounds []any          `json:"outbounds"`
	Routing   xrayRouting    `json:"routing"`
}

type xrayLog struct {
	Loglevel string `json:"loglevel"`
}

type xrayAPI struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type xrayPolicy struct {
	Levels map[string]xrayLevelPolicy `json:"levels"`
	System xraySystemPolicy           `json:"system"`
}

type xrayLevelPolicy struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
}

type xraySystemPolicy struct {
	StatsInboundUplink    bool `json:"statsInboundUplink"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
}

type xrayRouting struct {
	DomainStrategy string          `json:"domainStrategy"`
	Rules          []xrayRouteRule `json:"rules"`
}

type xrayRouteRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// buildXrayConfig produces the full Xray config object for a NodeSpec. This is
// the heart of shadow-agent: it wires user-traffic inbounds to either a direct
// freedom outbound, a single upstream proxy, or a dialer-proxy chain.
func buildXrayConfig(spec *NodeSpec) (xrayConfig, error) {
	apiPort := spec.EffectiveAPIPort()

	inbounds, err := buildXrayInbounds(spec, apiPort)
	if err != nil {
		return xrayConfig{}, err
	}

	outbounds, mainTag := buildXrayOutbounds(spec)

	cfg := xrayConfig{
		Log: xrayLog{Loglevel: "warning"},
		API: xrayAPI{
			Tag:      "api",
			Services: []string{"HandlerService", "StatsService", "LoggerService"},
		},
		Stats: map[string]any{},
		Policy: xrayPolicy{
			Levels: map[string]xrayLevelPolicy{
				"0": {StatsUserUplink: true, StatsUserDownlink: true},
			},
			System: xraySystemPolicy{
				StatsInboundUplink:    true,
				StatsInboundDownlink:  true,
				StatsOutboundUplink:   true,
				StatsOutboundDownlink: true,
			},
		},
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Routing: xrayRouting{
			DomainStrategy: "AsIs",
			Rules: []xrayRouteRule{
				{Type: "field", InboundTag: []string{"api"}, OutboundTag: "api"},
				{Type: "field", InboundTag: []string{spec.Tag}, OutboundTag: mainTag},
			},
		},
	}
	return cfg, nil
}

// buildXrayInbounds returns the api dokodemo-door inbound plus the business
// protocol inbound.
func buildXrayInbounds(spec *NodeSpec, apiPort int) ([]any, error) {
	api := map[string]any{
		"tag":      "api",
		"listen":   "127.0.0.1",
		"port":     apiPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}

	business, err := buildXrayBusinessInbound(spec)
	if err != nil {
		return nil, err
	}
	return []any{api, business}, nil
}

func buildXrayBusinessInbound(spec *NodeSpec) (map[string]any, error) {
	settings, err := buildXrayInboundSettings(spec)
	if err != nil {
		return nil, err
	}

	in := map[string]any{
		"tag":      spec.Tag,
		"listen":   spec.EffectiveListen(),
		"port":     spec.Port,
		"protocol": spec.Protocol,
		"settings": settings,
	}
	if ss := buildXrayStreamSettings(spec.Stream); ss != nil {
		in["streamSettings"] = ss
	}
	return in, nil
}

func buildXrayInboundSettings(spec *NodeSpec) (map[string]any, error) {
	switch spec.Protocol {
	case "vless":
		clients := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			clients = append(clients, map[string]any{
				"id":    u.ID,
				"email": u.Email,
				"level": u.Level,
			})
		}
		settings := map[string]any{"clients": clients, "decryption": "none"}
		if spec.Stream != nil && spec.Stream.Security == "reality" {
			settings["flow"] = "xtls-rprx-vision"
		}
		return settings, nil
	case "vmess":
		clients := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			clients = append(clients, map[string]any{
				"id":    u.ID,
				"email": u.Email,
				"level": u.Level,
			})
		}
		return map[string]any{"clients": clients}, nil
	case "trojan":
		clients := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			clients = append(clients, map[string]any{
				"password": u.Password,
				"email":    u.Email,
				"level":    u.Level,
			})
		}
		return map[string]any{"clients": clients}, nil
	case "shadowsocks":
		// Xray multi-user shadowsocks: top-level method + clients.
		method := "aes-128-gcm"
		var password string
		if len(spec.Users) > 0 {
			password = spec.Users[0].Password
		}
		clients := make([]map[string]any, 0, len(spec.Users))
		for _, u := range spec.Users {
			clients = append(clients, map[string]any{
				"password": u.Password,
				"email":    u.Email,
				"level":    u.Level,
				"method":   method,
			})
		}
		return map[string]any{
			"method":   method,
			"password": password,
			"clients":  clients,
			"network":  "tcp,udp",
		}, nil
	default:
		return nil, fmt.Errorf("xray: unsupported inbound protocol %q", spec.Protocol)
	}
}

func buildXrayStreamSettings(s *StreamSpec) map[string]any {
	if s == nil {
		return nil
	}
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	ss := map[string]any{"network": network}

	switch s.Security {
	case "tls":
		ss["security"] = "tls"
		tls := map[string]any{}
		if s.TLS != nil {
			if s.TLS.SNI != "" {
				tls["serverName"] = s.TLS.SNI
			}
			if len(s.TLS.ALPN) > 0 {
				tls["alpn"] = s.TLS.ALPN
			}
			tls["allowInsecure"] = s.TLS.AllowInsecure
			if s.TLS.CertFile != "" || s.TLS.KeyFile != "" {
				tls["certificates"] = []map[string]any{
					{"certificateFile": s.TLS.CertFile, "keyFile": s.TLS.KeyFile},
				}
			}
		}
		ss["tlsSettings"] = tls
	case "reality":
		ss["security"] = "reality"
		r := map[string]any{}
		if s.Reality != nil {
			r["dest"] = s.Reality.Dest
			r["serverNames"] = s.Reality.ServerNames
			r["privateKey"] = s.Reality.PrivateKey
			r["shortIds"] = s.Reality.ShortIDs
			r["show"] = false
		}
		ss["realitySettings"] = r
	default:
		ss["security"] = "none"
	}

	switch network {
	case "ws":
		ws := map[string]any{"path": "/"}
		if s.WS != nil {
			if s.WS.Path != "" {
				ws["path"] = s.WS.Path
			}
			if s.WS.Host != "" {
				ws["headers"] = map[string]any{"Host": s.WS.Host}
			}
		}
		ss["wsSettings"] = ws
	case "grpc":
		ss["grpcSettings"] = map[string]any{"serviceName": "gun"}
	}
	return ss
}

// buildXrayOutbounds is THE CRUX. It generates the outbounds array and returns
// the tag of the main outbound that user traffic should be routed to.
//
//   - default (no Outbound, empty Dialer): [{freedom, tag:direct}], main=direct
//   - single upstream (socks/http): main outbound is that proxy, tag=proxy
//   - dialer chain: main outbound dials through hop1; hop1 through hop2; ...;
//     the last hop dials directly (freedom, no dialerProxy). Linkage is via
//     streamSettings.sockopt.dialerProxy referencing the NEXT hop's tag.
func buildXrayOutbounds(spec *NodeSpec) ([]any, string) {
	// No upstream and no chain: plain direct.
	if spec.Outbound == nil && len(spec.Dialer) == 0 {
		direct := map[string]any{"protocol": "freedom", "tag": "direct"}
		return []any{direct}, "direct"
	}

	outbounds := make([]any, 0, len(spec.Dialer)+2)

	// Determine the main outbound spec. If Outbound is provided we use it,
	// otherwise the first dialer hop acts as the main outbound.
	var mainSpec OutboundSpec
	var chain []OutboundSpec
	if spec.Outbound != nil {
		mainSpec = *spec.Outbound
		chain = spec.Dialer
	} else {
		mainSpec = spec.Dialer[0]
		chain = spec.Dialer[1:]
	}

	mainTag := mainSpec.Tag
	if mainTag == "" {
		mainTag = "proxy"
		mainSpec.Tag = mainTag
	}

	// Resolve the dialerProxy tag for the main outbound: the first chain hop.
	mainDialerProxy := mainSpec.DialerProxyTag
	if mainDialerProxy == "" && len(chain) > 0 {
		mainDialerProxy = chainTag(chain, 0)
	}

	main := buildXrayOutbound(mainSpec, mainDialerProxy)
	outbounds = append(outbounds, main)

	// Append chain hops; each hop dials through the next hop's tag, the last
	// hop dials directly.
	for i := range chain {
		hop := chain[i]
		if hop.Tag == "" {
			hop.Tag = chainTag(chain, i)
		}
		dialerProxy := hop.DialerProxyTag
		if dialerProxy == "" && i+1 < len(chain) {
			dialerProxy = chainTag(chain, i+1)
		}
		outbounds = append(outbounds, buildXrayOutbound(hop, dialerProxy))
	}

	return outbounds, mainTag
}

// chainTag returns the effective tag for chain hop i, honoring an explicit Tag
// or falling back to a stable generated name.
func chainTag(chain []OutboundSpec, i int) string {
	if chain[i].Tag != "" {
		return chain[i].Tag
	}
	return fmt.Sprintf("dialer-%d", i+1)
}

// buildXrayOutbound renders one outbound. When dialerProxyTag is non-empty the
// outbound's underlying TCP is dialed through that tag's outbound.
func buildXrayOutbound(spec OutboundSpec, dialerProxyTag string) map[string]any {
	ob := map[string]any{"tag": spec.Tag}

	switch spec.Protocol {
	case "", "freedom":
		ob["protocol"] = "freedom"
	case "socks":
		server := map[string]any{"address": spec.Address, "port": spec.Port}
		if spec.User != "" || spec.Pass != "" {
			server["users"] = []map[string]any{{"user": spec.User, "pass": spec.Pass}}
		}
		ob["protocol"] = "socks"
		ob["settings"] = map[string]any{"servers": []map[string]any{server}}
	case "http":
		server := map[string]any{"address": spec.Address, "port": spec.Port}
		if spec.User != "" || spec.Pass != "" {
			server["users"] = []map[string]any{{"user": spec.User, "pass": spec.Pass}}
		}
		ob["protocol"] = "http"
		ob["settings"] = map[string]any{"servers": []map[string]any{server}}
	case "shadowsocks":
		ob["protocol"] = "shadowsocks"
		ob["settings"] = map[string]any{"servers": []map[string]any{{
			"address":  spec.Address,
			"port":     spec.Port,
			"method":   firstNonEmpty(spec.Security, "aes-128-gcm"),
			"password": spec.Pass,
		}}}
	case "vless":
		user := map[string]any{"id": spec.UUID, "encryption": "none"}
		if spec.Security != "" {
			user["flow"] = spec.Security
		}
		ob["protocol"] = "vless"
		ob["settings"] = map[string]any{"vnext": []map[string]any{{
			"address": spec.Address,
			"port":    spec.Port,
			"users":   []map[string]any{user},
		}}}
	case "vmess":
		ob["protocol"] = "vmess"
		ob["settings"] = map[string]any{"vnext": []map[string]any{{
			"address": spec.Address,
			"port":    spec.Port,
			"users":   []map[string]any{{"id": spec.UUID, "security": firstNonEmpty(spec.Security, "auto")}},
		}}}
	case "trojan":
		ob["protocol"] = "trojan"
		ob["settings"] = map[string]any{"servers": []map[string]any{{
			"address":  spec.Address,
			"port":     spec.Port,
			"password": spec.Pass,
		}}}
	default:
		ob["protocol"] = "freedom"
	}

	if dialerProxyTag != "" {
		ob["streamSettings"] = map[string]any{
			"sockopt": map[string]any{"dialerProxy": dialerProxyTag},
		}
	}
	return ob
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
