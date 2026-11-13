package kernel

import (
	"fmt"
	"strings"
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
	// Observatory health-checks the pool members so dead upstreams are skipped.
	Observatory map[string]any `json:"observatory,omitempty"`
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
	Balancers      []any           `json:"balancers,omitempty"`
}

type xrayRouteRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
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

	outbounds, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		return xrayConfig{}, err
	}
	// Pool egress: route the business inbound to a balancer over the members.
	var balancers []any
	var observatory map[string]any
	userRule := xrayRouteRule{Type: "field", InboundTag: []string{spec.Tag}, OutboundTag: mainTag}
	if spec.OutboundGroup != nil {
		balancers, observatory = buildXrayBalancer(spec.OutboundGroup)
		userRule = xrayRouteRule{Type: "field", InboundTag: []string{spec.Tag}, BalancerTag: poolBalancerTag}
	}

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
				userRule,
			},
			Balancers: balancers,
		},
		Observatory: observatory,
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
	case "socks", "http":
		accts := make([]map[string]any, 0, len(spec.Users))
		for _, a := range proxyAccounts(spec.Users) {
			accts = append(accts, map[string]any{"user": a.User, "pass": a.Pass})
		}
		if spec.Protocol == "socks" {
			return map[string]any{"auth": "password", "accounts": accts, "udp": false}, nil
		}
		return map[string]any{"accounts": accts, "allowTransparent": false}, nil
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
		// The spec reuses WS.Path as the gRPC serviceName and WS.Host as the
		// :authority; the panel's share links mirror this (see GRPCServiceName).
		grpc := map[string]any{"serviceName": GRPCServiceName(s)}
		if s.WS != nil && s.WS.Host != "" {
			grpc["authority"] = s.WS.Host
		}
		ss["grpcSettings"] = grpc
	}
	return ss
}

// GRPCServiceName returns the gRPC serviceName for a stream: WS.Path without a
// leading slash, or "gun" when unset.
func GRPCServiceName(s *StreamSpec) string {
	if s != nil && s.WS != nil {
		if n := strings.TrimPrefix(s.WS.Path, "/"); n != "" {
			return n
		}
	}
	return "gun"
}

// buildXrayOutbounds is THE CRUX. It generates the outbounds array and returns
// the tag of the main outbound that user traffic should be routed to.
//
//   - default (no Outbound, empty Dialer): [{freedom, tag:direct}], main=direct
//   - single upstream (socks/http): main outbound is that proxy, tag=proxy
//   - dialer chain: main outbound dials through hop1; hop1 through hop2; ...;
//     the last hop dials directly (freedom, no dialerProxy). Linkage is via
//     streamSettings.sockopt.dialerProxy referencing the NEXT hop's tag.
func buildXrayOutbounds(spec *NodeSpec) ([]any, string, error) {
	if spec.OutboundGroup != nil {
		return buildXrayPoolOutbounds(spec)
	}
	// No upstream and no chain: plain direct.
	if spec.Outbound == nil && len(spec.Dialer) == 0 {
		direct := map[string]any{"protocol": "freedom", "tag": "direct"}
		return []any{direct}, "direct", nil
	}

	outbounds := make([]any, 0, len(spec.Dialer)+2)
	tags := make([]string, 0, len(spec.Dialer)+1) // every generated outbound tag
	refs := make([]string, 0, len(spec.Dialer)+1) // every dialerProxy reference

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

	outbounds = append(outbounds, buildXrayOutbound(mainSpec, mainDialerProxy))
	tags = append(tags, mainSpec.Tag)
	if mainDialerProxy != "" {
		refs = append(refs, mainDialerProxy)
	}

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
		tags = append(tags, hop.Tag)
		if dialerProxy != "" {
			refs = append(refs, dialerProxy)
		}
	}

	// Validate tag uniqueness: duplicate outbound tags make Xray reject the
	// config and silently collapse dialer-proxy links.
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if t == "" {
			return nil, "", fmt.Errorf("xray: outbound with empty tag")
		}
		if seen[t] {
			return nil, "", fmt.Errorf("xray: duplicate outbound tag %q", t)
		}
		seen[t] = true
	}
	// Validate every dialerProxy reference points at a real outbound; an
	// explicit-but-dangling DialerProxyTag would orphan a hop.
	for _, r := range refs {
		if !seen[r] {
			return nil, "", fmt.Errorf("xray: dialerProxy tag %q references no outbound", r)
		}
	}

	return outbounds, mainTag, nil
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

	var ss map[string]any
	if spec.Stream != nil {
		ss = buildXrayOutboundStream(spec.Stream)
	}
	if dialerProxyTag != "" {
		if ss == nil {
			ss = map[string]any{}
		}
		ss["sockopt"] = map[string]any{"dialerProxy": dialerProxyTag}
	}
	if ss != nil {
		ob["streamSettings"] = ss
	}
	return ob
}

// buildXrayOutboundStream renders the client-side streamSettings used to dial
// another node's inbound.
func buildXrayOutboundStream(s *OutboundStream) map[string]any {
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	ss := map[string]any{"network": network}
	switch s.Security {
	case "tls":
		ss["security"] = "tls"
		tls := map[string]any{"allowInsecure": s.AllowInsecure}
		if s.SNI != "" {
			tls["serverName"] = s.SNI
		}
		if len(s.ALPN) > 0 {
			tls["alpn"] = s.ALPN
		}
		if s.Fingerprint != "" {
			tls["fingerprint"] = s.Fingerprint
		}
		ss["tlsSettings"] = tls
	case "reality":
		ss["security"] = "reality"
		r := map[string]any{
			"serverName":  s.SNI,
			"fingerprint": firstNonEmpty(s.Fingerprint, "chrome"),
			"publicKey":   s.PublicKey,
			"shortId":     s.ShortID,
		}
		ss["realitySettings"] = r
	default:
		ss["security"] = "none"
	}
	switch network {
	case "ws":
		ws := map[string]any{"path": firstNonEmpty(s.Path, "/")}
		if s.Host != "" {
			ws["headers"] = map[string]any{"Host": s.Host}
		}
		ss["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{"serviceName": firstNonEmpty(strings.TrimPrefix(s.Path, "/"), "gun")}
		if s.Host != "" {
			grpc["authority"] = s.Host
		}
		ss["grpcSettings"] = grpc
	}
	return ss
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

const (
	poolBalancerTag = "upstream-pool"
	poolMemberTag   = "pool-" // observatory/balancer selector prefix
)

// buildXrayPoolOutbounds renders every group member as its own outbound
// (pool-1..pool-N), all dialed through the node's dialer chain, plus the chain
// hops themselves. The returned main tag is unused for pools (the routing rule
// targets the balancer instead).
func buildXrayPoolOutbounds(spec *NodeSpec) ([]any, string, error) {
	g := spec.OutboundGroup
	if spec.Outbound != nil {
		return nil, "", fmt.Errorf("xray: outbound and outboundGroup are mutually exclusive")
	}
	if len(g.Members) == 0 {
		return nil, "", fmt.Errorf("xray: outboundGroup has no members")
	}
	switch g.Strategy {
	case "", "random", "roundRobin", "leastPing":
	default:
		return nil, "", fmt.Errorf("xray: unknown outboundGroup strategy %q", g.Strategy)
	}
	chain := spec.Dialer
	first := ""
	if len(chain) > 0 {
		first = chainTag(chain, 0)
	}
	outbounds := make([]any, 0, len(g.Members)+len(chain))
	tags := map[string]bool{}
	for i, m := range g.Members {
		m.Tag = fmt.Sprintf("%s%d", poolMemberTag, i+1)
		outbounds = append(outbounds, buildXrayOutbound(m, first))
		tags[m.Tag] = true
	}
	for i := range chain {
		hop := chain[i]
		if hop.Tag == "" {
			hop.Tag = chainTag(chain, i)
		}
		if tags[hop.Tag] {
			return nil, "", fmt.Errorf("xray: duplicate outbound tag %q", hop.Tag)
		}
		tags[hop.Tag] = true
		dp := hop.DialerProxyTag
		if dp == "" && i+1 < len(chain) {
			dp = chainTag(chain, i+1)
		}
		outbounds = append(outbounds, buildXrayOutbound(hop, dp))
	}
	return outbounds, poolBalancerTag, nil
}

// buildXrayBalancer returns the routing balancers and the observatory config
// for a pool. The observatory probes each member so a dead upstream is skipped.
func buildXrayBalancer(g *OutboundGroup) (balancers []any, observatory map[string]any) {
	strategy := g.Strategy
	if strategy == "" {
		strategy = "random"
	}
	strat := map[string]any{"type": strategy}
	if strategy == "random" {
		// xray's plain "random"/"roundRobin" ignore the observatory and keep
		// sending traffic to dead members. leastLoad with expected == pool size
		// picks randomly among the members that pass the health probe instead.
		strat = map[string]any{"type": "leastLoad", "settings": map[string]any{
			"expected": len(g.Members), "maxRTT": "5s", "tolerance": 0.01}}
	}
	bal := map[string]any{
		"tag":      poolBalancerTag,
		"selector": []string{poolMemberTag},
		"strategy": strat,
	}
	probe := g.ProbeURL
	if probe == "" {
		probe = "https://www.gstatic.com/generate_204"
	}
	interval := g.ProbeInt
	if interval == "" {
		interval = "1m"
	}
	observatory = map[string]any{
		"subjectSelector": []string{poolMemberTag},
		"probeUrl":        probe,
		"probeInterval":   interval,
	}
	return []any{bal}, observatory
}
