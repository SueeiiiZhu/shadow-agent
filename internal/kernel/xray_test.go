package kernel

import (
	"encoding/json"
	"strings"
	"testing"
)

// findOutbound returns the outbound map whose "tag" equals tag.
func findOutbound(t *testing.T, outbounds []any, tag string) map[string]any {
	t.Helper()
	for _, o := range outbounds {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if m["tag"] == tag {
			return m
		}
	}
	t.Fatalf("outbound with tag %q not found", tag)
	return nil
}

// dialerProxyOf extracts streamSettings.sockopt.dialerProxy from an outbound.
func dialerProxyOf(t *testing.T, ob map[string]any) string {
	t.Helper()
	ss, ok := ob["streamSettings"].(map[string]any)
	if !ok {
		return ""
	}
	sock, ok := ss["sockopt"].(map[string]any)
	if !ok {
		return ""
	}
	dp, _ := sock["dialerProxy"].(string)
	return dp
}

// TestXraySocksUpstreamWithDialerChain is THE delivery proof: a NodeSpec with a
// socks upstream main outbound plus a two-hop dialer chain must generate
// outbounds where (a) the main outbound's sockopt.dialerProxy == hop1.tag;
// (b) every hop is present with correct chained tags; (c) the socks server's
// address/port/credentials are correct.
func TestXraySocksUpstreamWithDialerChain(t *testing.T) {
	spec := &NodeSpec{
		Tag:      "node-1",
		Kernel:   "xray",
		Protocol: "vless",
		Listen:   "0.0.0.0",
		Port:     443,
		Users:    []UserSpec{{ID: "11111111-1111-1111-1111-111111111111", Email: "u@x"}},
		Outbound: &OutboundSpec{
			Protocol: "socks",
			Address:  "1.2.3.4",
			Port:     1080,
			User:     "alice",
			Pass:     "s3cret",
			Tag:      "proxy",
		},
		Dialer: []OutboundSpec{
			{Protocol: "socks", Address: "5.6.7.8", Port: 1081, Tag: "hop1"},
			{Protocol: "http", Address: "9.10.11.12", Port: 8080, Tag: "hop2"},
		},
	}

	outbounds, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		t.Fatalf("buildXrayOutbounds: %v", err)
	}
	if mainTag != "proxy" {
		t.Fatalf("main tag = %q, want proxy", mainTag)
	}

	// (a) main outbound dials through hop1.
	main := findOutbound(t, outbounds, "proxy")
	if got := dialerProxyOf(t, main); got != "hop1" {
		t.Fatalf("main dialerProxy = %q, want hop1", got)
	}

	// (b) chained tags: hop1 -> hop2 -> direct (last hop has no dialerProxy).
	hop1 := findOutbound(t, outbounds, "hop1")
	if got := dialerProxyOf(t, hop1); got != "hop2" {
		t.Fatalf("hop1 dialerProxy = %q, want hop2", got)
	}
	hop2 := findOutbound(t, outbounds, "hop2")
	if got := dialerProxyOf(t, hop2); got != "" {
		t.Fatalf("hop2 dialerProxy = %q, want empty (last hop direct)", got)
	}

	// All three outbounds present.
	if len(outbounds) != 3 {
		t.Fatalf("len(outbounds) = %d, want 3", len(outbounds))
	}

	// (c) socks server address/port/credentials.
	settings := main["settings"].(map[string]any)
	servers := settings["servers"].([]map[string]any)
	if len(servers) != 1 {
		t.Fatalf("len(servers) = %d, want 1", len(servers))
	}
	srv := servers[0]
	if srv["address"] != "1.2.3.4" {
		t.Fatalf("address = %v, want 1.2.3.4", srv["address"])
	}
	if srv["port"] != 1080 {
		t.Fatalf("port = %v, want 1080", srv["port"])
	}
	users := srv["users"].([]map[string]any)
	if len(users) != 1 || users[0]["user"] != "alice" || users[0]["pass"] != "s3cret" {
		t.Fatalf("users = %v, want alice/s3cret", users)
	}
}

// TestXrayDefaultDirect verifies the default no-upstream case is freedom/direct.
func TestXrayDefaultDirect(t *testing.T) {
	spec := &NodeSpec{Tag: "t", Kernel: "xray", Protocol: "vless", Port: 443}
	outbounds, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		t.Fatalf("buildXrayOutbounds: %v", err)
	}
	if mainTag != "direct" {
		t.Fatalf("mainTag = %q, want direct", mainTag)
	}
	if len(outbounds) != 1 {
		t.Fatalf("len(outbounds) = %d, want 1", len(outbounds))
	}
	ob := outbounds[0].(map[string]any)
	if ob["protocol"] != "freedom" || ob["tag"] != "direct" {
		t.Fatalf("default outbound = %v, want freedom/direct", ob)
	}
}

// TestXrayChainOnly verifies a chain supplied with no Outbound uses the first
// hop as the main outbound.
func TestXrayChainOnly(t *testing.T) {
	spec := &NodeSpec{
		Tag: "t", Kernel: "xray", Protocol: "vless", Port: 443,
		Dialer: []OutboundSpec{
			{Protocol: "socks", Address: "1.1.1.1", Port: 1080, Tag: "edge"},
			{Protocol: "socks", Address: "2.2.2.2", Port: 1080, Tag: "exit"},
		},
	}
	outbounds, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		t.Fatalf("buildXrayOutbounds: %v", err)
	}
	if mainTag != "edge" {
		t.Fatalf("mainTag = %q, want edge", mainTag)
	}
	main := findOutbound(t, outbounds, "edge")
	if got := dialerProxyOf(t, main); got != "exit" {
		t.Fatalf("edge dialerProxy = %q, want exit", got)
	}
	exit := findOutbound(t, outbounds, "exit")
	if got := dialerProxyOf(t, exit); got != "" {
		t.Fatalf("exit dialerProxy = %q, want empty", got)
	}
}

// TestXrayFullConfigMarshals ensures the complete config marshals to valid JSON
// and contains the expected top-level keys and routing wiring.
func TestXrayFullConfigMarshals(t *testing.T) {
	spec := &NodeSpec{
		Tag: "node-1", Kernel: "xray", Protocol: "vless", Port: 443,
		Users:  []UserSpec{{ID: "uuid", Email: "e"}},
		Stream: &StreamSpec{Network: "ws", Security: "tls", TLS: &TLSSpec{SNI: "x.com"}, WS: &WSSpec{Path: "/ray"}},
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.2.3.4", Port: 1080, Tag: "proxy"},
	}
	data, ext, err := Render(spec)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ext != "json" {
		t.Fatalf("ext = %q, want json", ext)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"log", "api", "stats", "policy", "inbounds", "outbounds", "routing"} {
		if _, ok := cfg[k]; !ok {
			t.Fatalf("config missing key %q", k)
		}
	}
	routing := cfg["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	// Second rule routes the node tag to the main outbound (proxy).
	r1 := rules[1].(map[string]any)
	if r1["outboundTag"] != "proxy" {
		t.Fatalf("node route outboundTag = %v, want proxy", r1["outboundTag"])
	}
}

// TestXrayAutoTagChain verifies the auto-generated tag path: when hops omit
// explicit tags, the main outbound dials through "dialer-1", which dials through
// "dialer-2", and the last hop dials directly.
func TestXrayAutoTagChain(t *testing.T) {
	spec := &NodeSpec{
		Tag: "t", Kernel: "xray", Protocol: "vless", Port: 443,
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.1.1.1", Port: 1080}, // no Tag
		Dialer: []OutboundSpec{
			{Protocol: "socks", Address: "2.2.2.2", Port: 1080}, // no Tag -> dialer-1
			{Protocol: "http", Address: "3.3.3.3", Port: 8080},  // no Tag -> dialer-2
		},
	}
	outbounds, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		t.Fatalf("buildXrayOutbounds: %v", err)
	}
	if mainTag != "proxy" {
		t.Fatalf("mainTag = %q, want proxy (default)", mainTag)
	}
	main := findOutbound(t, outbounds, "proxy")
	if got := dialerProxyOf(t, main); got != "dialer-1" {
		t.Fatalf("main dialerProxy = %q, want dialer-1", got)
	}
	d1 := findOutbound(t, outbounds, "dialer-1")
	if got := dialerProxyOf(t, d1); got != "dialer-2" {
		t.Fatalf("dialer-1 dialerProxy = %q, want dialer-2", got)
	}
	d2 := findOutbound(t, outbounds, "dialer-2")
	if got := dialerProxyOf(t, d2); got != "" {
		t.Fatalf("dialer-2 dialerProxy = %q, want empty (last hop direct)", got)
	}
}

// TestXrayDuplicateTagRejected verifies that colliding outbound tags are
// rejected rather than silently producing a broken config.
func TestXrayDuplicateTagRejected(t *testing.T) {
	spec := &NodeSpec{
		Tag: "t", Kernel: "xray", Protocol: "vless", Port: 443,
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.1.1.1", Port: 1080, Tag: "dup"},
		Dialer: []OutboundSpec{
			{Protocol: "socks", Address: "2.2.2.2", Port: 1080, Tag: "dup"},
		},
	}
	if _, _, err := buildXrayOutbounds(spec); err == nil {
		t.Fatalf("expected error for duplicate outbound tag, got nil")
	}
}

// TestXrayDanglingDialerProxyRejected verifies that an explicit DialerProxyTag
// pointing at no outbound is rejected.
func TestXrayDanglingDialerProxyRejected(t *testing.T) {
	spec := &NodeSpec{
		Tag: "t", Kernel: "xray", Protocol: "vless", Port: 443,
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.1.1.1", Port: 1080, Tag: "proxy", DialerProxyTag: "ghost"},
	}
	if _, _, err := buildXrayOutbounds(spec); err == nil {
		t.Fatalf("expected error for dangling dialerProxy tag, got nil")
	}
}

func TestXrayGRPCServiceNameFromSpec(t *testing.T) {
	cases := []struct {
		path, host, want, wantAuth string
	}{
		{"", "", "gun", ""},
		{"/myservice", "", "myservice", ""},
		{"svc", "cdn.example.com", "svc", "cdn.example.com"},
	}
	for _, c := range cases {
		ss := buildXrayStreamSettings(&StreamSpec{Network: "grpc", WS: &WSSpec{Path: c.path, Host: c.host}})
		g := ss["grpcSettings"].(map[string]any)
		if g["serviceName"] != c.want {
			t.Errorf("path %q: serviceName %v, want %s", c.path, g["serviceName"], c.want)
		}
		if a, _ := g["authority"].(string); a != c.wantAuth {
			t.Errorf("host %q: authority %q, want %q", c.host, a, c.wantAuth)
		}
	}
	// nil WS block still yields the default.
	ss := buildXrayStreamSettings(&StreamSpec{Network: "grpc"})
	if ss["grpcSettings"].(map[string]any)["serviceName"] != "gun" {
		t.Error("default serviceName must be gun")
	}
}

// A dialer hop that is another panel node: vless over REALITY/TLS/ws, with the
// upstream dialed through it.
func TestXrayNodeHopStream(t *testing.T) {
	spec := &NodeSpec{
		Tag: "a", Kernel: "xray", Protocol: "vless", Port: 2053,
		Outbound: &OutboundSpec{Protocol: "socks", Address: "up.example.com", Port: 5001, User: "u", Pass: "p"},
		Dialer: []OutboundSpec{{
			Protocol: "vless", Address: "b.example.com", Port: 443, UUID: "uuid-b",
			Stream: &OutboundStream{Network: "tcp", Security: "reality", SNI: "www.microsoft.com", PublicKey: "PUB", ShortID: "ab"},
		}, {
			Protocol: "trojan", Address: "c.example.com", Port: 8443, Pass: "pw",
			Stream: &OutboundStream{Network: "ws", Security: "tls", SNI: "c.example.com", Path: "/w", Host: "c.example.com"},
		}},
	}
	obs, mainTag, err := buildXrayOutbounds(spec)
	if err != nil {
		t.Fatal(err)
	}
	main := findOutbound(t, obs, mainTag)
	if dialerProxyOf(t, main) != "dialer-1" {
		t.Fatalf("upstream must dial via hop1, got %q", dialerProxyOf(t, main))
	}
	hop1 := findOutbound(t, obs, "dialer-1")
	ss := hop1["streamSettings"].(map[string]any)
	if ss["security"] != "reality" {
		t.Fatalf("hop1 security = %v", ss["security"])
	}
	r := ss["realitySettings"].(map[string]any)
	if r["publicKey"] != "PUB" || r["shortId"] != "ab" || r["serverName"] != "www.microsoft.com" || r["fingerprint"] != "chrome" {
		t.Fatalf("reality settings = %v", r)
	}
	if dialerProxyOf(t, hop1) != "dialer-2" {
		t.Fatalf("hop1 must dial via hop2, got %q", dialerProxyOf(t, hop1))
	}
	hop2 := findOutbound(t, obs, "dialer-2")
	ss2 := hop2["streamSettings"].(map[string]any)
	if ss2["network"] != "ws" || ss2["security"] != "tls" {
		t.Fatalf("hop2 stream = %v", ss2)
	}
	if ss2["wsSettings"].(map[string]any)["path"] != "/w" {
		t.Fatalf("hop2 ws = %v", ss2["wsSettings"])
	}
	if dialerProxyOf(t, hop2) != "" {
		t.Fatalf("last hop must dial directly")
	}
	if _, err := json.Marshal(obs); err != nil {
		t.Fatal(err)
	}
}

func TestXrayOutboundGroup(t *testing.T) {
	spec := &NodeSpec{Tag: "a", Kernel: "xray", Protocol: "vless", Port: 2055,
		OutboundGroup: &OutboundGroup{Strategy: "roundRobin", Members: []OutboundSpec{
			{Protocol: "socks", Address: "1.1.1.1", Port: 1080},
			{Protocol: "socks", Address: "2.2.2.2", Port: 1080, User: "u", Pass: "p"},
		}},
		Dialer: []OutboundSpec{{Protocol: "socks", Address: "9.9.9.9", Port: 1}},
	}
	cfg, err := buildXrayConfig(spec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	obs := m["outbounds"].([]any)
	if len(obs) != 3 {
		t.Fatalf("want 2 members + 1 hop, got %d", len(obs))
	}
	for _, tag := range []string{"pool-1", "pool-2"} {
		if dialerProxyOf(t, findOutbound(t, obs, tag)) != "dialer-1" {
			t.Errorf("%s must dial through the chain", tag)
		}
	}
	rules := m["routing"].(map[string]any)["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["balancerTag"] != "upstream-pool" || last["outboundTag"] != nil {
		t.Fatalf("user rule must target the balancer: %v", last)
	}
	bal := m["routing"].(map[string]any)["balancers"].([]any)[0].(map[string]any)
	if bal["strategy"].(map[string]any)["type"] != "roundRobin" || bal["selector"].([]any)[0] != "pool-" {
		t.Fatalf("balancer = %v", bal)
	}
	if m["observatory"].(map[string]any)["probeUrl"] == "" {
		t.Fatal("observatory missing")
	}

	// Non-pool nodes must not grow balancers/observatory.
	plain, _ := json.Marshal(mustCfg(t, &NodeSpec{Tag: "p", Kernel: "xray", Protocol: "vless", Port: 1}))
	if strings.Contains(string(plain), "balancers") || strings.Contains(string(plain), "observatory") {
		t.Fatal("plain node must not carry pool config")
	}
	for name, bad := range map[string]*NodeSpec{
		"empty":    {Tag: "a", Kernel: "xray", Protocol: "vless", Port: 1, OutboundGroup: &OutboundGroup{}},
		"strategy": {Tag: "a", Kernel: "xray", Protocol: "vless", Port: 1, OutboundGroup: &OutboundGroup{Strategy: "x", Members: []OutboundSpec{{Protocol: "socks", Address: "a", Port: 1}}}},
		"both":     {Tag: "a", Kernel: "xray", Protocol: "vless", Port: 1, Outbound: &OutboundSpec{Protocol: "socks", Address: "a", Port: 1}, OutboundGroup: &OutboundGroup{Members: []OutboundSpec{{Protocol: "socks", Address: "a", Port: 1}}}},
	} {
		if _, err := buildXrayConfig(bad); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	nonX := &NodeSpec{Tag: "s", Kernel: "singbox", Protocol: "vless", Port: 1, OutboundGroup: &OutboundGroup{Members: []OutboundSpec{{Protocol: "socks", Address: "a", Port: 1}}}}
	if _, _, err := Render(nonX); err == nil {
		t.Error("group on a non-xray kernel must be rejected")
	}
}

func mustCfg(t *testing.T, s *NodeSpec) xrayConfig {
	t.Helper()
	c, err := buildXrayConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestXrayRandomPoolIsHealthAware(t *testing.T) {
	cfg := mustCfg(t, &NodeSpec{Tag: "a", Kernel: "xray", Protocol: "vless", Port: 1, OutboundGroup: &OutboundGroup{
		Strategy: "random", Members: []OutboundSpec{{Protocol: "socks", Address: "a", Port: 1}, {Protocol: "socks", Address: "b", Port: 1}}}})
	if len(cfg.Routing.Balancers) != 1 {
		t.Fatalf("want 1 balancer, got %d", len(cfg.Routing.Balancers))
	}
	raw, _ := json.Marshal(cfg.Routing.Balancers[0])
	var bal struct {
		Strategy struct {
			Type     string
			Settings struct{ Expected int }
		}
	}
	_ = json.Unmarshal(raw, &bal)
	if bal.Strategy.Type != "leastLoad" || bal.Strategy.Settings.Expected != 2 {
		t.Fatalf("random must render as health-aware leastLoad with expected=pool size: %s", raw)
	}
}
