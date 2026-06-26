package kernel

import (
	"encoding/json"
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

	outbounds, mainTag := buildXrayOutbounds(spec)
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
	outbounds, mainTag := buildXrayOutbounds(spec)
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
	outbounds, mainTag := buildXrayOutbounds(spec)
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
