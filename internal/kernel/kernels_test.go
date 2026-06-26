package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHysteria2Render(t *testing.T) {
	spec := &NodeSpec{
		Tag: "h", Kernel: "hysteria2", Protocol: "hysteria2", Port: 443,
		Users:    []UserSpec{{Email: "u@x", Password: "pw"}},
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.2.3.4", Port: 1080, User: "a", Pass: "b"},
	}
	data, ext, err := Render(spec)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ext != "yaml" {
		t.Fatalf("ext = %q, want yaml", ext)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("hysteria2 config not valid json: %v", err)
	}
	if cfg["listen"] != "0.0.0.0:443" {
		t.Fatalf("listen = %v", cfg["listen"])
	}
	if _, ok := cfg["outbounds"]; !ok {
		t.Fatalf("expected outbounds for socks upstream")
	}
}

func TestSingboxRenderChain(t *testing.T) {
	spec := &NodeSpec{
		Tag: "s", Kernel: "singbox", Protocol: "trojan", Port: 443,
		Users:    []UserSpec{{Email: "u", Password: "pw"}},
		Outbound: &OutboundSpec{Protocol: "socks", Address: "1.1.1.1", Port: 1080, Tag: "proxy"},
		Dialer:   []OutboundSpec{{Protocol: "socks", Address: "2.2.2.2", Port: 1080, Tag: "hop1"}},
	}
	data, ext, err := Render(spec)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ext != "json" {
		t.Fatalf("ext = %q", ext)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	obs := cfg["outbounds"].([]any)
	// proxy must detour through hop1.
	var proxyDetour string
	for _, o := range obs {
		m := o.(map[string]any)
		if m["tag"] == "proxy" {
			proxyDetour, _ = m["detour"].(string)
		}
	}
	if proxyDetour != "hop1" {
		t.Fatalf("proxy detour = %q, want hop1", proxyDetour)
	}
}

func TestNaiveRender(t *testing.T) {
	spec := &NodeSpec{
		Tag: "n", Kernel: "naive", Protocol: "naive", Port: 443,
		Users:  []UserSpec{{Email: "user1", Password: "pass1"}},
		Stream: &StreamSpec{Security: "tls", TLS: &TLSSpec{SNI: "proxy.example.com"}},
	}
	data, ext, err := Render(spec)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ext != "Caddyfile" {
		t.Fatalf("ext = %q, want Caddyfile", ext)
	}
	out := string(data)
	if !strings.Contains(out, "proxy.example.com:443") {
		t.Fatalf("missing site address in Caddyfile:\n%s", out)
	}
	if !strings.Contains(out, "forward_proxy") {
		t.Fatalf("missing forward_proxy directive")
	}
	if !strings.Contains(out, "basic_auth user1 pass1") {
		t.Fatalf("missing basic_auth entry:\n%s", out)
	}
}

func TestGenerateWritesFile(t *testing.T) {
	dir := t.TempDir()
	spec := &NodeSpec{Tag: "g", Kernel: "xray", Protocol: "vless", Port: 443}
	path, err := Generate(spec, dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if filepath.Dir(path) != filepath.Join(dir, "xray") {
		t.Fatalf("unexpected dir: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %v", err)
	}
}

func TestUnknownKernel(t *testing.T) {
	_, _, err := Render(&NodeSpec{Kernel: "bogus"})
	if err == nil {
		t.Fatalf("expected error for unknown kernel")
	}
}
