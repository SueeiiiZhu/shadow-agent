package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"token":"abc","listen":":9999"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "abc" {
		t.Fatalf("token = %q", cfg.Token)
	}
	if cfg.Listen != ":9999" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.DataDir == "" || cfg.KernelBinDir == "" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("SHADOW_AGENT_TOKEN", "envtok")
	t.Setenv("SHADOW_AGENT_LISTEN", ":7000")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "envtok" {
		t.Fatalf("token = %q, want envtok", cfg.Token)
	}
	if cfg.Listen != ":7000" {
		t.Fatalf("listen = %q, want :7000", cfg.Listen)
	}
}

func TestSelfSignedCert(t *testing.T) {
	cert, err := SelfSignedCert()
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("no certificate generated")
	}
	if cert.PrivateKey == nil {
		t.Fatalf("no private key generated")
	}
}

func TestTLSCertificateFallback(t *testing.T) {
	cfg := Default()
	cert, err := cfg.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate fallback: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("fallback produced empty cert")
	}
}
