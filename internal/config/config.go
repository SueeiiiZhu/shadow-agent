// Package config loads the shadow-agent runtime configuration from a JSON file
// with environment-variable overrides, and provides a self-signed TLS
// certificate (persisted under DataDir) so the agent can always serve HTTPS.
package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AgentConfig is the shadow-agent configuration.
type AgentConfig struct {
	Listen       string `json:"listen"`       // bind address, default ":8443"
	Token        string `json:"token"`        // per-agent bearer token
	TLSCertFile  string `json:"tlsCertFile"`  // optional PEM cert file
	TLSKeyFile   string `json:"tlsKeyFile"`   // optional PEM key file
	KernelBinDir string `json:"kernelBinDir"` // dir holding kernel binaries
	DataDir      string `json:"dataDir"`      // dir for generated configs/state
}

// Default returns a config populated with sensible defaults.
func Default() AgentConfig {
	return AgentConfig{
		Listen:       ":8443",
		KernelBinDir: "/usr/local/bin",
		DataDir:      "/var/lib/shadow-agent",
	}
}

// Load reads config from path (if non-empty) layered over defaults, then
// applies environment-variable overrides.
func Load(path string) (AgentConfig, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	applyEnv(&cfg)
	cfg.normalize()
	return cfg, nil
}

func applyEnv(cfg *AgentConfig) {
	if v := os.Getenv("SHADOW_AGENT_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("SHADOW_AGENT_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("SHADOW_AGENT_TLS_CERT"); v != "" {
		cfg.TLSCertFile = v
	}
	if v := os.Getenv("SHADOW_AGENT_TLS_KEY"); v != "" {
		cfg.TLSKeyFile = v
	}
	if v := os.Getenv("SHADOW_AGENT_KERNEL_BIN_DIR"); v != "" {
		cfg.KernelBinDir = v
	}
	if v := os.Getenv("SHADOW_AGENT_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
}

func (cfg *AgentConfig) normalize() {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.KernelBinDir == "" {
		cfg.KernelBinDir = "/usr/local/bin"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/shadow-agent"
	}
}

// Names of the self-signed certificate persisted under DataDir.
const (
	persistedCertName = "agent-tls.crt"
	persistedKeyName  = "agent-tls.key"
)

// TLSCertificate returns the certificate to serve. If both cert and key files
// are configured it loads them from disk. Otherwise it uses a self-signed
// certificate persisted under DataDir (generated on first start), so the
// certificate fingerprint the panel pinned (TOFU) survives agent restarts.
// If DataDir is unusable it falls back to an ephemeral in-memory certificate.
func (cfg AgentConfig) TLSCertificate() (tls.Certificate, error) {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		return tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if cfg.DataDir == "" {
		return SelfSignedCert()
	}
	certPath := filepath.Join(cfg.DataDir, persistedCertName)
	keyPath := filepath.Join(cfg.DataDir, persistedKeyName)
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}
	certPEM, keyPEM, err := selfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writePersistedCert(cfg.DataDir, certPath, keyPath, certPEM, keyPEM); err != nil {
		log.Printf("warning: cannot persist self-signed TLS cert in %s (%v); using an ephemeral cert, the panel's pinned fingerprint will mismatch after restart", cfg.DataDir, err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writePersistedCert(dir, certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

// SelfSignedCert generates an ephemeral self-signed ECDSA certificate valid for
// localhost and the wildcard, usable entirely from memory.
func SelfSignedCert() (tls.Certificate, error) {
	certPEM, keyPEM, err := selfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func selfSignedPEM() (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Shadow Agent"}, CommonName: "shadow-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "shadow-agent"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
