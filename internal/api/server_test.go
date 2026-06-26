package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SueeiiiZhu/shadow-agent/internal/config"
	"github.com/SueeiiiZhu/shadow-agent/internal/process"
)

func newTestServer(t *testing.T, token string) http.Handler {
	t.Helper()
	cfg := config.AgentConfig{Token: token, DataDir: t.TempDir(), KernelBinDir: t.TempDir()}
	sup := process.New(cfg.DataDir, cfg.KernelBinDir)
	return New(cfg, sup).Handler()
}

func TestHealthzNoAuth(t *testing.T) {
	h := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz code = %d, want 200", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["ok"] != true {
		t.Fatalf("healthz ok = %v", body["ok"])
	}
}

func TestAuthRequired(t *testing.T) {
	h := newTestServer(t, "secret")
	tests := []struct {
		name, auth string
		want       int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"right token", "Bearer secret", http.StatusOK},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
		if tt.auth != "" {
			req.Header.Set("Authorization", tt.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Fatalf("%s: code = %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
}

func TestCreateAndListNode(t *testing.T) {
	h := newTestServer(t, "secret")
	specJSON := `{"tag":"node-1","kernel":"xray","protocol":"vless","port":443,
		"users":[{"id":"uuid"}],
		"outbound":{"protocol":"socks","address":"1.2.3.4","port":1080,"tag":"proxy"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader(specJSON))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create code = %d body=%s", rec.Code, rec.Body.String())
	}
	var state map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &state)
	if state["tag"] != "node-1" {
		t.Fatalf("tag = %v", state["tag"])
	}
	// Binary absent in test env -> running false, error binary not found.
	if state["error"] != "binary not found" {
		t.Fatalf("error = %v", state["error"])
	}

	// List should return it.
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	lreq.Header.Set("Authorization", "Bearer secret")
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, lreq)
	var list []map[string]any
	_ = json.Unmarshal(lrec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}

	// Delete it.
	dreq := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/node-1", nil)
	dreq.Header.Set("Authorization", "Bearer secret")
	drec := httptest.NewRecorder()
	h.ServeHTTP(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("delete code = %d", drec.Code)
	}
}

func TestTrafficZeroWithoutKernel(t *testing.T) {
	h := newTestServer(t, "secret")
	// Create a node first.
	specJSON := `{"tag":"t","kernel":"xray","protocol":"vless","port":443}`
	creq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader(specJSON))
	creq.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(httptest.NewRecorder(), creq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/traffic", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var stats []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats len = %d, want 1", len(stats))
	}
	if stats[0]["uplinkBytes"] != float64(0) || stats[0]["downlinkBytes"] != float64(0) {
		t.Fatalf("expected zero traffic, got %v", stats[0])
	}
}

func TestEmptyTokenDenies(t *testing.T) {
	h := newTestServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty-token agent should deny, got %d", rec.Code)
	}
}
