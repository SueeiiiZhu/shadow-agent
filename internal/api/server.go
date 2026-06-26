// Package api implements the shadow-agent HTTPS REST control surface consumed by
// the shadow-panel control plane.
package api

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/SueeiiiZhu/shadow-agent/internal/config"
	"github.com/SueeiiiZhu/shadow-agent/internal/kernel"
	"github.com/SueeiiiZhu/shadow-agent/internal/process"
	"github.com/SueeiiiZhu/shadow-agent/internal/traffic"
)

// Version is the agent build version reported via /healthz and /server/state.
const Version = "0.1.0"

// Server wires the supervisor, traffic collector, and config into an
// http.Server with TLS and bearer-token auth.
type Server struct {
	cfg     config.AgentConfig
	sup     *process.Supervisor
	traffic *traffic.Collector
	start   time.Time
}

// New constructs a Server.
func New(cfg config.AgentConfig, sup *process.Supervisor) *Server {
	return &Server{
		cfg:     cfg,
		sup:     sup,
		traffic: traffic.New(),
		start:   time.Now(),
	}
}

// Handler returns the fully-routed, auth-wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/server/state", s.handleServerState)
	mux.HandleFunc("POST /api/v1/nodes", s.handleCreateNode)
	mux.HandleFunc("GET /api/v1/nodes", s.handleListNodes)
	mux.HandleFunc("DELETE /api/v1/nodes/{tag}", s.handleDeleteNode)
	mux.HandleFunc("GET /api/v1/nodes/{tag}/state", s.handleNodeState)
	mux.HandleFunc("GET /api/v1/traffic", s.handleTraffic)
	return s.authMiddleware(mux)
}

// HTTPServer builds an *http.Server with TLS configured from the agent config.
func (s *Server) HTTPServer() (*http.Server, error) {
	cert, err := s.cfg.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              "",
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}, nil
}

// authMiddleware enforces the bearer token using a constant-time comparison.
// /healthz is exempt so liveness probes work without credentials.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.Token == "" {
			// No token configured: deny by default to avoid an open control plane.
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "agent token not configured"})
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		got := strings.TrimPrefix(auth, prefix)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": Version})
}

func (s *Server) handleServerState(w http.ResponseWriter, _ *http.Request) {
	mem := readMem()
	st := serverState{
		CPUPercent: readCPUPercent(),
		MemUsedMB:  mem.usedMB,
		MemTotalMB: mem.totalMB,
		UptimeSec:  int64(time.Since(s.start).Seconds()),
		Kernels:    s.detectKernels(),
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var spec kernel.NodeSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid NodeSpec: " + err.Error()})
		return
	}
	if spec.Tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tag is required"})
		return
	}
	state, err := s.sup.Apply(spec)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleListNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.sup.List())
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	if err := s.sup.Remove(tag); err != nil {
		if err == process.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "node not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.traffic.Forget(tag)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleNodeState(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	state, err := s.sup.State(tag)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "node not found"})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleTraffic(w http.ResponseWriter, _ *http.Request) {
	specs := s.sup.Specs()
	tags := make([]string, 0, len(specs))
	for _, sp := range specs {
		tags = append(tags, sp.Tag)
	}
	// No kernel stats source wired in this environment: sampler reports no data,
	// yielding zero deltas per contract.
	stats := s.traffic.Collect(tags, func(string) (int64, int64, bool) { return 0, 0, false })
	writeJSON(w, http.StatusOK, stats)
}

// serverState is the /server/state response body.
type serverState struct {
	CPUPercent float64           `json:"cpuPercent"`
	MemUsedMB  int64             `json:"memUsedMB"`
	MemTotalMB int64             `json:"memTotalMB"`
	UptimeSec  int64             `json:"uptimeSec"`
	Kernels    map[string]string `json:"kernels"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ensure runtime is referenced (used by sysstat on all platforms).
var _ = runtime.NumCPU
