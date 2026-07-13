package process

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// statsQueryTimeout bounds a single `xray api statsquery` invocation.
const statsQueryTimeout = 4 * time.Second

// XrayStats queries the local Xray stats API for the node identified by tag and
// returns a map of stat name -> cumulative byte value. The query runs the xray
// binary's `api statsquery` subcommand against the node's own gRPC API port, so
// no third-party gRPC dependency is needed.
//
// ok is false (and the map nil) for non-xray kernels, a missing xray binary, an
// unreachable API, or any parse error — so callers report no data rather than a
// misleading zero.
func (s *Supervisor) XrayStats(tag string) (map[string]int64, bool) {
	s.mu.Lock()
	n, present := s.nodes[tag]
	var apiPort int
	var kern string
	if present {
		kern = n.spec.Kernel
		apiPort = n.spec.EffectiveAPIPort()
	}
	s.mu.Unlock()

	if !present || kern != "xray" {
		return nil, false
	}
	bin := s.binaryPath("xray")
	if _, err := os.Stat(bin); err != nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), statsQueryTimeout)
	defer cancel()
	server := "127.0.0.1:" + strconv.Itoa(apiPort)
	cmd := exec.CommandContext(ctx, bin, "api", "statsquery", "--server="+server)
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}

	var resp struct {
		Stat []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, false
	}
	m := make(map[string]int64, len(resp.Stat))
	for _, st := range resp.Stat {
		v, _ := strconv.ParseInt(st.Value, 10, 64)
		m[st.Name] = v
	}
	return m, true
}
