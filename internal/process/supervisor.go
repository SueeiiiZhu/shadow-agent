// Package process supervises kernel subprocesses: it generates config files,
// (re)starts/stops the kernel binary via os/exec, and tracks per-tag state.
package process

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SueeiiiZhu/shadow-agent/internal/kernel"
)

// ErrNotFound is returned when a tag is unknown.
var ErrNotFound = errors.New("node not found")

const (
	// stderrCapBytes bounds how much kernel stderr we retain per node for
	// diagnostics, keeping the most recent output.
	stderrCapBytes = 8 << 10
	// stopWaitTimeout bounds how long we wait for a killed process to exit (and
	// release its listening port) before re-applying.
	stopWaitTimeout = 5 * time.Second
)

// node bundles the spec, generated config path, and running process for a tag.
type node struct {
	spec       kernel.NodeSpec
	configPath string
	cmd        *exec.Cmd
	stderr     *boundedBuffer
	done       chan struct{} // closed by the reaper after the process exits
	stopping   bool          // set before a deliberate kill so the reaper won't record an error
	state      kernel.NodeState
}

// Supervisor manages the lifecycle of all kernel processes on this agent.
type Supervisor struct {
	life         sync.Mutex // serializes lifecycle mutations (Apply/Remove/Shutdown)
	mu           sync.Mutex // guards the nodes map and each node.state
	dataDir      string
	kernelBinDir string
	nodes        map[string]*node
}

// New creates a Supervisor writing configs under dataDir and resolving kernel
// binaries from kernelBinDir.
func New(dataDir, kernelBinDir string) *Supervisor {
	return &Supervisor{
		dataDir:      dataDir,
		kernelBinDir: kernelBinDir,
		nodes:        make(map[string]*node),
	}
}

// binaryPath returns the expected path of a kernel's binary.
func (s *Supervisor) binaryPath(k string) string {
	return filepath.Join(s.kernelBinDir, k)
}

// kernelArgs returns the exec args for launching a kernel with a config file.
func kernelArgs(k, configPath string) []string {
	switch k {
	case "xray":
		return []string{"run", "-c", configPath}
	case "hysteria2":
		return []string{"server", "-c", configPath}
	case "singbox":
		return []string{"run", "-c", configPath}
	case "naive":
		// Caddy with the forward_proxy plugin.
		return []string{"run", "--config", configPath, "--adapter", "caddyfile"}
	default:
		return []string{"-c", configPath}
	}
}

// Apply generates the config for spec and (re)starts the kernel process. The
// config file is always written, even when the kernel binary is missing, so
// generation can be validated offline.
func (s *Supervisor) Apply(spec kernel.NodeSpec) (kernel.NodeState, error) {
	s.life.Lock()
	defer s.life.Unlock()

	// Stop any existing process for this tag and wait for its port to free
	// before starting the replacement (avoids a bind race on the same port).
	s.mu.Lock()
	existing := s.nodes[spec.Tag]
	s.mu.Unlock()
	if existing != nil {
		s.killAndWait(existing)
	}

	configPath, err := kernel.Generate(&spec, s.dataDir)
	if err != nil {
		return kernel.NodeState{}, err
	}

	n := &node{
		spec:       spec,
		configPath: configPath,
		state: kernel.NodeState{
			Tag:        spec.Tag,
			Kernel:     spec.Kernel,
			Port:       spec.Port,
			ConfigPath: configPath,
		},
	}

	bin := s.binaryPath(spec.Kernel)
	if _, statErr := os.Stat(bin); statErr != nil {
		// Binary missing: config is generated but process is not running.
		n.state.Running = false
		n.state.Error = "binary not found"
		return s.register(n), nil
	}

	stderr := &boundedBuffer{max: stderrCapBytes}
	cmd := exec.Command(bin, kernelArgs(spec.Kernel, configPath)...)
	cmd.Stdout = nil
	cmd.Stderr = stderr
	if startErr := cmd.Start(); startErr != nil {
		n.state.Running = false
		n.state.Error = startErr.Error()
		return s.register(n), nil
	}

	n.cmd = cmd
	n.stderr = stderr
	n.done = make(chan struct{})
	n.state.Running = true
	n.state.PID = cmd.Process.Pid
	n.state.Error = ""

	ret := s.register(n)

	// Reap the process when it exits so we don't leave zombies, and record the
	// exit reason (with a stderr tail) when it dies unexpectedly.
	go func(nn *node) {
		waitErr := nn.cmd.Wait()
		s.mu.Lock()
		if s.nodes[nn.spec.Tag] == nn {
			nn.state.Running = false
			nn.cmd = nil
			if !nn.stopping && waitErr != nil {
				nn.state.Error = describeExit(waitErr, nn.stderr)
			}
		}
		s.mu.Unlock()
		close(nn.done)
	}(n)

	return ret, nil
}

// register inserts n into the nodes map and returns a snapshot of its state.
func (s *Supervisor) register(n *node) kernel.NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[n.spec.Tag] = n
	return n.state
}

// killAndWait terminates n's process (if any) and waits for the reaper to
// observe the exit, so the port is released before the caller proceeds. The
// caller must hold s.life but must NOT hold s.mu.
func (s *Supervisor) killAndWait(n *node) {
	s.mu.Lock()
	n.stopping = true
	if n.cmd != nil && n.cmd.Process != nil {
		_ = n.cmd.Process.Kill()
	}
	done := n.done
	n.state.Running = false
	s.mu.Unlock()

	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(stopWaitTimeout):
	}
}

// Remove stops and deletes the node identified by tag.
func (s *Supervisor) Remove(tag string) error {
	s.life.Lock()
	defer s.life.Unlock()

	s.mu.Lock()
	n, ok := s.nodes[tag]
	s.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	s.killAndWait(n)
	s.mu.Lock()
	delete(s.nodes, tag)
	s.mu.Unlock()
	return nil
}

// State returns the current state of a single node.
func (s *Supervisor) State(tag string) (kernel.NodeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[tag]
	if !ok {
		return kernel.NodeState{}, ErrNotFound
	}
	return n.state, nil
}

// List returns the state of all known nodes.
func (s *Supervisor) List() []kernel.NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]kernel.NodeState, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n.state)
	}
	return out
}

// Specs returns a snapshot of all node specs (used by traffic collection).
func (s *Supervisor) Specs() []kernel.NodeSpec {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]kernel.NodeSpec, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n.spec)
	}
	return out
}

// Shutdown stops every supervised process, waiting for each to exit.
func (s *Supervisor) Shutdown() {
	s.life.Lock()
	defer s.life.Unlock()

	s.mu.Lock()
	nodes := make([]*node, 0, len(s.nodes))
	for _, n := range s.nodes {
		nodes = append(nodes, n)
	}
	s.mu.Unlock()

	for _, n := range nodes {
		s.killAndWait(n)
	}
}

// describeExit renders a diagnostic message from a process exit error plus the
// last line of its stderr, if any.
func describeExit(waitErr error, stderr *boundedBuffer) string {
	msg := waitErr.Error()
	if stderr != nil {
		if tail := strings.TrimSpace(stderr.String()); tail != "" {
			msg += ": " + lastLine(tail)
		}
	}
	return msg
}

// lastLine returns the final non-empty line of s.
func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// boundedBuffer is a concurrency-safe io.Writer that retains only the last max
// bytes written, used to capture a rolling tail of kernel stderr.
type boundedBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
