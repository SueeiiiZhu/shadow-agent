// Package process supervises kernel subprocesses: it generates config files,
// (re)starts/stops the kernel binary via os/exec, and tracks per-tag state.
package process

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/SueeiiiZhu/shadow-agent/internal/kernel"
)

// ErrNotFound is returned when a tag is unknown.
var ErrNotFound = errors.New("node not found")

// node bundles the spec, generated config path, and running process for a tag.
type node struct {
	spec       kernel.NodeSpec
	configPath string
	cmd        *exec.Cmd
	state      kernel.NodeState
}

// Supervisor manages the lifecycle of all kernel processes on this agent.
type Supervisor struct {
	mu           sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop any existing process for this tag before re-applying.
	if existing, ok := s.nodes[spec.Tag]; ok {
		stopProcess(existing)
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
	s.nodes[spec.Tag] = n

	bin := s.binaryPath(spec.Kernel)
	if _, statErr := os.Stat(bin); statErr != nil {
		// Binary missing: config is generated but process is not running.
		n.state.Running = false
		n.state.Error = "binary not found"
		return n.state, nil
	}

	cmd := exec.Command(bin, kernelArgs(spec.Kernel, configPath)...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if startErr := cmd.Start(); startErr != nil {
		n.state.Running = false
		n.state.Error = startErr.Error()
		return n.state, nil
	}

	n.cmd = cmd
	n.state.Running = true
	n.state.PID = cmd.Process.Pid
	n.state.Error = ""

	// Reap the process when it exits so we don't leave zombies, and update state.
	go func(nn *node, c *exec.Cmd) {
		_ = c.Wait()
		s.mu.Lock()
		if s.nodes[nn.spec.Tag] == nn {
			nn.state.Running = false
			nn.cmd = nil
		}
		s.mu.Unlock()
	}(n, cmd)

	return n.state, nil
}

// Remove stops and deletes the node identified by tag.
func (s *Supervisor) Remove(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[tag]
	if !ok {
		return ErrNotFound
	}
	stopProcess(n)
	delete(s.nodes, tag)
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

// Shutdown stops every supervised process.
func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		stopProcess(n)
	}
}

// stopProcess terminates a node's process if running. Caller holds the lock.
func stopProcess(n *node) {
	if n.cmd != nil && n.cmd.Process != nil {
		_ = n.cmd.Process.Kill()
		n.cmd = nil
	}
	n.state.Running = false
}
