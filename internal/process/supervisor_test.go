package process

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SueeiiiZhu/shadow-agent/internal/kernel"
)

// TestApplyMissingBinaryGeneratesConfig verifies that when the kernel binary is
// absent the supervisor does not crash, reports running=false with a clear
// error, and still writes the config file for offline validation.
func TestApplyMissingBinaryGeneratesConfig(t *testing.T) {
	dataDir := t.TempDir()
	binDir := t.TempDir() // empty: no kernel binaries present

	sup := New(dataDir, binDir)
	spec := kernel.NodeSpec{
		Tag: "node-1", Kernel: "xray", Protocol: "vless", Port: 443,
		Users: []kernel.UserSpec{{ID: "uuid"}},
	}
	state, err := sup.Apply(spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if state.Running {
		t.Fatalf("expected running=false with missing binary")
	}
	if state.Error != "binary not found" {
		t.Fatalf("error = %q, want 'binary not found'", state.Error)
	}
	if state.ConfigPath == "" {
		t.Fatalf("config path empty")
	}
	if _, statErr := os.Stat(state.ConfigPath); statErr != nil {
		t.Fatalf("config file not written: %v", statErr)
	}
	if filepath.Base(state.ConfigPath) != "config-node-1.json" {
		t.Fatalf("unexpected config name: %s", state.ConfigPath)
	}
}

// TestListRemoveState exercises the lifecycle accessors.
func TestListRemoveState(t *testing.T) {
	sup := New(t.TempDir(), t.TempDir())
	spec := kernel.NodeSpec{Tag: "a", Kernel: "xray", Protocol: "vless", Port: 443}
	if _, err := sup.Apply(spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := sup.List(); len(got) != 1 {
		t.Fatalf("List len = %d, want 1", len(got))
	}
	if _, err := sup.State("a"); err != nil {
		t.Fatalf("State: %v", err)
	}
	if err := sup.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := sup.Remove("a"); err != ErrNotFound {
		t.Fatalf("Remove missing = %v, want ErrNotFound", err)
	}
	if _, err := sup.State("a"); err != ErrNotFound {
		t.Fatalf("State missing = %v, want ErrNotFound", err)
	}
}
