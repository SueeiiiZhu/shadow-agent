package kernel

import (
	"os"
	"strings"
	"testing"
)

func TestValidTag(t *testing.T) {
	ok := []string{"n1", "node-1", "us-west.1_edge", "A", strings.Repeat("a", 64)}
	for _, tag := range ok {
		if !ValidTag(tag) {
			t.Errorf("ValidTag(%q) = false, want true", tag)
		}
	}
	bad := []string{"", "../evil", "a/b", `a\b`, "bad tag", "tag$", strings.Repeat("a", 65)}
	for _, tag := range bad {
		if ValidTag(tag) {
			t.Errorf("ValidTag(%q) = true, want false", tag)
		}
	}
}

// TestGenerateRejectsBadTag ensures a path-traversal tag never reaches WriteFile,
// even though the panel also validates tags upstream (defense in depth).
func TestGenerateRejectsBadTag(t *testing.T) {
	dir := t.TempDir()
	spec := &NodeSpec{Tag: "../escape", Kernel: "xray", Protocol: "vless", Port: 443}
	path, err := Generate(spec, dir)
	if err == nil {
		t.Fatalf("Generate accepted traversal tag, wrote %q", path)
	}
	if !strings.Contains(err.Error(), "invalid tag") {
		t.Errorf("unexpected error: %v", err)
	}
	// Nothing should have been written outside (or inside) the data dir.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Generate created %d entries for a rejected tag", len(entries))
	}
}
