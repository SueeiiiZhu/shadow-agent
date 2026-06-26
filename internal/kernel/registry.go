package kernel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Marshaler renders a NodeSpec into a kernel-specific config byte payload plus
// the file extension to use on disk.
type Marshaler func(spec *NodeSpec) (data []byte, ext string, err error)

// marshalers maps kernel name -> config renderer.
var marshalers = map[string]Marshaler{
	"xray":      marshalXray,
	"hysteria2": marshalHysteria2,
	"singbox":   marshalSingbox,
	"naive":     marshalNaive,
}

// Render returns the rendered config bytes and extension for a spec's kernel.
func Render(spec *NodeSpec) ([]byte, string, error) {
	m, ok := marshalers[spec.Kernel]
	if !ok {
		return nil, "", fmt.Errorf("unknown kernel %q", spec.Kernel)
	}
	return m(spec)
}

// Generate renders the config for spec and writes it to dataDir/<kernel>/
// config-<tag>.<ext>, returning the absolute config path.
func Generate(spec *NodeSpec, dataDir string) (string, error) {
	data, ext, err := Render(spec)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(dataDir, spec.Kernel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("config-%s.%s", spec.Tag, ext))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func marshalXray(spec *NodeSpec) ([]byte, string, error) {
	cfg, err := buildXrayConfig(spec)
	if err != nil {
		return nil, "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return data, "json", nil
}
