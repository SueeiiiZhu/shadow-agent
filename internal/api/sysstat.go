package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type memInfo struct {
	usedMB  int64
	totalMB int64
}

// readMem returns memory usage. On Linux it parses /proc/meminfo; elsewhere it
// falls back to the Go runtime's view of allocated heap (best-effort).
func readMem() memInfo {
	if runtime.GOOS == "linux" {
		if mi, ok := readMemLinux(); ok {
			return mi
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	used := int64(ms.Sys / 1024 / 1024)
	return memInfo{usedMB: used, totalMB: used}
}

func readMemLinux() (memInfo, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memInfo{}, false
	}
	var totalKB, availKB int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = val
		case "MemAvailable:":
			availKB = val
		}
	}
	if totalKB == 0 {
		return memInfo{}, false
	}
	used := (totalKB - availKB) / 1024
	return memInfo{usedMB: used, totalMB: totalKB / 1024}, true
}

// readCPUPercent returns a coarse CPU load estimate. On Linux it derives a
// percentage from the 1-minute load average relative to the CPU count;
// elsewhere it returns 0 (best-effort, stdlib only).
func readCPUPercent() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	n := float64(runtime.NumCPU())
	if n <= 0 {
		n = 1
	}
	pct := load1 / n * 100
	if pct > 100 {
		pct = 100
	}
	return pct
}

// detectKernels probes each kernel binary in KernelBinDir for its version. When
// a binary is missing the value is empty.
func (s *Server) detectKernels() map[string]string {
	out := map[string]string{"xray": "", "hysteria2": "", "singbox": "", "naive": ""}
	for name := range out {
		out[name] = kernelVersion(filepath.Join(s.cfg.KernelBinDir, name), name)
	}
	return out
}

// kernelVersion runs the kernel binary's version subcommand and returns the
// first non-empty line; empty if the binary is absent or fails.
func kernelVersion(bin, name string) string {
	if _, err := os.Stat(bin); err != nil {
		return ""
	}
	var args []string
	switch name {
	case "xray":
		args = []string{"version"}
	case "hysteria2", "singbox", "naive":
		args = []string{"version"}
	default:
		args = []string{"--version"}
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}
