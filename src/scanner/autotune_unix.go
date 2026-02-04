//go:build !windows
// +build !windows

package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func detectDiskType() string {
	if runtime.GOOS == "darwin" {
		return "ssd"
	}
	if runtime.GOOS != "linux" {
		return "unknown"
	}
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return "unknown"
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rotPath := filepath.Join("/sys/block", entry.Name(), "queue/rotational")
		b, err := os.ReadFile(rotPath)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(b))
		if val == "1" {
			return "hdd"
		}
		if val == "0" {
			return "ssd"
		}
	}
	return "unknown"
}
