package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"safnari/config"
)

type profileSample struct {
	files      int
	totalBytes int64
	textFiles  int
}

func applyPerformanceProfile(cfg *config.Config) {
	if cfg == nil {
		return
	}

	profile := strings.ToLower(strings.TrimSpace(cfg.PerfProfile))
	if profile == "" {
		profile = "adaptive"
		cfg.PerfProfile = profile
	}

	switch profile {
	case "ultra":
		if cfg.SensitiveEngine == "" || cfg.SensitiveEngine == "auto" {
			cfg.SensitiveEngine = "deterministic"
		}
		if cfg.SensitiveLongtail == "" || cfg.SensitiveLongtail == "sampled" {
			cfg.SensitiveLongtail = "off"
		}
		if cfg.ContentReadMode == "" || cfg.ContentReadMode == "auto" {
			cfg.ContentReadMode = "stream"
		}
	case "adaptive":
		sample := sampleStartPaths(cfg.StartPaths, 128)
		if cfg.ContentReadMode == "" || cfg.ContentReadMode == "auto" {
			if sample.files > 0 && sample.totalBytes/int64(sample.files) >= 1*1024*1024 {
				cfg.ContentReadMode = "mmap"
			} else {
				cfg.ContentReadMode = "stream"
			}
		}
		if cfg.SensitiveEngine == "" || cfg.SensitiveEngine == "auto" {
			cfg.SensitiveEngine = "hybrid"
		}
		if cfg.SensitiveLongtail == "" {
			cfg.SensitiveLongtail = "sampled"
		}
	}
}

func sampleStartPaths(startPaths []string, maxFiles int) profileSample {
	var sample profileSample
	if maxFiles <= 0 {
		maxFiles = 1
	}
	for _, root := range startPaths {
		if sample.files >= maxFiles {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			sample.files++
			sample.totalBytes += info.Size()
			if hasLikelyTextExtension(path) {
				sample.textFiles++
			}
			if sample.files >= maxFiles {
				return filepath.SkipDir
			}
			return nil
		})
	}
	return sample
}
