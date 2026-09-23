package scanner

import (
	"strings"

	"safnari/config"
)

func applyPerformanceProfile(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if cfg.PerfProfile == "" {
		cfg.PerfProfile = "adaptive"
	}
	// Performance modes may tune scheduling but cannot alter detector coverage.
	if strings.TrimSpace(cfg.SensitiveEngine) == "" || cfg.SensitiveEngine == "auto" {
		cfg.SensitiveEngine = "hybrid"
	}
	if cfg.SensitiveLongtail == "" {
		cfg.SensitiveLongtail = "sampled"
	}
}
