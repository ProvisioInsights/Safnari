package scanner

import "safnari/config"

func sensitiveMatchMode(cfg *config.Config) string {
	if cfg == nil || cfg.SensitiveMatchMode == "" {
		return "all"
	}
	return cfg.SensitiveMatchMode
}

func effectiveSensitivePerTypeLimit(cfg *config.Config) int {
	if sensitiveMatchMode(cfg) == "first" {
		return 1
	}
	if cfg == nil {
		return 0
	}
	return cfg.SensitiveMaxPerType
}

func remainingSensitiveTotalLimit(cfg *config.Config, totalCount, activePatterns int) int {
	if cfg != nil && cfg.SensitiveMaxTotal > 0 {
		remaining := cfg.SensitiveMaxTotal - totalCount
		if remaining < 0 {
			return 0
		}
		return remaining
	}
	if sensitiveMatchMode(cfg) == "first" {
		if activePatterns <= 0 {
			return 0
		}
		return activePatterns
	}
	return 0
}

func remainingSensitivePerTypeLimit(cfg *config.Config, pattern string, counts map[string]int) int {
	limit := effectiveSensitivePerTypeLimit(cfg)
	if limit <= 0 {
		return -1
	}
	remaining := limit - counts[pattern]
	if remaining < 0 {
		return 0
	}
	return remaining
}

func activeSensitivePatternNames(cfg *config.Config, patternNames []string, counts map[string]int) []string {
	limit := effectiveSensitivePerTypeLimit(cfg)
	if len(patternNames) == 0 {
		return nil
	}
	if limit <= 0 {
		return append([]string(nil), patternNames...)
	}
	active := make([]string, 0, len(patternNames))
	for _, pattern := range patternNames {
		if counts[pattern] < limit {
			active = append(active, pattern)
		}
	}
	return active
}

func sensitiveCollectionSaturated(cfg *config.Config, patternNames []string, counts map[string]int, totalCount int) bool {
	if cfg != nil && cfg.SensitiveMaxTotal > 0 && totalCount >= cfg.SensitiveMaxTotal {
		return true
	}
	limit := effectiveSensitivePerTypeLimit(cfg)
	if limit <= 0 || len(patternNames) == 0 {
		return false
	}
	for _, pattern := range patternNames {
		if counts[pattern] < limit {
			return false
		}
	}
	return true
}
