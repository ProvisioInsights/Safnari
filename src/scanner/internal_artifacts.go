package scanner

import (
	"path/filepath"
	"strings"
	"unicode"

	"safnari/config"
)

type internalArtifactFilter struct {
	exactPaths map[string]struct{}
	outputDir  string
	outputBase string
	outputExt  string
	diagDir    string
	cacheDir   string
}

func newInternalArtifactFilter(cfg *config.Config) *internalArtifactFilter {
	filter := &internalArtifactFilter{
		exactPaths: make(map[string]struct{}, 4),
	}
	if cfg == nil {
		return filter
	}

	if outputPath := normalizeArtifactPath(cfg.OutputFileName); outputPath != "" {
		ext := filepath.Ext(outputPath)
		if ext == "" {
			ext = ".ndjson"
			outputPath += ext
		}
		filter.exactPaths[outputPath] = struct{}{}
		filter.outputDir = filepath.Dir(outputPath)
		filter.outputExt = ext
		filter.outputBase = strings.TrimSuffix(filepath.Base(outputPath), ext)
	}

	for _, candidate := range []string{
		cfg.LastScanFile,
		cfg.TraceFlightFile,
		"trace.out",
	} {
		if normalized := normalizeArtifactPath(candidate); normalized != "" {
			filter.exactPaths[normalized] = struct{}{}
		}
	}

	filter.diagDir = normalizeArtifactPath(cfg.DiagDir)
	filter.cacheDir = normalizeArtifactPath(cfg.DeltaCacheDir)
	return filter
}

func normalizeArtifactPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return filepath.Clean(absPath)
}

func (f *internalArtifactFilter) ShouldSkip(path string) bool {
	if f == nil {
		return false
	}
	absPath := normalizeArtifactPath(path)
	if absPath == "" {
		return false
	}
	if _, ok := f.exactPaths[absPath]; ok {
		return true
	}
	if f.cacheDir != "" && (absPath == f.cacheDir || strings.HasPrefix(absPath, f.cacheDir+string(filepath.Separator))) {
		return true
	}
	if f.matchesRotatedOutput(absPath) {
		return true
	}
	return f.matchesDiagnosticArtifact(absPath)
}

func (f *internalArtifactFilter) matchesRotatedOutput(path string) bool {
	if f.outputDir == "" || f.outputBase == "" || f.outputExt == "" {
		return false
	}
	if filepath.Dir(path) != f.outputDir {
		return false
	}
	name := filepath.Base(path)
	if !strings.HasPrefix(name, f.outputBase+".") || !strings.HasSuffix(name, f.outputExt) {
		return false
	}
	index := strings.TrimSuffix(strings.TrimPrefix(name, f.outputBase+"."), f.outputExt)
	if index == "" {
		return false
	}
	for _, r := range index {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func (f *internalArtifactFilter) matchesDiagnosticArtifact(path string) bool {
	if f.diagDir == "" || filepath.Dir(path) != f.diagDir {
		return false
	}
	name := filepath.Base(path)
	switch {
	case strings.HasPrefix(name, "safnari-slow-scan-") && strings.HasSuffix(name, ".json"):
		return true
	case strings.HasPrefix(name, "safnari-flight-") && strings.HasSuffix(name, ".out"):
		return true
	case strings.HasPrefix(name, "safnari-") && strings.Contains(name, "-profile-") && strings.HasSuffix(name, ".pprof"):
		return true
	default:
		return false
	}
}
