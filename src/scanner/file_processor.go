package scanner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/scanner/prefilter"
	"safnari/scanner/sensitive"
	"safnari/tracing"
	"safnari/utils"

	"github.com/h2non/filetype"
)

func ProcessFile(ctx context.Context, path string, cfg *config.Config, w *output.Writer, sensitivePatterns map[string]*regexp.Regexp) {
	processFile(ctx, path, nil, cfg, w, sensitivePatterns, nil, true)
}

func processFile(
	ctx context.Context,
	path string,
	fileInfo os.FileInfo,
	cfg *config.Config,
	w *output.Writer,
	sensitivePatterns map[string]*regexp.Regexp,
	modules []FileModule,
	enforcePathWithin bool,
) {
	ctx, endTask := tracing.StartTask(ctx, "process_file")
	tracing.Log(ctx, "file", path)
	defer endTask()

	select {
	case <-ctx.Done():
		return
	default:
	}
	if enforcePathWithin && !utils.IsPathWithin(path, cfg.StartPaths) {
		logger.Warnf("Skipping file outside target paths: %s", path)
		return
	}

	if fileInfo == nil {
		fi, err := os.Stat(path)
		if err != nil {
			logger.Warnf("Failed to stat file %s: %v", path, err)
			return
		}
		fileInfo = fi
	}

	if fileInfo.IsDir() {
		return
	}

	if cfg.MaxFileSize > 0 && fileInfo.Size() > cfg.MaxFileSize {
		logger.Debugf("Skipping large file %s", path)
		return
	}

	w.IncrementScanned()

	endRegion := tracing.StartRegion(ctx, "collect_file_data")
	fileData, err := collectFileData(ctx, path, fileInfo, cfg, sensitivePatterns, modules)
	endRegion()
	if err != nil {
		logger.Warnf("Failed to process file %s: %v", path, err)
		return
	}
	if shouldWriteFileData(cfg, fileData) {
		w.WriteData(fileData)
	}
}

func collectFileData(
	ctx context.Context,
	path string,
	fileInfo os.FileInfo,
	cfg *config.Config,
	sensitivePatterns map[string]*regexp.Regexp,
	modules []FileModule,
) (*FileRecord, error) {
	data := &FileRecord{Path: path}

	fc := FileContext{
		Path:              path,
		Info:              fileInfo,
		Cfg:               cfg,
		SensitivePatterns: sensitivePatterns,
	}
	if len(modules) == 0 {
		modules = buildFileModules(cfg, sensitivePatterns)
	}
	for _, module := range modules {
		if !module.Enabled(cfg) {
			continue
		}
		if err := module.Collect(ctx, &fc, data); err != nil {
			if errors.Is(err, context.Canceled) {
				return data, err
			}
			logger.Debugf("Module %s failed for %s: %v", module.Name(), path, err)
		}
	}

	return data, nil
}

func shouldWriteFileData(cfg *config.Config, data *FileRecord) bool {
	if cfg.ScanFiles {
		return true
	}
	return data != nil && data.HasSignalData()
}

func getFileAttributes(fileInfo os.FileInfo) []string {
	attrs := make([]string, 0, 3)
	mode := fileInfo.Mode()

	if mode&os.ModeSymlink != 0 {
		attrs = append(attrs, "symlink")
	}
	if isHidden(fileInfo) {
		attrs = append(attrs, "hidden")
	}
	if mode&0222 == 0 {
		attrs = append(attrs, "read-only")
	}
	return attrs
}

func isHidden(fileInfo os.FileInfo) bool {
	name := fileInfo.Name()
	if name == "." || name == ".." {
		return false
	}
	if name[0] == '.' {
		return true
	}
	return false
}

func getMimeType(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := make([]byte, 261)
	_, err = file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	kind, err := filetype.Match(buf)
	if err != nil {
		return "", err
	}
	if kind == filetype.Unknown || kind.MIME.Value == "" {
		return "unknown", nil
	}
	return kind.MIME.Value, nil
}

func shouldSearchContent(mimeType, path string) bool {
	if hasLikelyTextExtension(path) {
		return true
	}
	if strings.HasPrefix(mimeType, "text/") ||
		strings.Contains(mimeType, "json") ||
		strings.Contains(mimeType, "xml") ||
		strings.Contains(mimeType, "html") ||
		strings.Contains(mimeType, "javascript") {
		return true
	}
	if mimeType == "unknown" || mimeType == "application/octet-stream" {
		return isLikelyText(path)
	}
	return false
}

func isLikelyText(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	var sample [4096]byte
	n, err := file.Read(sample[:])
	if err != nil && err != io.EOF {
		return false
	}
	return looksLikeText(sample[:n])
}

var likelyTextExtensions = map[string]struct{}{
	".txt": {}, ".log": {}, ".json": {}, ".xml": {}, ".yaml": {}, ".yml": {}, ".csv": {},
	".md": {}, ".rst": {}, ".ini": {}, ".cfg": {}, ".conf": {}, ".toml": {}, ".env": {},
	".html": {}, ".htm": {}, ".css": {}, ".js": {}, ".mjs": {}, ".cjs": {}, ".ts": {},
	".tsx": {}, ".jsx": {}, ".go": {}, ".py": {}, ".rb": {}, ".php": {}, ".java": {},
	".kt": {}, ".swift": {}, ".sh": {}, ".bash": {}, ".zsh": {}, ".ps1": {},
}

func hasLikelyTextExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := likelyTextExtensions[ext]
	return ok
}

func looksLikeText(sample []byte) bool {
	return looksLikeTextFast(sample)
}

func luhnValid(number string) bool {
	num := strings.ReplaceAll(number, " ", "")
	num = strings.ReplaceAll(num, "-", "")
	if len(num) < 13 || len(num) > 16 {
		return false
	}
	var sum int
	alt := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func luhnValidBytes(number []byte) bool {
	if len(number) == 0 {
		return false
	}
	var digitCount int
	for _, ch := range number {
		switch ch {
		case ' ', '-':
			continue
		default:
			if ch < '0' || ch > '9' {
				return false
			}
			digitCount++
		}
	}
	if digitCount < 13 || digitCount > 16 {
		return false
	}

	var sum int
	alt := false
	for i := len(number) - 1; i >= 0; i-- {
		ch := number[i]
		if ch == ' ' || ch == '-' {
			continue
		}
		d := int(ch - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func scanForSensitiveData(content string, patterns map[string]*regexp.Regexp, maxPerType, maxTotal int) (map[string][]string, map[string]int) {
	return scanForSensitiveDataAdvanced([]byte(content), patterns, maxPerType, maxTotal, "hybrid", "full", 4096, nil)
}

func scanForSensitiveDataWithPrefilter(
	content string,
	patterns map[string]*regexp.Regexp,
	maxPerType, maxTotal int,
	mode string,
) (map[string][]string, map[string]int) {
	return scanForSensitiveDataAdvanced([]byte(content), patterns, maxPerType, maxTotal, "hybrid", "full", 4096, nil)
}

func scanForSensitiveDataBytes(
	content []byte,
	patterns map[string]*regexp.Regexp,
	maxPerType, maxTotal int,
) (map[string][]string, map[string]int) {
	return scanForSensitiveDataAdvanced(content, patterns, maxPerType, maxTotal, "hybrid", "full", 4096, nil)
}

func scanForSensitiveDataWithPrefilterNamesBytes(
	content []byte,
	patterns map[string]*regexp.Regexp,
	maxPerType, maxTotal int,
	mode string,
	patternNames []string,
) (map[string][]string, map[string]int) {
	_ = mode
	return scanForSensitiveDataAdvanced(content, patterns, maxPerType, maxTotal, "hybrid", "full", 4096, patternNames)
}

func scanForSensitiveDataAdvanced(
	content []byte,
	patterns map[string]*regexp.Regexp,
	maxPerType, maxTotal int,
	engine string,
	longtail string,
	windowBytes int,
	patternNames []string,
) (map[string][]string, map[string]int) {
	var matches map[string][]string
	var matchCounts map[string]int
	remaining := maxTotal
	limitTotal := maxTotal > 0
	if len(patternNames) == 0 {
		patternNames = make([]string, 0, len(patterns))
		for name := range patterns {
			patternNames = append(patternNames, name)
		}
		sort.Strings(patternNames)
	}
	engine = strings.ToLower(strings.TrimSpace(engine))
	longtail = strings.ToLower(strings.TrimSpace(longtail))
	if windowBytes <= 0 {
		windowBytes = 4096
	}

	deterministicMode := engine == "auto" || engine == "deterministic" || engine == "hybrid"
	criticalPatternNames := filterCriticalPatternNames(patternNames, patterns)
	if deterministicMode && len(criticalPatternNames) > 0 {
		perTypeLimit := maxPerType
		if perTypeLimit <= 0 {
			perTypeLimit = -1
		}
		deterministicTotalLimit := maxTotal
		if limitTotal {
			deterministicTotalLimit = remaining
		}
		detMatches, detCounts := sensitive.ScanDeterministicAll(content, criticalPatternNames, perTypeLimit, deterministicTotalLimit)
		if len(detMatches) > 0 {
			if matches == nil {
				matches = make(map[string][]string, len(detMatches))
				matchCounts = make(map[string]int, len(detCounts))
			}
			for kind, values := range detMatches {
				matches[kind] = append(matches[kind], values...)
			}
			for kind, count := range detCounts {
				matchCounts[kind] += count
				if limitTotal {
					remaining -= count
				}
			}
		}
	}

	if engine == "deterministic" || longtail == "off" {
		return matches, matchCounts
	}

	safeGate := prefilter.BuildSensitiveGateBytes("safe", content, patternNames)
	for _, dataType := range patternNames {
		if sensitive.IsCriticalPattern(dataType) {
			continue
		}
		pattern, ok := patterns[dataType]
		if !ok {
			continue
		}
		if limitTotal && remaining <= 0 {
			break
		}
		perTypeLimit := maxPerType
		if perTypeLimit <= 0 {
			perTypeLimit = -1
		}
		if limitTotal && (perTypeLimit < 0 || perTypeLimit > remaining) {
			perTypeLimit = remaining
		}
		if perTypeLimit == 0 {
			continue
		}
		if !safeGate.Allow(dataType) {
			continue
		}

		values := regexSensitiveMatches(content, pattern, perTypeLimit, longtail, windowBytes)
		if len(values) == 0 {
			continue
		}
		if matches == nil {
			matches = make(map[string][]string, 4)
			matchCounts = make(map[string]int, 4)
		}
		matches[dataType] = values
		matchCounts[dataType] = len(values)
		if limitTotal {
			remaining -= len(values)
		}
	}

	return matches, matchCounts
}

func filterCriticalPatternNames(patternNames []string, patterns map[string]*regexp.Regexp) []string {
	if len(patternNames) == 0 || len(patterns) == 0 {
		return nil
	}
	critical := make([]string, 0, len(patternNames))
	for _, name := range patternNames {
		if !sensitive.IsCriticalPattern(name) {
			continue
		}
		if _, ok := patterns[name]; !ok {
			continue
		}
		critical = append(critical, name)
	}
	return critical
}

func regexSensitiveMatches(content []byte, pattern *regexp.Regexp, limit int, longtail string, windowBytes int) []string {
	switch longtail {
	case "off":
		return nil
	case "sampled":
		return regexSensitiveMatchesSampled(content, pattern, limit, windowBytes)
	default:
		return regexSensitiveMatchesFull(content, pattern, limit)
	}
}

func regexSensitiveMatchesFull(content []byte, pattern *regexp.Regexp, limit int) []string {
	foundIndexes := pattern.FindAllIndex(content, limit)
	if len(foundIndexes) == 0 {
		return nil
	}
	values := make([]string, len(foundIndexes))
	for i, idx := range foundIndexes {
		values[i] = string(content[idx[0]:idx[1]])
	}
	return values
}

func regexSensitiveMatchesSampled(content []byte, pattern *regexp.Regexp, limit int, windowBytes int) []string {
	n := len(content)
	if n == 0 {
		return nil
	}
	if windowBytes <= 0 || n <= windowBytes*3 {
		return regexSensitiveMatchesFull(content, pattern, limit)
	}

	half := windowBytes / 2
	mid := n / 2
	spans := []byteSpan{
		{start: 0, end: minInt(windowBytes, n)},
		{start: maxInt(0, mid-half), end: minInt(n, mid+half)},
		{start: maxInt(0, n-windowBytes), end: n},
	}
	merged := mergeSpans(spans)
	seen := make(map[string]struct{})
	values := make([]string, 0, len(merged))
	for _, s := range merged {
		foundIndexes := pattern.FindAllIndex(content[s.start:s.end], limit)
		for _, idx := range foundIndexes {
			value := string(content[s.start+idx[0] : s.start+idx[1]])
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
			if limit > 0 && len(values) >= limit {
				return values
			}
		}
	}
	return values
}

type byteSpan struct {
	start int
	end   int
}

func mergeSpans(spans []byteSpan) []byteSpan {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	merged := make([]byteSpan, 0, len(spans))
	current := spans[0]
	for i := 1; i < len(spans); i++ {
		s := spans[i]
		if s.start <= current.end {
			if s.end > current.end {
				current.end = s.end
			}
			continue
		}
		merged = append(merged, current)
		current = s
	}
	merged = append(merged, current)
	return merged
}

func redactSensitiveData(matches map[string][]string, mode string) map[string][]string {
	if mode == "" {
		return matches
	}
	redacted := make(map[string][]string, len(matches))
	for kind, values := range matches {
		for _, value := range values {
			redacted[kind] = append(redacted[kind], redactValue(value, mode))
		}
	}
	return redacted
}

func redactValue(value, mode string) string {
	switch mode {
	case "hash":
		sum := sha256.Sum256([]byte(value))
		return fmt.Sprintf("%x", sum[:])
	case "mask":
		if len(value) <= 4 {
			return "****"
		}
		return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
	default:
		return value
	}
}

func scanForSearchTerms(content string, terms []string) map[string]int {
	counter := prefilter.BuildSearchCounter(terms)
	return counter.CountBytes([]byte(content))
}

func readFileContent(path string, maxSize int64) ([]byte, error) {
	return readFileContentStandard(path, maxSize)
}

// getFileOwnership function is implemented in platform-specific files:
// - file_ownership_windows.go
// - file_ownership_unix.go
