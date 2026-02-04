package scanner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/tracing"
	"safnari/utils"

	"github.com/h2non/filetype"
)

func ProcessFile(ctx context.Context, path string, cfg *config.Config, w *output.Writer, sensitivePatterns map[string]*regexp.Regexp) {
	ctx, endTask := tracing.StartTask(ctx, "process_file")
	tracing.Log(ctx, "file", path)
	defer endTask()

	select {
	case <-ctx.Done():
		return
	default:
	}
	if !utils.IsPathWithin(path, cfg.StartPaths) {
		logger.Warnf("Skipping file outside target paths: %s", path)
		return
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		logger.Warnf("Failed to stat file %s: %v", path, err)
		return
	}

	if fileInfo.IsDir() {
		return
	}

	if fileInfo.Size() > cfg.MaxFileSize {
		logger.Debugf("Skipping large file %s", path)
		return
	}

	w.IncrementScanned()

	endRegion := tracing.StartRegion(ctx, "collect_file_data")
	fileData, err := collectFileData(ctx, path, fileInfo, cfg, sensitivePatterns)
	endRegion()
	if err != nil {
		logger.Warnf("Failed to process file %s: %v", path, err)
		return
	}
	if shouldWriteFileData(cfg, fileData) {
		w.WriteData(fileData)
	}
}

func collectFileData(ctx context.Context, path string, fileInfo os.FileInfo, cfg *config.Config, sensitivePatterns map[string]*regexp.Regexp) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	data["path"] = path

	fc := newFileContext(path, fileInfo, cfg, sensitivePatterns)
	for _, module := range buildFileModules(cfg, sensitivePatterns) {
		if !module.Enabled(cfg) {
			continue
		}
		if err := module.Collect(ctx, fc, data); err != nil {
			if errors.Is(err, context.Canceled) {
				return data, err
			}
			logger.Debugf("Module %s failed for %s: %v", module.Name(), path, err)
		}
	}

	return data, nil
}

func shouldWriteFileData(cfg *config.Config, data map[string]interface{}) bool {
	if cfg.ScanFiles {
		return true
	}
	keys := []string{
		"sensitive_data",
		"search_hits",
		"fuzzy_hashes",
		"xattrs",
		"acl",
		"alternate_data_streams",
	}
	for _, key := range keys {
		if data[key] != nil {
			return true
		}
	}
	return false
}

func getFileAttributes(fileInfo os.FileInfo) []string {
	var attrs []string
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
	sample, err := readFileSample(path, 4096)
	if err != nil {
		return false
	}
	return looksLikeText(sample)
}

func looksLikeText(sample []byte) bool {
	if len(sample) == 0 {
		return false
	}
	if !utf8.Valid(sample) {
		return false
	}
	var control int
	for _, b := range sample {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			control++
		}
	}
	return control <= len(sample)/10
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

func scanForSensitiveData(content string, patterns map[string]*regexp.Regexp) map[string][]string {
	matches := make(map[string][]string)
	for dataType, pattern := range patterns {
		found := pattern.FindAllString(content, -1)
		if dataType == "credit_card" {
			filtered := []string{}
			for _, f := range found {
				if luhnValid(f) {
					filtered = append(filtered, f)
				}
			}
			found = filtered
		}
		if len(found) > 0 {
			matches[dataType] = found
		}
	}

	return matches
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
	hits := make(map[string]int)
	for _, term := range terms {
		if term == "" {
			continue
		}
		count := strings.Count(content, term)
		if count > 0 {
			hits[term] = count
		}
	}
	return hits
}

func readFileContent(path string, maxSize int64) ([]byte, error) {
	const maxContentScanBytes int64 = 10 * 1024 * 1024
	if maxSize <= 0 || maxSize > maxContentScanBytes {
		maxSize = maxContentScanBytes
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if maxSize > 0 {
		stat, err := file.Stat()
		if err == nil && stat.Size() > maxSize {
			return nil, nil
		}
	}
	var reader io.Reader = file
	if maxSize > 0 {
		reader = io.LimitReader(file, maxSize)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func readFileSample(path string, maxSize int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, maxSize)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// getFileOwnership function is implemented in platform-specific files:
// - file_ownership_windows.go
// - file_ownership_unix.go
