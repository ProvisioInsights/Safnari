package scanner

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"safnari/config"
	"safnari/hasher"
	"safnari/logger"
	"safnari/metadata"
	"safnari/output"

	"github.com/djherbis/times"
	"github.com/h2non/filetype"
)

func ProcessFile(ctx context.Context, path string, cfg *config.Config, w *output.Writer, sensitivePatterns map[string]*regexp.Regexp) {
	select {
	case <-ctx.Done():
		return
	default:
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

	fileData, err := collectFileData(path, fileInfo, cfg, sensitivePatterns)
	if err != nil {
		logger.Warnf("Failed to process file %s: %v", path, err)
		return
	}
	w.WriteData(fileData)
}

func collectFileData(path string, fileInfo os.FileInfo, cfg *config.Config, sensitivePatterns map[string]*regexp.Regexp) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	data["path"] = path
	data["name"] = fileInfo.Name()
	data["size"] = fileInfo.Size()
	data["mod_time"] = fileInfo.ModTime().Format(time.RFC3339)

	// Get access and creation times using times package
	t, err := times.Stat(path)
	if err == nil {
		if t.HasBirthTime() {
			data["creation_time"] = t.BirthTime().Format(time.RFC3339)
		} else {
			data["creation_time"] = ""
		}
		data["access_time"] = t.AccessTime().Format(time.RFC3339)
		data["change_time"] = t.ChangeTime().Format(time.RFC3339)
	} else {
		data["creation_time"] = ""
		data["access_time"] = ""
		data["change_time"] = ""
	}

	// Get file attributes
	data["attributes"] = getFileAttributes(fileInfo)

	// Get file permissions
	data["permissions"] = fileInfo.Mode().Perm().String()

	// Get file owner
	owner, err := getFileOwnership(path)
	if err == nil {
		data["owner"] = owner
	} else {
		data["owner"] = ""
	}

	// Determine MIME type
	mimeType, err := getMimeType(path)
	if err != nil {
		mimeType = "unknown"
	}
	data["mime_type"] = mimeType

	// Compute hashes
	hashes := hasher.ComputeHashes(path, cfg.HashAlgorithms)
	data["hashes"] = hashes

	// Extract metadata if applicable
	meta := metadata.ExtractMetadata(path, mimeType)
	data["metadata"] = meta

	// Sensitive Data Scanning
	if shouldSearchContent(mimeType) && len(sensitivePatterns) > 0 {
		matches := scanForSensitiveData(path, sensitivePatterns)
		if len(matches) > 0 {
			data["sensitive_data"] = matches
		}
	}

	return data, nil
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
	return kind.MIME.Value, nil
}

func shouldSearchContent(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") ||
		strings.Contains(mimeType, "json") ||
		strings.Contains(mimeType, "xml") ||
		strings.Contains(mimeType, "html") ||
		strings.Contains(mimeType, "javascript")
}

func scanForSensitiveData(path string, patterns map[string]*regexp.Regexp) map[string][]string {
	matches := make(map[string][]string)

	file, err := os.Open(path)
	if err != nil {
		logger.Warnf("Failed to open file for scanning %s: %v", path, err)
		return matches
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return matches
	}

	// Limit scanning to files below a certain size (e.g., 10 MB)
	const maxSize = 10 * 1024 * 1024
	if stat.Size() > maxSize {
		logger.Debugf("Skipping content scanning for large file %s", path)
		return matches
	}

	content, err := io.ReadAll(file)
	if err != nil {
		logger.Warnf("Failed to read file %s: %v", path, err)
		return matches
	}

	textContent := string(content)
	for dataType, pattern := range patterns {
		found := pattern.FindAllString(textContent, -1)
		if len(found) > 0 {
			matches[dataType] = found
		}
	}

	return matches
}

// getFileOwnership function is implemented in platform-specific files:
// - file_ownership_windows.go
// - file_ownership_unix.go
