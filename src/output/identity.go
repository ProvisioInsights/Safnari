package output

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"safnari/config"
	"safnari/internal/securefile"
)

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func loadInstallationID(cfg *config.Config) (string, error) {
	dir := cfg.SpoolDir
	if dir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(cache, "safnari", "spool")
	}
	if err := ensurePrivateSpoolDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "installation-id")
	data, err := securefile.ReadNoSymlinkMax(path, 64)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) != 32 {
			return "", errors.New("invalid installation ID")
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadInstallationID(cfg)
	}
	if err != nil {
		return "", err
	}
	_, err = file.WriteString(id)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return "", err
	}
	return id, nil
}

func effectivePolicyDigest(cfg *config.Config) string {
	policy := struct {
		StartPaths          []string
		ScanFiles           bool
		ScanSensitive       bool
		ScanProcesses       bool
		CollectSystemInfo   bool
		HashAlgorithms      []string
		SearchTerms         []string
		IncludePatterns     []string
		ExcludePatterns     []string
		IncludeDataTypes    []string
		ExcludeDataTypes    []string
		CustomPatterns      map[string]string
		MaxFileSize         int64
		ContentScanMaxBytes int64
		SensitiveEngine     string
		SensitiveLongtail   string
		SensitiveMatchMode  string
		RedactSensitive     string
	}{
		StartPaths: cfg.StartPaths, ScanFiles: cfg.ScanFiles, ScanSensitive: cfg.ScanSensitive,
		ScanProcesses: cfg.ScanProcesses, CollectSystemInfo: cfg.CollectSystemInfo,
		HashAlgorithms: cfg.HashAlgorithms, SearchTerms: cfg.SearchTerms,
		IncludePatterns: cfg.IncludePatterns, ExcludePatterns: cfg.ExcludePatterns,
		IncludeDataTypes: cfg.IncludeDataTypes, ExcludeDataTypes: cfg.ExcludeDataTypes,
		CustomPatterns: cfg.CustomPatterns, MaxFileSize: cfg.MaxFileSize,
		ContentScanMaxBytes: cfg.ContentScanMaxBytes, SensitiveEngine: cfg.SensitiveEngine,
		SensitiveLongtail: cfg.SensitiveLongtail, SensitiveMatchMode: cfg.SensitiveMatchMode,
		RedactSensitive: cfg.RedactSensitive,
	}
	data, _ := json.Marshal(policy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
