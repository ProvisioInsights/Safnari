package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"safnari/config"
	"safnari/output"
	"safnari/scanner/sensitive"
	"safnari/systeminfo"
)

type normalizedFileRecord struct {
	Path          string
	SearchHits    string
	SensitiveData string
}

type lineRecord struct {
	RecordType    string                 `json:"record_type"`
	SchemaVersion string                 `json:"schema_version"`
	Payload       map[string]interface{} `json:"payload"`
}

func TestV2OutputNDJSONDeterministicAcrossProfiles(t *testing.T) {
	corpusDir := filepath.Join("..", "testdata", "corpus", "basic")
	goldenSet := loadGoldenFileset(t, filepath.Join("..", "testdata", "golden", "fileset_basic.txt"))

	adaptive := runScanAndNormalize(t, corpusDir, func(cfg *config.Config) {
		cfg.PerfProfile = "adaptive"
		cfg.SensitiveEngine = "auto"
		cfg.SensitiveLongtail = "sampled"
		cfg.ContentReadMode = "auto"
	})
	ultra := runScanAndNormalize(t, corpusDir, func(cfg *config.Config) {
		cfg.PerfProfile = "ultra"
		cfg.SensitiveEngine = "deterministic"
		cfg.SensitiveLongtail = "off"
		cfg.ContentReadMode = "stream"
	})

	assertParityAndGolden(t, goldenSet, adaptive, ultra)
}

func runScanAndNormalize(t *testing.T, corpusDir string, mutate func(cfg *config.Config)) map[string]normalizedFileRecord {
	t.Helper()
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "scan.ndjson")
	cfg := &config.Config{
		StartPaths:           []string{corpusDir},
		ScanFiles:            true,
		ScanSensitive:        true,
		ScanProcesses:        false,
		CollectSystemInfo:    false,
		OutputFormat:         "json",
		OutputFileName:       outPath,
		ConcurrencyLevel:     1,
		NiceLevel:            "low",
		HashAlgorithms:       []string{"md5"},
		SearchTerms:          []string{"ALPHA"},
		MaxFileSize:          1 << 20,
		MaxOutputFileSize:    10 << 20,
		LogLevel:             "error",
		MaxIOPerSecond:       0,
		IncludeDataTypes:     []string{"email", "api_key", "aws_access_key", "ssn", "phone_number", "jwt_token"},
		CustomPatterns:       map[string]string{},
		SensitiveMaxPerType:  100,
		SensitiveMaxTotal:    1000,
		MetadataMaxBytes:     1 << 20,
		RedactSensitive:      "",
		CollectXattrs:        false,
		CollectACL:           false,
		CollectScheduled:     false,
		CollectUsers:         false,
		CollectGroups:        false,
		CollectAdmins:        false,
		ScanADS:              false,
		SkipCount:            true,
		AutoTune:             false,
		PerfProfile:          "adaptive",
		SensitiveEngine:      "auto",
		SensitiveLongtail:    "sampled",
		SensitiveWindowBytes: 4096,
		ContentReadMode:      "auto",
		StreamChunkSize:      256 * 1024,
		StreamOverlapBytes:   512,
		MmapMinSize:          1,
		JSONLayout:           "ndjson",
	}
	if mutate != nil {
		mutate(cfg)
	}

	writer, err := output.New(cfg, &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}, &output.Metrics{})
	if err != nil {
		t.Fatalf("output init: %v", err)
	}
	if err := ScanFiles(context.Background(), cfg, &output.Metrics{}, writer); err != nil {
		writer.Close()
		t.Fatalf("scan files: %v", err)
	}
	writer.Close()
	return loadNormalizedNDJSON(t, outPath)
}

func loadNormalizedNDJSON(t *testing.T, path string) map[string]normalizedFileRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open ndjson output: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	records := make(map[string]normalizedFileRecord)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec lineRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode ndjson output: %v", err)
		}
		if rec.RecordType != "file" {
			continue
		}
		pathValue, _ := rec.Payload["path"].(string)
		records[pathValue] = normalizedFileRecord{
			Path:          pathValue,
			SearchHits:    canonicalJSON(rec.Payload["search_hits"]),
			SensitiveData: canonicalJSON(filterCriticalSensitive(rec.Payload["sensitive_data"])),
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan ndjson output: %v", err)
	}
	return records
}

func loadGoldenFileset(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file set: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		files = append(files, line)
	}
	sort.Strings(files)
	return files
}

func assertParityAndGolden(
	t *testing.T,
	golden []string,
	base map[string]normalizedFileRecord,
	candidate map[string]normalizedFileRecord,
) {
	t.Helper()
	if len(base) != len(candidate) {
		t.Fatalf("expected same file count across profiles, base=%d candidate=%d", len(base), len(candidate))
	}

	var relFiles []string
	for pathValue := range base {
		normalized := filepath.ToSlash(filepath.Clean(pathValue))
		rel := normalized
		if idx := strings.Index(normalized, "testdata/corpus/basic"); idx >= 0 {
			rel = strings.TrimPrefix(normalized[idx+len("testdata/corpus/basic"):], "/")
		}
		relFiles = append(relFiles, rel)
	}
	sort.Strings(relFiles)
	if strings.Join(relFiles, ",") != strings.Join(golden, ",") {
		t.Fatalf("file set drifted from golden fixture.\nfiles=%v\ngolden=%v", relFiles, golden)
	}

	for pathValue, baseRecord := range base {
		candidateRecord, ok := candidate[pathValue]
		if !ok {
			t.Fatalf("candidate output missing file %s", pathValue)
		}
		if baseRecord.SearchHits != candidateRecord.SearchHits {
			t.Fatalf("search hits mismatch for %s: base=%s candidate=%s", pathValue, baseRecord.SearchHits, candidateRecord.SearchHits)
		}
		if baseRecord.SensitiveData != candidateRecord.SensitiveData {
			t.Fatalf("sensitive data mismatch for %s: base=%s candidate=%s", pathValue, baseRecord.SensitiveData, candidateRecord.SensitiveData)
		}
	}
}

func canonicalJSON(value interface{}) string {
	if value == nil {
		return ""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func filterCriticalSensitive(value interface{}) interface{} {
	sensitiveMap, ok := value.(map[string]interface{})
	if !ok {
		return value
	}
	filtered := make(map[string]interface{}, len(sensitiveMap))
	for key, val := range sensitiveMap {
		if sensitive.IsCriticalPattern(key) {
			filtered[key] = val
		}
	}
	return filtered
}
