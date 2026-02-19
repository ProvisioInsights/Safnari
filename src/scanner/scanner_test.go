package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/systeminfo"
	"safnari/utils"
)

func init() {
	logger.Init("error")
}

func TestIsHidden(t *testing.T) {
	hidden, err := os.CreateTemp("", ".hidden")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(hidden.Name())
	fi, _ := os.Stat(hidden.Name())
	if !isHidden(fi) {
		t.Fatal("expected hidden")
	}
	tmp, _ := os.CreateTemp("", "visible")
	defer os.Remove(tmp.Name())
	fi2, _ := os.Stat(tmp.Name())
	if isHidden(fi2) {
		t.Fatal("expected visible")
	}
}

func TestGetMimeType(t *testing.T) {
	tmp, _ := os.CreateTemp("", "mime*.txt")
	tmp.WriteString("hello")
	tmp.Close()
	defer os.Remove(tmp.Name())
	_, err := getMimeType(tmp.Name())
	if err != nil {
		t.Fatalf("mime: %v", err)
	}
}

func TestShouldSearchContent(t *testing.T) {
	if !shouldSearchContent("text/plain", "") {
		t.Fatal("text should search")
	}
	if shouldSearchContent("image/png", "") {
		t.Fatal("image should not search")
	}
}

func TestScanForSensitiveData(t *testing.T) {
	tmp, _ := os.CreateTemp("", "data*.txt")
	content := "contact me at test@example.com"
	tmp.WriteString(content)
	tmp.Close()
	defer os.Remove(tmp.Name())
	patterns := GetPatterns([]string{"email"}, nil, nil)
	fileContent, _ := os.ReadFile(tmp.Name())
	matches, _ := scanForSensitiveData(string(fileContent), patterns, 100, 1000)
	if len(matches["email"]) == 0 {
		t.Fatal("expected email match")
	}
}

func TestScanForSensitiveDataCreditCard(t *testing.T) {
	tmp, _ := os.CreateTemp("", "cc*.txt")
	content := "valid 4111-1111-1111-1111 invalid 1234-5678-9012-3456"
	tmp.WriteString(content)
	tmp.Close()
	defer os.Remove(tmp.Name())
	patterns := GetPatterns([]string{"credit_card"}, nil, nil)
	contentBytes, _ := os.ReadFile(tmp.Name())
	matches, _ := scanForSensitiveData(string(contentBytes), patterns, 100, 1000)
	if len(matches["credit_card"]) != 1 || matches["credit_card"][0] != "4111-1111-1111-1111" {
		t.Fatalf("expected valid credit card match, got %v", matches["credit_card"])
	}
}

func TestCustomSensitivePattern(t *testing.T) {
	tmp, _ := os.CreateTemp("", "custom*.txt")
	tmp.WriteString("token abc123")
	tmp.Close()
	defer os.Remove(tmp.Name())
	custom := map[string]string{"token": "abc\\d+"}
	patterns := GetPatterns([]string{"token"}, custom, nil)
	contentBytes, _ := os.ReadFile(tmp.Name())
	matches, _ := scanForSensitiveData(string(contentBytes), patterns, 100, 1000)
	if len(matches["token"]) == 0 {
		t.Fatal("expected custom pattern match")
	}
}

func TestInternationalSensitivePatterns(t *testing.T) {
	tmp, _ := os.CreateTemp("", "intl*.txt")
	content := "IBAN GB29NWBK60161331926819 Aadhaar 1234 5678 9012"
	tmp.WriteString(content)
	tmp.Close()
	defer os.Remove(tmp.Name())
	patterns := GetPatterns([]string{"iban", "india_aadhaar"}, nil, nil)
	contentBytes, _ := os.ReadFile(tmp.Name())
	matches, _ := scanForSensitiveData(string(contentBytes), patterns, 100, 1000)
	if len(matches["iban"]) == 0 || len(matches["india_aadhaar"]) == 0 {
		t.Fatal("expected international pattern matches")
	}
}

func TestExcludeSensitiveDataTypes(t *testing.T) {
	tmp, _ := os.CreateTemp("", "exclude*.txt")
	tmp.WriteString("test@example.com 4111-1111-1111-1111")
	tmp.Close()
	defer os.Remove(tmp.Name())
	patterns := GetPatterns([]string{"email", "credit_card"}, nil, []string{"email"})
	contentBytes, _ := os.ReadFile(tmp.Name())
	matches, _ := scanForSensitiveData(string(contentBytes), patterns, 100, 1000)
	if _, ok := matches["email"]; ok {
		t.Fatal("email should have been excluded")
	}
	if len(matches["credit_card"]) == 0 {
		t.Fatal("expected credit card match")
	}
}

func TestScanForSensitiveDataLimits(t *testing.T) {
	content := "a@test.com b@test.com c@test.com d@test.com"
	patterns := GetPatterns([]string{"email"}, nil, nil)
	matches, counts := scanForSensitiveData(content, patterns, 2, 2)
	if len(matches["email"]) != 2 {
		t.Fatalf("expected 2 limited matches, got %v", matches["email"])
	}
	if counts["email"] != 2 {
		t.Fatalf("expected limited count of 2, got %d", counts["email"])
	}
}

func TestRedactSensitiveMask(t *testing.T) {
	matches := map[string][]string{
		"email": {"test@example.com"},
	}
	redacted := redactSensitiveData(matches, "mask")
	if redacted["email"][0] == "test@example.com" {
		t.Fatal("expected masked value")
	}
	if !strings.HasSuffix(redacted["email"][0], "com") {
		t.Fatal("expected masked value to preserve suffix")
	}
}

func TestRedactSensitiveHash(t *testing.T) {
	matches := map[string][]string{
		"email": {"test@example.com"},
	}
	redacted := redactSensitiveData(matches, "hash")
	if len(redacted["email"][0]) != 64 {
		t.Fatalf("expected sha256 hash length, got %d", len(redacted["email"][0]))
	}
}

func TestExcludeOnlyDefaultsToAll(t *testing.T) {
	patterns := GetPatterns(nil, nil, []string{"email"})
	if _, ok := patterns["email"]; ok {
		t.Fatal("email should have been excluded")
	}
	if _, ok := patterns["credit_card"]; !ok {
		t.Fatal("expected credit card pattern when only exclude specified")
	}
}

func TestGetFileAttributes(t *testing.T) {
	tmp, _ := os.CreateTemp("", "attr")
	tmp.Close()
	defer os.Remove(tmp.Name())
	os.Chmod(tmp.Name(), 0444)
	fi, _ := os.Stat(tmp.Name())
	attrs := getFileAttributes(fi)
	if len(attrs) == 0 {
		t.Fatal("expected some attributes")
	}
}

func TestCollectFileData(t *testing.T) {
	tmp, _ := os.CreateTemp("", "collect*.txt")
	tmp.WriteString("hello test@example.com")
	tmp.Close()
	defer os.Remove(tmp.Name())
	fi, _ := os.Stat(tmp.Name())
	cfg := &config.Config{HashAlgorithms: []string{"md5"}, MaxFileSize: 1024, ScanFiles: true, ScanSensitive: true}
	patterns := GetPatterns([]string{"email"}, nil, nil)
	data, err := collectFileData(context.Background(), tmp.Name(), fi, cfg, patterns, buildFileModules(cfg, patterns))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if data.Path != tmp.Name() {
		t.Fatalf("unexpected path")
	}
	if _, ok := data.Hashes["md5"]; !ok {
		t.Fatalf("hash missing")
	}
}

func TestProcessFile(t *testing.T) {
	tmp, _ := os.CreateTemp("", "proc*.txt")
	tmp.WriteString("hello test@example.com")
	tmp.Close()
	defer os.Remove(tmp.Name())

	outFile, _ := os.CreateTemp("", "out*.json")
	defer os.Remove(outFile.Name())
	cfg := &config.Config{HashAlgorithms: []string{"md5"}, MaxFileSize: 1024, ScanFiles: true, ScanSensitive: true, OutputFileName: outFile.Name()}
	sys := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &output.Metrics{}
	w, err := output.New(cfg, sys, metrics)
	if err != nil {
		t.Fatalf("output init: %v", err)
	}
	defer w.Close()

	patterns := GetPatterns([]string{"email"}, nil, nil)
	ctx := context.Background()
	ProcessFile(ctx, tmp.Name(), cfg, w, patterns)
}

func TestProcessFileMaxFileSizeZeroTreatsAsUnlimited(t *testing.T) {
	tmp, _ := os.CreateTemp("", "proc-zero-limit*.txt")
	content := strings.Repeat("z", 256)
	tmp.WriteString(content)
	tmp.Close()
	defer os.Remove(tmp.Name())

	outFile, _ := os.CreateTemp("", "out-zero-limit*.json")
	defer os.Remove(outFile.Name())
	cfg := &config.Config{
		HashAlgorithms: []string{"sha256"},
		MaxFileSize:    0,
		ScanFiles:      true,
		ScanSensitive:  false,
		StartPaths:     []string{filepath.Dir(tmp.Name())},
		OutputFileName: outFile.Name(),
	}
	sys := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &output.Metrics{}
	w, err := output.New(cfg, sys, metrics)
	if err != nil {
		t.Fatalf("output init: %v", err)
	}
	defer w.Close()

	ProcessFile(context.Background(), tmp.Name(), cfg, w, GetPatterns(nil, nil, nil))
	if got := w.FilesScanned(); got != 1 {
		t.Fatalf("expected file to be scanned when max-file-size=0, got %d", got)
	}
}

func TestCountTotalFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.txt", []byte("a"), 0644)
	os.WriteFile(dir+"/b.txt", []byte("b"), 0644)
	cfg := &config.Config{}
	matcher := utils.NewPatternMatcher(cfg.IncludePatterns, cfg.ExcludePatterns)
	count, err := countTotalFiles(context.Background(), dir, cfg, time.Time{}, matcher)
	if err != nil || count != 2 {
		t.Fatalf("count: %v %d", err, count)
	}
}

func TestCountTotalFilesDelta(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.txt", []byte("a"), 0644)
	time.Sleep(1 * time.Second)
	last := time.Now()
	time.Sleep(1 * time.Second)
	os.WriteFile(dir+"/b.txt", []byte("b"), 0644)
	cfg := &config.Config{DeltaScan: true}
	matcher := utils.NewPatternMatcher(cfg.IncludePatterns, cfg.ExcludePatterns)
	count, err := countTotalFiles(context.Background(), dir, cfg, last, matcher)
	if err != nil || count != 1 {
		t.Fatalf("delta count: %v %d", err, count)
	}
}

func TestScanFilesLastScanTime(t *testing.T) {
	dir := t.TempDir()
	scanDir := filepath.Join(dir, "scan")
	os.Mkdir(scanDir, 0755)
	oldPath := filepath.Join(scanDir, "old.txt")
	os.WriteFile(oldPath, []byte("old"), 0644)
	time.Sleep(1 * time.Second)
	last := time.Now().UTC()
	time.Sleep(1 * time.Second)
	newPath := filepath.Join(scanDir, "new.txt")
	os.WriteFile(newPath, []byte("new"), 0644)

	outFile := filepath.Join(dir, "out.json")
	cfg := &config.Config{
		StartPaths:     []string{scanDir},
		OutputFileName: outFile,
		DeltaScan:      true,
		LastScanTime:   last.Format(time.RFC3339),
		LastScanFile:   "",
		NiceLevel:      "low",
		MaxIOPerSecond: 1000,
		ScanFiles:      true,
		MaxFileSize:    1024,
	}
	sys := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &output.Metrics{}
	w, err := output.New(cfg, sys, metrics)
	if err != nil {
		t.Fatalf("output init: %v", err)
	}
	defer w.Close()

	ctx := context.Background()
	if err := ScanFiles(ctx, cfg, metrics, w); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if metrics.FilesProcessed != 1 {
		t.Fatalf("expected 1 file processed got %d", metrics.FilesProcessed)
	}
}

func TestAdjustConcurrency(t *testing.T) {
	cfg := &config.Config{NiceLevel: "high"}
	adjustConcurrency(cfg)
	if cfg.ConcurrencyLevel != runtime.NumCPU() {
		t.Fatalf("high expected %d got %d", runtime.NumCPU(), cfg.ConcurrencyLevel)
	}
	cfg = &config.Config{NiceLevel: "medium"}
	adjustConcurrency(cfg)
	if cfg.ConcurrencyLevel != runtime.NumCPU()/2 && cfg.ConcurrencyLevel != 1 {
		t.Fatalf("medium got %d", cfg.ConcurrencyLevel)
	}
	cfg = &config.Config{NiceLevel: "low"}
	adjustConcurrency(cfg)
	if cfg.ConcurrencyLevel != 1 {
		t.Fatalf("low expected 1")
	}
}

func TestGetFileOwnership(t *testing.T) {
	tmp, _ := os.CreateTemp("", "owner")
	tmp.Close()
	defer os.Remove(tmp.Name())
	owner, err := getFileOwnership(tmp.Name(), nil)
	if err != nil || owner == "" {
		t.Fatalf("ownership: %v %s", err, owner)
	}
}

func TestShouldWriteFileData(t *testing.T) {
	cfg := &config.Config{ScanFiles: false}
	if shouldWriteFileData(cfg, &FileRecord{}) {
		t.Fatal("expected empty data to be skipped when scan-files is disabled")
	}
	if !shouldWriteFileData(cfg, &FileRecord{SearchHits: map[string]int{"secret": 1}}) {
		t.Fatal("expected data with search hits to be written")
	}

	cfg.ScanFiles = true
	if !shouldWriteFileData(cfg, &FileRecord{}) {
		t.Fatal("expected scan-files mode to always write")
	}
}

func TestScanForSearchTerms(t *testing.T) {
	content := "alpha beta alpha gamma"
	hits := scanForSearchTerms(content, []string{"alpha", "delta", ""})
	if hits["alpha"] != 2 {
		t.Fatalf("expected 2 alpha hits, got %d", hits["alpha"])
	}
	if _, ok := hits["delta"]; ok {
		t.Fatal("expected no delta hits")
	}
	if _, ok := hits[""]; ok {
		t.Fatal("expected empty search term to be ignored")
	}
}

func TestSensitiveEngineDeterministicCriticalParity(t *testing.T) {
	content := "test@example.com api_key=abcd1234 " +
		"AKIA" + "ABCDEFGHIJKLMNOP " +
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
	patterns := GetPatterns([]string{"email", "api_key", "aws_access_key", "jwt_token"}, nil, nil)

	regexMatches, regexCounts := scanForSensitiveData(content, patterns, 100, 1000)
	detMatches, detCounts := scanForSensitiveDataAdvanced([]byte(content), patterns, 100, 1000, "deterministic", "off", 4096, nil)

	if len(regexMatches) != len(detMatches) {
		t.Fatalf("expected deterministic critical parity, regex=%v deterministic=%v", regexMatches, detMatches)
	}
	for key, regexCount := range regexCounts {
		if detCounts[key] != regexCount {
			t.Fatalf("expected deterministic count parity for %s: regex=%d deterministic=%d", key, regexCount, detCounts[key])
		}
	}
}

func TestSensitiveMatchesMayBeTruncated(t *testing.T) {
	counts := map[string]int{"email": 2, "credit_card": 1}
	if !sensitiveMatchesMayBeTruncated(counts, 2, 0) {
		t.Fatal("expected per-type limit to mark potential truncation")
	}
	if !sensitiveMatchesMayBeTruncated(counts, 0, 3) {
		t.Fatal("expected total limit to mark potential truncation")
	}
	if sensitiveMatchesMayBeTruncated(counts, 3, 4) {
		t.Fatal("did not expect truncation when all counts are below limits")
	}
}

func TestBuildFuzzyHashers(t *testing.T) {
	cfg := &config.Config{FuzzyHash: true}
	hashers := buildFuzzyHashers(cfg)
	if len(hashers) == 0 || hashers[0].Name() != "tlsh" {
		t.Fatalf("expected default tlsh hasher, got %#v", hashers)
	}

	cfg = &config.Config{FuzzyAlgorithms: []string{"not-real"}}
	hashers = buildFuzzyHashers(cfg)
	if len(hashers) != 0 {
		t.Fatalf("expected unsupported fuzzy hasher to be dropped, got %#v", hashers)
	}
}

func TestTraversalDiscoversExpectedSet(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "x"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWrite := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	mustWrite(filepath.Join(root, "a", "keep-1.txt"), "one")
	mustWrite(filepath.Join(root, "a", "b", "keep-2.txt"), "two")
	mustWrite(filepath.Join(root, "x", "ignore.bin"), "bin")

	cfg := &config.Config{
		IncludePatterns: []string{"*.txt"},
		ExcludePatterns: []string{"*ignore*"},
	}

	discovered := collectWalkedFiles(t, root, cfg)
	if len(discovered) != 2 {
		t.Fatalf("expected 2 discovered files, got %d", len(discovered))
	}
	if !discovered[filepath.Join(root, "a", "keep-1.txt")] {
		t.Fatal("missing keep-1.txt")
	}
	if !discovered[filepath.Join(root, "a", "b", "keep-2.txt")] {
		t.Fatal("missing keep-2.txt")
	}
}

func collectWalkedFiles(t *testing.T, root string, cfg *config.Config) map[string]bool {
	t.Helper()
	matcher := utils.NewPatternMatcher(cfg.IncludePatterns, cfg.ExcludePatterns)
	files := make(map[string]bool)
	err := selectWalker(cfg).Walk(context.Background(), root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if matcher.ShouldInclude(path) {
			files[path] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	return files
}
