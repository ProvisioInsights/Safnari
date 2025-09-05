package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/systeminfo"
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
	if !shouldSearchContent("text/plain") {
		t.Fatal("text should search")
	}
	if shouldSearchContent("image/png") {
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
	matches := scanForSensitiveData(tmp.Name(), patterns)
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
	matches := scanForSensitiveData(tmp.Name(), patterns)
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
	matches := scanForSensitiveData(tmp.Name(), patterns)
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
	matches := scanForSensitiveData(tmp.Name(), patterns)
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
	matches := scanForSensitiveData(tmp.Name(), patterns)
	if _, ok := matches["email"]; ok {
		t.Fatal("email should have been excluded")
	}
	if len(matches["credit_card"]) == 0 {
		t.Fatal("expected credit card match")
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
	cfg := &config.Config{HashAlgorithms: []string{"md5"}, MaxFileSize: 1024}
	patterns := GetPatterns([]string{"email"}, nil, nil)
	data, err := collectFileData(tmp.Name(), fi, cfg, patterns)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if data["path"] != tmp.Name() {
		t.Fatalf("unexpected path")
	}
	if _, ok := data["hashes"].(map[string]string)["md5"]; !ok {
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
	cfg := &config.Config{HashAlgorithms: []string{"md5"}, MaxFileSize: 1024, OutputFileName: outFile.Name()}
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

func TestCountTotalFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.txt", []byte("a"), 0644)
	os.WriteFile(dir+"/b.txt", []byte("b"), 0644)
	cfg := &config.Config{}
	count, err := countTotalFiles(dir, cfg, time.Time{})
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
	count, err := countTotalFiles(dir, cfg, last)
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
	owner, err := getFileOwnership(tmp.Name())
	if err != nil || owner == "" {
		t.Fatalf("ownership: %v %s", err, owner)
	}
}
