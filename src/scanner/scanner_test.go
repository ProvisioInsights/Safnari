package scanner

import (
	"context"
	"os"
	"runtime"
	"testing"

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
	patterns := GetPatterns([]string{"email"})
	matches := scanForSensitiveData(tmp.Name(), patterns)
	if len(matches["email"]) == 0 {
		t.Fatal("expected email match")
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
	patterns := GetPatterns([]string{"email"})
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
	if err := output.Init(cfg, sys, metrics); err != nil {
		t.Fatalf("output init: %v", err)
	}
	defer output.Close()

	patterns := GetPatterns([]string{"email"})
	ctx := context.Background()
	ProcessFile(ctx, tmp.Name(), cfg, patterns)
}

func TestCountTotalFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.txt", []byte("a"), 0644)
	os.WriteFile(dir+"/b.txt", []byte("b"), 0644)
	cfg := &config.Config{}
	count, err := countTotalFiles(dir, cfg)
	if err != nil || count != 2 {
		t.Fatalf("count: %v %d", err, count)
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
