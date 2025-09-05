package config

import (
	"flag"
	"os"
	"runtime"
	"testing"
)

func TestParseCommaSeparated(t *testing.T) {
	res := parseCommaSeparated("a,b , c")
	if len(res) != 3 || res[1] != "b" {
		t.Fatalf("unexpected result: %v", res)
	}
	if res := parseCommaSeparated(""); len(res) != 0 {
		t.Fatalf("expected empty slice")
	}
}

func TestParseCustomPatterns(t *testing.T) {
	res := parseCustomPatterns("a:1+,b:2?")
	if res["a"] != "1+" || res["b"] != "2?" {
		t.Fatalf("unexpected result: %v", res)
	}
	if res := parseCustomPatterns(""); len(res) != 0 {
		t.Fatalf("expected empty map")
	}
}

func TestLoadFromFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "cfg*.json")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	tmp.WriteString(`{"start_paths":["/tmp"],"scan_files":false}`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg := &Config{}
	if err := cfg.loadFromFile(tmp.Name()); err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.StartPaths[0] != "/tmp" || cfg.ScanFiles {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{ScanFiles: false, ScanProcesses: false}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error when both scanning disabled")
	}
	cfg = &Config{ScanFiles: true}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for missing paths")
	}
	cfg = &Config{ScanFiles: true, AllDrives: true}
	if err := cfg.validate(); err == nil && runtime.GOOS != "windows" {
		// On non-windows, AllDrives should cause error
		t.Fatal("expected error for all drives on non-windows")
	}
	cfg = &Config{ScanFiles: true, StartPaths: []string{"/"}, OutputFormat: "xml"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid output format error")
	}
	cfg = &Config{ScanFiles: true, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 0}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid concurrency")
	}
	cfg = &Config{ScanFiles: true, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "bad"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid nice level")
	}
	cfg = &Config{ScanFiles: true, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "high", LogLevel: "bad"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid log level")
	}
	cfg = &Config{ScanFiles: true, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "high", LogLevel: "info"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFuzzyHashFlagAddsAlgorithm(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd", "--fuzzy-hash"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.FuzzyHash {
		t.Fatal("expected fuzzy hash enabled")
	}
	found := false
	for _, a := range cfg.HashAlgorithms {
		if a == "ssdeep" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ssdeep algorithm not added")
	}
}

func TestExcludeSensitiveFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd", "--sensitive-data-types", "email,credit_card", "--exclude-sensitive-data-types", "email"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.SensitiveDataTypes) != 2 || len(cfg.ExcludeDataTypes) != 1 || cfg.ExcludeDataTypes[0] != "email" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}
