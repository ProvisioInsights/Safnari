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

func TestFlagParsers(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("i", 5, "")
	fs.Int64("i64", 10, "")
	fs.Bool("b", true, "")
	fs.Parse([]string{"-i=7", "-i64=20", "-b=false"})
	if getIntFlagValue(fs.Lookup("i")) != 7 {
		t.Fatal("int parse failed")
	}
	if getInt64FlagValue(fs.Lookup("i64")) != 20 {
		t.Fatal("int64 parse failed")
	}
	if parseBoolFlagValue(fs.Lookup("b")) {
		t.Fatal("bool parse failed")
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
