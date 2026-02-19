package config

import (
	"flag"
	"os"
	"runtime"
	"testing"
	"time"
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
	res := parseCustomPatterns(`{"a":"1+","b":"2?"}`)
	if res["a"] != "1+" || res["b"] != "2?" {
		t.Fatalf("unexpected result: %v", res)
	}
	res = parseCustomPatterns(`{"ipv6":"[a-fA-F0-9:]{2,}"}`)
	if res["ipv6"] != "[a-fA-F0-9:]{2,}" {
		t.Fatalf("failed to parse complex regex: %v", res["ipv6"])
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
	cfg := &Config{CollectSystemInfo: false, ScanFiles: false, ScanProcesses: false, ScanSensitive: false}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error when all gathering disabled")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for missing paths")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, AllDrives: true}
	if err := cfg.validate(); err == nil && runtime.GOOS != "windows" {
		// On non-windows, AllDrives should cause error
		t.Fatal("expected error for all drives on non-windows")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, StartPaths: []string{"/"}, OutputFormat: "xml"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid output format error")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 0}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid concurrency")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "bad"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid nice level")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "high", LogLevel: "bad"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid log level")
	}
	cfg = &Config{ScanFiles: true, ScanSensitive: false, StartPaths: []string{"/"}, OutputFormat: "json", ConcurrencyLevel: 1, NiceLevel: "high", LogLevel: "info"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFuzzyHashFlagDefaultsAlgorithm(t *testing.T) {
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
	if len(cfg.FuzzyAlgorithms) == 0 || cfg.FuzzyAlgorithms[0] != "tlsh" {
		t.Fatalf("expected tlsh default, got %v", cfg.FuzzyAlgorithms)
	}
}

func TestIncludeSensitiveFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd", "--include-sensitive-data-types", "email,credit_card", "--exclude-sensitive-data-types", "email"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.IncludeDataTypes) != 2 || len(cfg.ExcludeDataTypes) != 1 || cfg.ExcludeDataTypes[0] != "email" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}

func TestScanSensitiveFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd", "--scan-sensitive=false"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ScanSensitive {
		t.Fatal("expected sensitive scanning disabled")
	}
}

func TestCollectSystemInfoFlag(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd", "--collect-system-info=false"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CollectSystemInfo {
		t.Fatal("expected system info collection disabled")
	}
}

func TestRedactAndTraceFlightFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{
		"cmd",
		"--redact-sensitive", "mask",
		"--trace-flight",
		"--trace-flight-file", "trace.out",
		"--trace-flight-max-bytes", "2048",
		"--trace-flight-min-age", "5s",
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RedactSensitive != "mask" {
		t.Fatalf("expected redact-sensitive mask, got %q", cfg.RedactSensitive)
	}
	if !cfg.TraceFlight {
		t.Fatal("expected trace flight enabled")
	}
	if cfg.TraceFlightFile != "trace.out" {
		t.Fatalf("unexpected trace flight file: %s", cfg.TraceFlightFile)
	}
	if cfg.TraceFlightMaxBytes != 2048 {
		t.Fatalf("unexpected trace flight max bytes: %d", cfg.TraceFlightMaxBytes)
	}
	if cfg.TraceFlightMinAge != 5*time.Second {
		t.Fatalf("unexpected trace flight min age: %v", cfg.TraceFlightMinAge)
	}
}

func TestOtelFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{
		"cmd",
		"--otel-endpoint", "https://otel.example.com/v1/logs",
		"--otel-export-paths",
		"--otel-export-sensitive",
		"--otel-export-cmdline",
		"--otel-headers", "Authorization=Bearer test,Env=prod",
		"--otel-service-name", "safnari-agent",
		"--otel-timeout", "10s",
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OtelEndpoint != "https://otel.example.com/v1/logs" {
		t.Fatalf("unexpected otel endpoint: %s", cfg.OtelEndpoint)
	}
	if cfg.OtelServiceName != "safnari-agent" {
		t.Fatalf("unexpected otel service name: %s", cfg.OtelServiceName)
	}
	if cfg.OtelTimeout != 10*time.Second {
		t.Fatalf("unexpected otel timeout: %v", cfg.OtelTimeout)
	}
	if !cfg.OtelExportPaths || !cfg.OtelExportSensitive || !cfg.OtelExportCmdline {
		t.Fatalf("expected otel export flags to be enabled: %+v", cfg)
	}
	if cfg.OtelHeaders["Authorization"] != "Bearer test" || cfg.OtelHeaders["Env"] != "prod" {
		t.Fatalf("unexpected otel headers: %v", cfg.OtelHeaders)
	}
}

func TestDefaultSkipCountEnabled(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{"cmd"}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.SkipCount {
		t.Fatal("expected skip-count default to be enabled")
	}
}

func TestOptimizationFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	oldFlag := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlag }()

	os.Args = []string{
		"cmd",
		"--perf-profile", "ultra",
		"--sensitive-engine", "hybrid",
		"--sensitive-longtail", "full",
		"--sensitive-window-bytes", "8192",
		"--content-read-mode", "mmap",
		"--stream-chunk-size", "131072",
		"--stream-overlap-bytes", "256",
		"--mmap-min-size", "262144",
		"--json-layout", "ndjson",
		"--simd-fastpath",
		"--auto-tune-runtime-metrics=false",
		"--auto-tune-target-runq", "1.5",
		"--auto-tune-target-latency-ms", "40",
		"--diag-slow-scan-threshold", "3s",
		"--diag-dir", "./diag-out",
		"--diag-goroutine-leak",
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.PerfProfile != "ultra" {
		t.Fatalf("unexpected perf profile: %s", cfg.PerfProfile)
	}
	if cfg.SensitiveEngine != "hybrid" {
		t.Fatalf("unexpected sensitive engine: %s", cfg.SensitiveEngine)
	}
	if cfg.SensitiveLongtail != "full" {
		t.Fatalf("unexpected sensitive longtail: %s", cfg.SensitiveLongtail)
	}
	if cfg.SensitiveWindowBytes != 8192 {
		t.Fatalf("unexpected sensitive window bytes: %d", cfg.SensitiveWindowBytes)
	}
	if cfg.ContentReadMode != "mmap" {
		t.Fatalf("unexpected content read mode: %s", cfg.ContentReadMode)
	}
	if cfg.StreamChunkSize != 131072 {
		t.Fatalf("unexpected stream chunk size: %d", cfg.StreamChunkSize)
	}
	if cfg.StreamOverlapBytes != 256 {
		t.Fatalf("unexpected stream overlap bytes: %d", cfg.StreamOverlapBytes)
	}
	if cfg.MmapMinSize != 262144 {
		t.Fatalf("unexpected mmap min size: %d", cfg.MmapMinSize)
	}
	if cfg.JSONLayout != "ndjson" {
		t.Fatalf("unexpected json layout: %s", cfg.JSONLayout)
	}
	if !cfg.SimdFastpath {
		t.Fatal("expected simd-fastpath enabled")
	}
	if cfg.AutoTuneRuntimeMetrics {
		t.Fatal("expected auto-tune-runtime-metrics disabled")
	}
	if cfg.AutoTuneTargetRunQ != 1.5 {
		t.Fatalf("unexpected auto-tune-target-runq: %f", cfg.AutoTuneTargetRunQ)
	}
	if cfg.AutoTuneTargetLatencyMs != 40 {
		t.Fatalf("unexpected auto-tune-target-latency-ms: %d", cfg.AutoTuneTargetLatencyMs)
	}
	if cfg.DiagSlowScanThreshold != 3*time.Second {
		t.Fatalf("unexpected diag-slow-scan-threshold: %v", cfg.DiagSlowScanThreshold)
	}
	if cfg.DiagDir != "./diag-out" {
		t.Fatalf("unexpected diag-dir: %s", cfg.DiagDir)
	}
	if !cfg.DiagGoroutineLeak {
		t.Fatal("expected diag-goroutine-leak enabled")
	}
}

func TestOptimizationFlagValidation(t *testing.T) {
	cfg := &Config{
		ScanFiles:               true,
		ScanSensitive:           false,
		ScanProcesses:           false,
		CollectSystemInfo:       false,
		StartPaths:              []string{"."},
		OutputFormat:            "json",
		ConcurrencyLevel:        1,
		NiceLevel:               "medium",
		LogLevel:                "info",
		PerfProfile:             "adaptive",
		SensitiveEngine:         "auto",
		SensitiveLongtail:       "sampled",
		SensitiveWindowBytes:    4096,
		ContentReadMode:         "auto",
		StreamChunkSize:         256 * 1024,
		StreamOverlapBytes:      512,
		JSONLayout:              "ndjson",
		AutoTune:                false,
		DiagDir:                 ".",
		MmapMinSize:             1024,
		AutoTuneTargetRunQ:      1,
		AutoTuneTargetLatencyMs: 25,
	}
	cfg.PerfProfile = "bad"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid perf-profile error")
	}

	cfg.PerfProfile = "adaptive"
	cfg.SensitiveEngine = "nope"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid sensitive-engine error")
	}

	cfg.SensitiveEngine = "auto"
	cfg.SensitiveLongtail = "broken"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid sensitive-longtail error")
	}

	cfg.SensitiveLongtail = "sampled"
	cfg.ContentReadMode = "broken"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid content-read-mode error")
	}

	cfg.ContentReadMode = "stream"
	cfg.StreamOverlapBytes = cfg.StreamChunkSize
	if err := cfg.validate(); err == nil {
		t.Fatal("expected invalid stream-overlap-bytes error")
	}
}
