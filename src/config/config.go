package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"safnari/version"
)

type Config struct {
	StartPaths              []string          `json:"start_paths"`
	AllDrives               bool              `json:"all_drives"`
	ScanFiles               bool              `json:"scan_files"`
	ScanSensitive           bool              `json:"scan_sensitive"`
	ScanProcesses           bool              `json:"scan_processes"`
	CollectSystemInfo       bool              `json:"collect_system_info"`
	OutputFormat            string            `json:"output_format"`
	OutputFileName          string            `json:"output_file_name"`
	ConcurrencyLevel        int               `json:"concurrency_level"`
	NiceLevel               string            `json:"nice_level"`
	HashAlgorithms          []string          `json:"hash_algorithms"`
	SearchTerms             []string          `json:"search_terms"`
	IncludePatterns         []string          `json:"include_patterns"`
	ExcludePatterns         []string          `json:"exclude_patterns"`
	MaxFileSize             int64             `json:"max_file_size"`
	MaxOutputFileSize       int64             `json:"max_output_file_size"`
	LogLevel                string            `json:"log_level"`
	MaxIOPerSecond          int               `json:"max_io_per_second"`
	ConfigFile              string            `json:"config_file"`
	ExtendedProcessInfo     bool              `json:"extended_process_info"`
	IncludeDataTypes        []string          `json:"include_sensitive_data_types"`
	ExcludeDataTypes        []string          `json:"exclude_sensitive_data_types"`
	CustomPatterns          map[string]string `json:"custom_patterns"`
	FuzzyHash               bool              `json:"fuzzy_hash"`
	FuzzyAlgorithms         []string          `json:"fuzzy_algorithms"`
	FuzzyMinSize            int64             `json:"fuzzy_min_size"`
	FuzzyMaxSize            int64             `json:"fuzzy_max_size"`
	DeltaScan               bool              `json:"delta_scan"`
	LastScanFile            string            `json:"last_scan_file"`
	LastScanTime            string            `json:"last_scan_time"`
	SkipCount               bool              `json:"skip_count"`
	SensitiveMaxPerType     int               `json:"sensitive_max_matches_per_type"`
	SensitiveMaxTotal       int               `json:"sensitive_max_total_matches"`
	MetadataMaxBytes        int64             `json:"metadata_max_bytes"`
	RedactSensitive         string            `json:"redact_sensitive"`
	CollectXattrs           bool              `json:"collect_xattrs"`
	XattrMaxValueSize       int               `json:"xattr_max_value_size"`
	CollectACL              bool              `json:"collect_acl"`
	CollectScheduled        bool              `json:"collect_scheduled_tasks"`
	CollectUsers            bool              `json:"collect_users"`
	CollectGroups           bool              `json:"collect_groups"`
	CollectAdmins           bool              `json:"collect_admins"`
	ScanADS                 bool              `json:"scan_ads"`
	AutoTune                bool              `json:"auto_tune"`
	AutoTuneInterval        time.Duration     `json:"auto_tune_interval"`
	AutoTuneTargetCPU       float64           `json:"auto_tune_target_cpu"`
	AutoTuneRuntimeMetrics  bool              `json:"auto_tune_runtime_metrics"`
	AutoTuneTargetRunQ      float64           `json:"auto_tune_target_runq"`
	AutoTuneTargetLatencyMs int               `json:"auto_tune_target_latency_ms"`
	PerfProfile             string            `json:"perf_profile"`
	SensitiveEngine         string            `json:"sensitive_engine"`
	SensitiveLongtail       string            `json:"sensitive_longtail"`
	SensitiveWindowBytes    int               `json:"sensitive_window_bytes"`
	ContentReadMode         string            `json:"content_read_mode"`
	StreamChunkSize         int               `json:"stream_chunk_size"`
	StreamOverlapBytes      int               `json:"stream_overlap_bytes"`
	MmapMinSize             int64             `json:"mmap_min_size"`
	JSONLayout              string            `json:"json_layout"`
	SimdFastpath            bool              `json:"simd_fastpath"`
	DiagSlowScanThreshold   time.Duration     `json:"diag_slow_scan_threshold"`
	DiagDir                 string            `json:"diag_dir"`
	DiagGoroutineLeak       bool              `json:"diag_goroutine_leak"`
	OtelEndpoint            string            `json:"otel_endpoint"`
	OtelFromEnv             bool              `json:"otel_from_env"`
	OtelHeaders             map[string]string `json:"otel_headers"`
	OtelServiceName         string            `json:"otel_service_name"`
	OtelTimeout             time.Duration     `json:"otel_timeout"`
	OtelExportPaths         bool              `json:"otel_export_paths"`
	OtelExportSensitive     bool              `json:"otel_export_sensitive"`
	OtelExportCmdline       bool              `json:"otel_export_cmdline"`
	TraceFlight             bool              `json:"trace_flight"`
	TraceFlightFile         string            `json:"trace_flight_file"`
	TraceFlightMaxBytes     uint64            `json:"trace_flight_max_bytes"`
	TraceFlightMinAge       time.Duration     `json:"trace_flight_min_age"`
	ConcurrencySet          bool              `json:"-"`
	MaxIOSet                bool              `json:"-"`
}

func LoadConfig() (*Config, error) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102-150405")
	cfg := &Config{
		StartPaths:              []string{"."},
		ScanFiles:               true,
		ScanSensitive:           true,
		ScanProcesses:           true,
		CollectSystemInfo:       true,
		OutputFormat:            "json",
		OutputFileName:          fmt.Sprintf("safnari-%s-%d.ndjson", timestamp, now.Unix()),
		ConcurrencyLevel:        runtime.NumCPU(),
		NiceLevel:               "medium",
		HashAlgorithms:          []string{"md5", "sha1", "sha256"},
		SearchTerms:             []string{},
		MaxFileSize:             10485760,
		MaxOutputFileSize:       104857600,
		LogLevel:                "info",
		MaxIOPerSecond:          1000,
		IncludeDataTypes:        []string{},
		ExcludeDataTypes:        []string{},
		CustomPatterns:          map[string]string{},
		FuzzyAlgorithms:         []string{},
		FuzzyMinSize:            256,
		FuzzyMaxSize:            20 * 1024 * 1024,
		DeltaScan:               false,
		LastScanFile:            ".safnari_last_scan",
		SkipCount:               true,
		SensitiveMaxPerType:     100,
		SensitiveMaxTotal:       1000,
		MetadataMaxBytes:        1 * 1024 * 1024,
		RedactSensitive:         "mask",
		CollectXattrs:           true,
		XattrMaxValueSize:       1024,
		CollectACL:              true,
		CollectScheduled:        true,
		CollectUsers:            true,
		CollectGroups:           true,
		CollectAdmins:           true,
		ScanADS:                 false,
		AutoTune:                true,
		AutoTuneInterval:        5 * time.Second,
		AutoTuneTargetCPU:       60,
		AutoTuneRuntimeMetrics:  true,
		AutoTuneTargetRunQ:      1.0,
		AutoTuneTargetLatencyMs: 25,
		PerfProfile:             "adaptive",
		SensitiveEngine:         "auto",
		SensitiveLongtail:       "sampled",
		SensitiveWindowBytes:    4096,
		ContentReadMode:         "auto",
		StreamChunkSize:         256 * 1024,
		StreamOverlapBytes:      512,
		MmapMinSize:             128 * 1024,
		JSONLayout:              "ndjson",
		SimdFastpath:            false,
		DiagSlowScanThreshold:   0,
		DiagDir:                 ".",
		DiagGoroutineLeak:       false,
		OtelEndpoint:            "",
		OtelFromEnv:             false,
		OtelHeaders:             map[string]string{},
		OtelServiceName:         "safnari",
		OtelTimeout:             5 * time.Second,
		OtelExportPaths:         false,
		OtelExportSensitive:     false,
		OtelExportCmdline:       false,
		TraceFlight:             false,
		TraceFlightFile:         "trace-flight.out",
		TraceFlightMaxBytes:     0,
		TraceFlightMinAge:       0,
	}

	startPath := flag.String("path", strings.Join(cfg.StartPaths, ","), fmt.Sprintf("Comma-separated list of start paths to scan (default: %s).", strings.Join(cfg.StartPaths, ",")))
	allDrives := flag.Bool("all-drives", cfg.AllDrives, fmt.Sprintf("Scan all local drives (Windows only) (default: %t).", cfg.AllDrives))
	scanFiles := flag.Bool("scan-files", cfg.ScanFiles, fmt.Sprintf("Enable file scanning (default: %t).", cfg.ScanFiles))
	scanSensitive := flag.Bool("scan-sensitive", cfg.ScanSensitive, fmt.Sprintf("Enable sensitive data scanning (default: %t).", cfg.ScanSensitive))
	scanProcesses := flag.Bool("scan-processes", cfg.ScanProcesses, fmt.Sprintf("Enable process scanning (default: %t).", cfg.ScanProcesses))
	collectSystemInfo := flag.Bool("collect-system-info", cfg.CollectSystemInfo, fmt.Sprintf("Collect system information (default: %t).", cfg.CollectSystemInfo))
	format := flag.String("format", cfg.OutputFormat, fmt.Sprintf("Output format: json (default: %s).", cfg.OutputFormat))
	output := flag.String("output", cfg.OutputFileName, "Output file name (default: safnari-<timestamp>-<unix>.ndjson).")
	concurrency := flag.Int("concurrency", cfg.ConcurrencyLevel, fmt.Sprintf("Concurrency level (default: %d).", cfg.ConcurrencyLevel))
	nice := flag.String("nice", cfg.NiceLevel, fmt.Sprintf("Nice level: high, medium, or low (default: %s).", cfg.NiceLevel))
	hashes := flag.String("hashes", strings.Join(cfg.HashAlgorithms, ","), fmt.Sprintf("Comma-separated list of hash algorithms (default: %s).", strings.Join(cfg.HashAlgorithms, ",")))
	searches := flag.String("search", "", "Comma-separated list of search terms (default: none).")
	includes := flag.String("include", "", "Comma-separated list of include patterns (default: none).")
	excludes := flag.String("exclude", "", "Comma-separated list of exclude patterns (default: none).")
	maxFileSize := flag.Int64("max-file-size", cfg.MaxFileSize, fmt.Sprintf("Maximum file size to process in bytes (default: %d).", cfg.MaxFileSize))
	maxOutputFileSize := flag.Int64("max-output-file-size", cfg.MaxOutputFileSize, fmt.Sprintf("Maximum output file size before rotation in bytes (default: %d).", cfg.MaxOutputFileSize))
	logLevel := flag.String("log-level", cfg.LogLevel, fmt.Sprintf("Log level: debug, info, warn, error, fatal, or panic (default: %s).", cfg.LogLevel))
	maxIO := flag.Int("max-io-per-second", cfg.MaxIOPerSecond, fmt.Sprintf("Maximum disk I/O operations per second (default: %d).", cfg.MaxIOPerSecond))
	skipCount := flag.Bool("skip-count", cfg.SkipCount, "Skip initial file counting to start scanning immediately")
	sensitiveMaxPerType := flag.Int(
		"sensitive-max-matches-per-type",
		cfg.SensitiveMaxPerType,
		fmt.Sprintf(
			"Maximum sensitive matches stored per type per file (default: %d, 0 means unlimited).",
			cfg.SensitiveMaxPerType,
		),
	)
	sensitiveMaxTotal := flag.Int(
		"sensitive-max-total-matches",
		cfg.SensitiveMaxTotal,
		fmt.Sprintf(
			"Maximum total sensitive matches stored per file (default: %d, 0 means unlimited).",
			cfg.SensitiveMaxTotal,
		),
	)
	metadataMaxBytes := flag.Int64(
		"metadata-max-bytes",
		cfg.MetadataMaxBytes,
		fmt.Sprintf(
			"Maximum bytes metadata parsers may read/decode per file (default: %d, 0 means unlimited).",
			cfg.MetadataMaxBytes,
		),
	)
	configFile := flag.String("config", "", "Path to JSON configuration file (default: none).")
	extendedProcessInfo := flag.Bool("extended-process-info", cfg.ExtendedProcessInfo, fmt.Sprintf("Gather extended process information (requires elevated privileges) (default: %t).", cfg.ExtendedProcessInfo))
	includeDataTypes := flag.String("include-sensitive-data-types", "", "Comma-separated list of sensitive data types to include when scanning (default: none). Use 'all' to include all built-in types.")
	excludeDataTypes := flag.String("exclude-sensitive-data-types", "", "Comma-separated list of sensitive data types to exclude when scanning.")
	customPatterns := flag.String("custom-patterns", "", "Custom sensitive data patterns as a JSON object mapping names to regexes")
	fuzzyHash := flag.Bool("fuzzy-hash", cfg.FuzzyHash, fmt.Sprintf("Enable fuzzy hashing (default: %t).", cfg.FuzzyHash))
	fuzzyAlgorithms := flag.String("fuzzy-algorithms", strings.Join(cfg.FuzzyAlgorithms, ","), "Comma-separated list of fuzzy hash algorithms (default: tlsh when fuzzy hashing enabled).")
	fuzzyMinSize := flag.Int64("fuzzy-min-size", cfg.FuzzyMinSize, fmt.Sprintf("Minimum file size in bytes for fuzzy hashing (default: %d).", cfg.FuzzyMinSize))
	fuzzyMaxSize := flag.Int64("fuzzy-max-size", cfg.FuzzyMaxSize, fmt.Sprintf("Maximum file size in bytes for fuzzy hashing (default: %d).", cfg.FuzzyMaxSize))
	deltaScan := flag.Bool("delta-scan", cfg.DeltaScan, fmt.Sprintf("Only scan files modified since the last run (default: %t).", cfg.DeltaScan))
	lastScanFile := flag.String("last-scan-file", cfg.LastScanFile, fmt.Sprintf("Path to timestamp file for delta scans (default: %s).", cfg.LastScanFile))
	lastScanTime := flag.String("last-scan", cfg.LastScanTime, "Timestamp of last scan in RFC3339 format (default: none).")
	redactSensitive := flag.String("redact-sensitive", cfg.RedactSensitive, "Redact sensitive data in output: mask or hash (default: none).")
	collectXattrs := flag.Bool("collect-xattrs", cfg.CollectXattrs, fmt.Sprintf("Collect extended attributes (default: %t).", cfg.CollectXattrs))
	xattrMaxValueSize := flag.Int("xattr-max-value-size", cfg.XattrMaxValueSize, fmt.Sprintf("Max bytes of xattr values to capture (default: %d).", cfg.XattrMaxValueSize))
	collectACL := flag.Bool("collect-acl", cfg.CollectACL, fmt.Sprintf("Collect ACLs (default: %t).", cfg.CollectACL))
	collectScheduled := flag.Bool("collect-scheduled-tasks", cfg.CollectScheduled, fmt.Sprintf("Collect scheduled tasks (default: %t).", cfg.CollectScheduled))
	collectUsers := flag.Bool("collect-users", cfg.CollectUsers, fmt.Sprintf("Collect local users (default: %t).", cfg.CollectUsers))
	collectGroups := flag.Bool("collect-groups", cfg.CollectGroups, fmt.Sprintf("Collect local groups (default: %t).", cfg.CollectGroups))
	collectAdmins := flag.Bool("collect-admins", cfg.CollectAdmins, fmt.Sprintf("Collect admin users/groups (default: %t).", cfg.CollectAdmins))
	scanADS := flag.Bool("scan-ads", cfg.ScanADS, fmt.Sprintf("Scan Windows alternate data streams (default: %t).", cfg.ScanADS))
	autoTune := flag.Bool("auto-tune", cfg.AutoTune, fmt.Sprintf("Auto-tune resource usage (default: %t).", cfg.AutoTune))
	autoTuneInterval := flag.Duration("auto-tune-interval", cfg.AutoTuneInterval, "Auto-tune interval (default: 5s).")
	autoTuneTargetCPU := flag.Float64("auto-tune-target-cpu", cfg.AutoTuneTargetCPU, "Auto-tune target CPU percent (default: 60).")
	autoTuneRuntimeMetrics := flag.Bool(
		"auto-tune-runtime-metrics",
		cfg.AutoTuneRuntimeMetrics,
		"Use runtime scheduler and heap signals in auto-tune decisions (default: true).",
	)
	autoTuneTargetRunQ := flag.Float64(
		"auto-tune-target-runq",
		cfg.AutoTuneTargetRunQ,
		"Auto-tune target scheduler run-queue ratio (default: 1.0).",
	)
	autoTuneTargetLatencyMs := flag.Int(
		"auto-tune-target-latency-ms",
		cfg.AutoTuneTargetLatencyMs,
		"Auto-tune target scheduler latency in milliseconds (default: 25).",
	)
	perfProfile := flag.String("perf-profile", cfg.PerfProfile, "Performance profile: adaptive or ultra (default: adaptive).")
	sensitiveEngine := flag.String(
		"sensitive-engine",
		cfg.SensitiveEngine,
		"Sensitive scan engine: auto, deterministic, or hybrid (default: auto).",
	)
	sensitiveLongtail := flag.String(
		"sensitive-longtail",
		cfg.SensitiveLongtail,
		"Long-tail sensitive pattern handling: off, sampled, or full (default: sampled).",
	)
	sensitiveWindowBytes := flag.Int(
		"sensitive-window-bytes",
		cfg.SensitiveWindowBytes,
		"Window size in bytes for long-tail hybrid scans (default: 4096).",
	)
	contentReadMode := flag.String("content-read-mode", cfg.ContentReadMode, "Content read mode: auto, stream, or mmap (default: auto).")
	streamChunkSize := flag.Int("stream-chunk-size", cfg.StreamChunkSize, "Streaming chunk size in bytes (default: 262144).")
	streamOverlapBytes := flag.Int("stream-overlap-bytes", cfg.StreamOverlapBytes, "Streaming overlap in bytes between chunks (default: 512).")
	mmapMinSize := flag.Int64(
		"mmap-min-size",
		cfg.MmapMinSize,
		"Minimum file size in bytes for mmap content read path when enabled (default: 131072).",
	)
	jsonLayout := flag.String("json-layout", cfg.JSONLayout, "JSON output layout. Only ndjson is supported (default: ndjson).")
	simdFastpath := flag.Bool("simd-fastpath", cfg.SimdFastpath, "Enable SIMD text fast path experiment when available (default: false).")
	diagSlowScanThreshold := flag.Duration(
		"diag-slow-scan-threshold",
		cfg.DiagSlowScanThreshold,
		"If positive, emit diagnostics when scan progress stalls for this duration (default: 0/off).",
	)
	diagDir := flag.String("diag-dir", cfg.DiagDir, "Diagnostics output directory (default: current directory).")
	diagGoroutineLeak := flag.Bool(
		"diag-goroutine-leak",
		cfg.DiagGoroutineLeak,
		"Write goroutine leak profile on shutdown (default: false).",
	)
	otelEndpoint := flag.String("otel-endpoint", cfg.OtelEndpoint, "OTLP/HTTP logs endpoint (default: none).")
	otelFromEnv := flag.Bool("otel-from-env", cfg.OtelFromEnv, "Allow OTEL endpoint fallback from OTEL environment variables (default: false).")
	otelHeaders := flag.String("otel-headers", "", "Comma-separated OTEL headers (key=value) for export (default: none).")
	otelServiceName := flag.String("otel-service-name", cfg.OtelServiceName, "OTEL service name for export (default: safnari).")
	otelTimeout := flag.Duration("otel-timeout", cfg.OtelTimeout, "OTEL export timeout (default: 5s).")
	otelExportPaths := flag.Bool("otel-export-paths", cfg.OtelExportPaths, "Include raw file/executable paths in OTEL payloads (default: false).")
	otelExportSensitive := flag.Bool("otel-export-sensitive", cfg.OtelExportSensitive, "Include sensitive_data and detailed system inventories in OTEL payloads (default: false).")
	otelExportCmdline := flag.Bool("otel-export-cmdline", cfg.OtelExportCmdline, "Include process command lines in OTEL payloads (default: false).")
	traceFlight := flag.Bool("trace-flight", cfg.TraceFlight, fmt.Sprintf("Enable flight recorder tracing (default: %t).", cfg.TraceFlight))
	traceFlightFile := flag.String("trace-flight-file", cfg.TraceFlightFile, fmt.Sprintf("Flight recorder output file (default: %s).", cfg.TraceFlightFile))
	traceFlightMaxBytes := flag.Uint64("trace-flight-max-bytes", cfg.TraceFlightMaxBytes, "Max bytes for flight recorder buffer (default: 0 for runtime default).")
	traceFlightMinAge := flag.Duration("trace-flight-min-age", cfg.TraceFlightMinAge, "Minimum age of trace events to retain (default: 0).")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = displayHelp
	flag.Parse()

	if *showVersion {
		fmt.Printf("Safnari version %s\n", version.Version)
		os.Exit(0)
	}

	if *configFile != "" {
		cfg.ConfigFile = *configFile
		if err := cfg.loadFromFile(cfg.ConfigFile); err != nil {
			return nil, err
		}
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "path":
			cfg.StartPaths = parseCommaSeparated(*startPath)
		case "all-drives":
			cfg.AllDrives = *allDrives
		case "scan-files":
			cfg.ScanFiles = *scanFiles
		case "scan-sensitive":
			cfg.ScanSensitive = *scanSensitive
		case "scan-processes":
			cfg.ScanProcesses = *scanProcesses
		case "collect-system-info":
			cfg.CollectSystemInfo = *collectSystemInfo
		case "format":
			cfg.OutputFormat = strings.ToLower(*format)
		case "output":
			cfg.OutputFileName = *output
		case "concurrency":
			cfg.ConcurrencyLevel = *concurrency
			cfg.ConcurrencySet = true
		case "nice":
			cfg.NiceLevel = *nice
		case "hashes":
			cfg.HashAlgorithms = parseCommaSeparated(*hashes)
		case "search":
			cfg.SearchTerms = parseCommaSeparated(*searches)
		case "include":
			cfg.IncludePatterns = parseCommaSeparated(*includes)
		case "exclude":
			cfg.ExcludePatterns = parseCommaSeparated(*excludes)
		case "max-file-size":
			cfg.MaxFileSize = *maxFileSize
		case "max-output-file-size":
			cfg.MaxOutputFileSize = *maxOutputFileSize
		case "log-level":
			cfg.LogLevel = *logLevel
		case "max-io-per-second":
			cfg.MaxIOPerSecond = *maxIO
			cfg.MaxIOSet = true
		case "extended-process-info":
			cfg.ExtendedProcessInfo = *extendedProcessInfo
		case "include-sensitive-data-types":
			cfg.IncludeDataTypes = parseCommaSeparated(*includeDataTypes)
		case "exclude-sensitive-data-types":
			cfg.ExcludeDataTypes = parseCommaSeparated(*excludeDataTypes)
		case "custom-patterns":
			cfg.CustomPatterns = parseCustomPatterns(*customPatterns)
		case "fuzzy-hash":
			cfg.FuzzyHash = *fuzzyHash
		case "fuzzy-algorithms":
			cfg.FuzzyAlgorithms = parseCommaSeparated(*fuzzyAlgorithms)
		case "fuzzy-min-size":
			cfg.FuzzyMinSize = *fuzzyMinSize
		case "fuzzy-max-size":
			cfg.FuzzyMaxSize = *fuzzyMaxSize
		case "delta-scan":
			cfg.DeltaScan = *deltaScan
		case "last-scan-file":
			cfg.LastScanFile = *lastScanFile
		case "last-scan":
			cfg.LastScanTime = *lastScanTime
		case "skip-count":
			cfg.SkipCount = *skipCount
		case "sensitive-max-matches-per-type":
			cfg.SensitiveMaxPerType = *sensitiveMaxPerType
		case "sensitive-max-total-matches":
			cfg.SensitiveMaxTotal = *sensitiveMaxTotal
		case "metadata-max-bytes":
			cfg.MetadataMaxBytes = *metadataMaxBytes
		case "redact-sensitive":
			cfg.RedactSensitive = strings.ToLower(*redactSensitive)
		case "collect-xattrs":
			cfg.CollectXattrs = *collectXattrs
		case "xattr-max-value-size":
			cfg.XattrMaxValueSize = *xattrMaxValueSize
		case "collect-acl":
			cfg.CollectACL = *collectACL
		case "collect-scheduled-tasks":
			cfg.CollectScheduled = *collectScheduled
		case "collect-users":
			cfg.CollectUsers = *collectUsers
		case "collect-groups":
			cfg.CollectGroups = *collectGroups
		case "collect-admins":
			cfg.CollectAdmins = *collectAdmins
		case "scan-ads":
			cfg.ScanADS = *scanADS
		case "auto-tune":
			cfg.AutoTune = *autoTune
		case "auto-tune-interval":
			cfg.AutoTuneInterval = *autoTuneInterval
		case "auto-tune-target-cpu":
			cfg.AutoTuneTargetCPU = *autoTuneTargetCPU
		case "auto-tune-runtime-metrics":
			cfg.AutoTuneRuntimeMetrics = *autoTuneRuntimeMetrics
		case "auto-tune-target-runq":
			cfg.AutoTuneTargetRunQ = *autoTuneTargetRunQ
		case "auto-tune-target-latency-ms":
			cfg.AutoTuneTargetLatencyMs = *autoTuneTargetLatencyMs
		case "perf-profile":
			cfg.PerfProfile = strings.ToLower(strings.TrimSpace(*perfProfile))
		case "sensitive-engine":
			cfg.SensitiveEngine = strings.ToLower(strings.TrimSpace(*sensitiveEngine))
		case "sensitive-longtail":
			cfg.SensitiveLongtail = strings.ToLower(strings.TrimSpace(*sensitiveLongtail))
		case "sensitive-window-bytes":
			cfg.SensitiveWindowBytes = *sensitiveWindowBytes
		case "content-read-mode":
			cfg.ContentReadMode = strings.ToLower(strings.TrimSpace(*contentReadMode))
		case "stream-chunk-size":
			cfg.StreamChunkSize = *streamChunkSize
		case "stream-overlap-bytes":
			cfg.StreamOverlapBytes = *streamOverlapBytes
		case "mmap-min-size":
			cfg.MmapMinSize = *mmapMinSize
		case "json-layout":
			cfg.JSONLayout = strings.ToLower(strings.TrimSpace(*jsonLayout))
		case "simd-fastpath":
			cfg.SimdFastpath = *simdFastpath
		case "diag-slow-scan-threshold":
			cfg.DiagSlowScanThreshold = *diagSlowScanThreshold
		case "diag-dir":
			cfg.DiagDir = strings.TrimSpace(*diagDir)
		case "diag-goroutine-leak":
			cfg.DiagGoroutineLeak = *diagGoroutineLeak
		case "otel-endpoint":
			cfg.OtelEndpoint = strings.TrimSpace(*otelEndpoint)
		case "otel-from-env":
			cfg.OtelFromEnv = *otelFromEnv
		case "otel-headers":
			cfg.OtelHeaders = parseHeaders(*otelHeaders)
		case "otel-service-name":
			cfg.OtelServiceName = strings.TrimSpace(*otelServiceName)
		case "otel-timeout":
			cfg.OtelTimeout = *otelTimeout
		case "otel-export-paths":
			cfg.OtelExportPaths = *otelExportPaths
		case "otel-export-sensitive":
			cfg.OtelExportSensitive = *otelExportSensitive
		case "otel-export-cmdline":
			cfg.OtelExportCmdline = *otelExportCmdline
		case "trace-flight":
			cfg.TraceFlight = *traceFlight
		case "trace-flight-file":
			cfg.TraceFlightFile = *traceFlightFile
		case "trace-flight-max-bytes":
			cfg.TraceFlightMaxBytes = *traceFlightMaxBytes
		case "trace-flight-min-age":
			cfg.TraceFlightMinAge = *traceFlightMinAge
		}
	})
	cfg.OutputFormat = strings.ToLower(cfg.OutputFormat)
	cfg.RedactSensitive = strings.ToLower(strings.TrimSpace(cfg.RedactSensitive))
	cfg.PerfProfile = strings.ToLower(strings.TrimSpace(cfg.PerfProfile))
	cfg.SensitiveEngine = strings.ToLower(strings.TrimSpace(cfg.SensitiveEngine))
	cfg.SensitiveLongtail = strings.ToLower(strings.TrimSpace(cfg.SensitiveLongtail))
	cfg.ContentReadMode = strings.ToLower(strings.TrimSpace(cfg.ContentReadMode))
	cfg.JSONLayout = strings.ToLower(strings.TrimSpace(cfg.JSONLayout))
	if cfg.RedactSensitive == "none" {
		cfg.RedactSensitive = ""
	}
	if cfg.PerfProfile == "" {
		cfg.PerfProfile = "adaptive"
	}
	if cfg.SensitiveEngine == "" {
		cfg.SensitiveEngine = "auto"
	}
	if cfg.SensitiveLongtail == "" {
		cfg.SensitiveLongtail = "sampled"
	}
	if cfg.ContentReadMode == "" {
		cfg.ContentReadMode = "auto"
	}
	if cfg.SensitiveWindowBytes <= 0 {
		cfg.SensitiveWindowBytes = 4096
	}
	if cfg.StreamChunkSize <= 0 {
		cfg.StreamChunkSize = 256 * 1024
	}
	if cfg.StreamOverlapBytes < 0 {
		cfg.StreamOverlapBytes = 512
	}
	if cfg.MmapMinSize <= 0 {
		cfg.MmapMinSize = 128 * 1024
	}
	if cfg.JSONLayout == "" {
		cfg.JSONLayout = "ndjson"
	}
	if cfg.DiagDir == "" {
		cfg.DiagDir = "."
	}
	cfg.FuzzyAlgorithms = normalizeAlgorithms(cfg.FuzzyAlgorithms)
	if cfg.FuzzyHash && len(cfg.FuzzyAlgorithms) == 0 {
		cfg.FuzzyAlgorithms = []string{"tlsh"}
	}
	if len(cfg.FuzzyAlgorithms) > 0 {
		cfg.FuzzyHash = true
	}
	if cfg.FuzzyMaxSize > 0 && cfg.FuzzyMaxSize < cfg.FuzzyMinSize {
		cfg.FuzzyMaxSize = cfg.FuzzyMinSize
	}
	if !containsString(cfg.HashAlgorithms, "sha256") {
		cfg.HashAlgorithms = append(cfg.HashAlgorithms, "sha256")
	}
	if cfg.TraceFlight && cfg.TraceFlightFile == "" {
		cfg.TraceFlightFile = "trace-flight.out"
	}
	if len(cfg.StartPaths) == 0 {
		cfg.StartPaths = []string{"."}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func displayHelp() {
	fmt.Println("Safnari - Advanced Cybersecurity Scanner")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  safnari [options]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  safnari --path \"/tmp\"")
	fmt.Println("  safnari --path \"/home,/var\"")
	fmt.Println("  safnari --all-drives --scan-files=false --scan-processes=true")
}

func (cfg *Config) loadFromFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config file: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid config file format: %v", err)
	}
	if _, ok := raw["concurrency_level"]; ok {
		cfg.ConcurrencySet = true
	}
	if _, ok := raw["max_io_per_second"]; ok {
		cfg.MaxIOSet = true
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return fmt.Errorf("invalid config file format: %v", err)
	}
	return nil
}

func (cfg *Config) validate() error {
	if strings.TrimSpace(cfg.PerfProfile) == "" {
		cfg.PerfProfile = "adaptive"
	}
	if strings.TrimSpace(cfg.SensitiveEngine) == "" {
		cfg.SensitiveEngine = "auto"
	}
	if strings.TrimSpace(cfg.SensitiveLongtail) == "" {
		cfg.SensitiveLongtail = "sampled"
	}
	if strings.TrimSpace(cfg.ContentReadMode) == "" {
		cfg.ContentReadMode = "auto"
	}
	if strings.TrimSpace(cfg.JSONLayout) == "" {
		cfg.JSONLayout = "ndjson"
	}
	if cfg.SensitiveWindowBytes <= 0 {
		cfg.SensitiveWindowBytes = 4096
	}
	if cfg.StreamChunkSize <= 0 {
		cfg.StreamChunkSize = 256 * 1024
	}
	if cfg.StreamOverlapBytes < 0 {
		cfg.StreamOverlapBytes = 512
	}
	if strings.TrimSpace(cfg.DiagDir) == "" {
		cfg.DiagDir = "."
	}

	if !cfg.ScanFiles && !cfg.ScanProcesses && !cfg.ScanSensitive && !cfg.CollectSystemInfo {
		return fmt.Errorf("at least one of --collect-system-info, --scan-files, --scan-sensitive, or --scan-processes must be enabled")
	}
	if len(cfg.StartPaths) == 0 && !cfg.AllDrives && (cfg.ScanFiles || cfg.ScanSensitive) {
		return fmt.Errorf("either start path(s) or --all-drives must be specified for file or sensitive scanning")
	}
	if cfg.AllDrives && runtime.GOOS != "windows" {
		return fmt.Errorf("--all-drives flag is only supported on Windows")
	}
	if cfg.OutputFormat != "json" {
		return fmt.Errorf("invalid output format: %s (only json is supported)", cfg.OutputFormat)
	}
	if cfg.RedactSensitive != "" && cfg.RedactSensitive != "mask" && cfg.RedactSensitive != "hash" {
		return fmt.Errorf("invalid redact-sensitive value: %s", cfg.RedactSensitive)
	}
	if cfg.FuzzyMinSize < 0 || cfg.FuzzyMaxSize < 0 {
		return fmt.Errorf("fuzzy size limits must be zero or positive")
	}
	if cfg.AutoTune {
		if cfg.AutoTuneInterval <= 0 {
			return fmt.Errorf("auto-tune-interval must be positive")
		}
		if cfg.AutoTuneTargetCPU <= 0 || cfg.AutoTuneTargetCPU > 100 {
			return fmt.Errorf("auto-tune-target-cpu must be between 1 and 100")
		}
		if cfg.AutoTuneTargetRunQ <= 0 {
			return fmt.Errorf("auto-tune-target-runq must be positive")
		}
		if cfg.AutoTuneTargetLatencyMs <= 0 {
			return fmt.Errorf("auto-tune-target-latency-ms must be positive")
		}
	}
	if cfg.PerfProfile != "adaptive" && cfg.PerfProfile != "ultra" {
		return fmt.Errorf("invalid perf-profile value: %s", cfg.PerfProfile)
	}
	if cfg.SensitiveEngine != "auto" && cfg.SensitiveEngine != "deterministic" && cfg.SensitiveEngine != "hybrid" {
		return fmt.Errorf("invalid sensitive-engine value: %s", cfg.SensitiveEngine)
	}
	if cfg.SensitiveLongtail != "off" && cfg.SensitiveLongtail != "sampled" && cfg.SensitiveLongtail != "full" {
		return fmt.Errorf("invalid sensitive-longtail value: %s", cfg.SensitiveLongtail)
	}
	if cfg.ContentReadMode != "stream" && cfg.ContentReadMode != "mmap" && cfg.ContentReadMode != "auto" {
		return fmt.Errorf("invalid content-read-mode value: %s", cfg.ContentReadMode)
	}
	if cfg.JSONLayout != "ndjson" {
		return fmt.Errorf("invalid json-layout value: %s", cfg.JSONLayout)
	}
	if cfg.MmapMinSize < 0 {
		return fmt.Errorf("mmap-min-size must be zero or positive")
	}
	if cfg.StreamChunkSize <= 0 {
		return fmt.Errorf("stream-chunk-size must be positive")
	}
	if cfg.StreamOverlapBytes < 0 {
		return fmt.Errorf("stream-overlap-bytes must be zero or positive")
	}
	if cfg.StreamOverlapBytes >= cfg.StreamChunkSize {
		return fmt.Errorf("stream-overlap-bytes must be smaller than stream-chunk-size")
	}
	if cfg.SensitiveWindowBytes <= 0 {
		return fmt.Errorf("sensitive-window-bytes must be positive")
	}
	if cfg.DiagSlowScanThreshold < 0 {
		return fmt.Errorf("diag-slow-scan-threshold must be zero or positive")
	}
	if cfg.XattrMaxValueSize < 0 {
		return fmt.Errorf("xattr-max-value-size must be zero or positive")
	}
	if cfg.TraceFlightMinAge < 0 {
		return fmt.Errorf("trace-flight-min-age must be zero or positive")
	}
	if cfg.OtelTimeout < 0 {
		return fmt.Errorf("otel-timeout must be zero or positive")
	}
	if cfg.OtelEndpoint != "" {
		if !strings.HasPrefix(cfg.OtelEndpoint, "http://") && !strings.HasPrefix(cfg.OtelEndpoint, "https://") {
			return fmt.Errorf("otel-endpoint must include scheme (http or https)")
		}
	}
	if cfg.MaxIOPerSecond < 0 {
		return fmt.Errorf("max-io-per-second must be zero or positive")
	}
	if cfg.SensitiveMaxPerType < 0 {
		return fmt.Errorf("sensitive-max-matches-per-type must be zero or positive")
	}
	if cfg.SensitiveMaxTotal < 0 {
		return fmt.Errorf("sensitive-max-total-matches must be zero or positive")
	}
	if cfg.MetadataMaxBytes < 0 {
		return fmt.Errorf("metadata-max-bytes must be zero or positive")
	}
	if cfg.ConcurrencyLevel <= 0 {
		return fmt.Errorf("concurrency level must be positive")
	}
	if cfg.NiceLevel != "high" && cfg.NiceLevel != "medium" && cfg.NiceLevel != "low" {
		return fmt.Errorf("invalid nice level: %s", cfg.NiceLevel)
	}
	if cfg.LogLevel != "debug" && cfg.LogLevel != "info" && cfg.LogLevel != "warn" &&
		cfg.LogLevel != "error" && cfg.LogLevel != "fatal" && cfg.LogLevel != "panic" {
		return fmt.Errorf("invalid log level: %s", cfg.LogLevel)
	}
	if cfg.DeltaScan && cfg.LastScanFile == "" && cfg.LastScanTime == "" {
		return fmt.Errorf("either last scan file or last scan time must be specified when delta scanning is enabled")
	}
	if cfg.LastScanTime != "" {
		if _, err := time.Parse(time.RFC3339, cfg.LastScanTime); err != nil {
			return fmt.Errorf("invalid last scan time format: %v", err)
		}
	}
	return nil
}

func parseCommaSeparated(input string) []string {
	if input == "" {
		return []string{}
	}
	items := strings.Split(input, ",")
	for i, item := range items {
		items[i] = strings.TrimSpace(item)
	}
	return items
}

func parseCustomPatterns(input string) map[string]string {
	patterns := make(map[string]string)
	if input == "" {
		return patterns
	}
	if err := json.Unmarshal([]byte(input), &patterns); err != nil {
		fmt.Fprintf(os.Stderr, "invalid custom patterns: %v\n", err)
		return map[string]string{}
	}
	return patterns
}

func parseHeaders(input string) map[string]string {
	headers := make(map[string]string)
	if input == "" {
		return headers
	}
	items := strings.Split(input, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		headers[key] = value
	}
	return headers
}

func normalizeAlgorithms(items []string) []string {
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
