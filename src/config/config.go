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
	StartPaths          []string          `json:"start_paths"`
	AllDrives           bool              `json:"all_drives"`
	ScanFiles           bool              `json:"scan_files"`
	ScanProcesses       bool              `json:"scan_processes"`
	OutputFormat        string            `json:"output_format"`
	OutputFileName      string            `json:"output_file_name"`
	ConcurrencyLevel    int               `json:"concurrency_level"`
	NiceLevel           string            `json:"nice_level"`
	HashAlgorithms      []string          `json:"hash_algorithms"`
	SearchTerms         []string          `json:"search_terms"`
	IncludePatterns     []string          `json:"include_patterns"`
	ExcludePatterns     []string          `json:"exclude_patterns"`
	MaxFileSize         int64             `json:"max_file_size"`
	MaxOutputFileSize   int64             `json:"max_output_file_size"`
	LogLevel            string            `json:"log_level"`
	MaxIOPerSecond      int               `json:"max_io_per_second"`
	ConfigFile          string            `json:"config_file"`
	ExtendedProcessInfo bool              `json:"extended_process_info"`
	IncludeDataTypes    []string          `json:"include_sensitive_data_types"`
	ExcludeDataTypes    []string          `json:"exclude_sensitive_data_types"`
	CustomPatterns      map[string]string `json:"custom_patterns"`
	FuzzyHash           bool              `json:"fuzzy_hash"`
	DeltaScan           bool              `json:"delta_scan"`
	LastScanFile        string            `json:"last_scan_file"`
	LastScanTime        string            `json:"last_scan_time"`
	SkipCount           bool              `json:"skip_count"`
}

func LoadConfig() (*Config, error) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102-150405")
	cfg := &Config{
		StartPaths:        []string{"."},
		ScanFiles:         true,
		ScanProcesses:     true,
		OutputFormat:      "json",
		OutputFileName:    fmt.Sprintf("safnari-%s-%d.json", timestamp, now.Unix()),
		ConcurrencyLevel:  runtime.NumCPU(),
		NiceLevel:         "medium",
		HashAlgorithms:    []string{"md5", "sha1", "sha256"},
		SearchTerms:       []string{},
		MaxFileSize:       10485760,
		MaxOutputFileSize: 104857600,
		LogLevel:          "info",
		MaxIOPerSecond:    1000,
		IncludeDataTypes:  []string{},
		ExcludeDataTypes:  []string{},
		CustomPatterns:    map[string]string{},
		DeltaScan:         false,
		LastScanFile:      ".safnari_last_scan",
		SkipCount:         false,
	}

	startPath := flag.String("path", strings.Join(cfg.StartPaths, ","), fmt.Sprintf("Comma-separated list of start paths to scan (default: %s).", strings.Join(cfg.StartPaths, ",")))
	allDrives := flag.Bool("all-drives", cfg.AllDrives, fmt.Sprintf("Scan all local drives (Windows only) (default: %t).", cfg.AllDrives))
	scanFiles := flag.Bool("scan-files", cfg.ScanFiles, fmt.Sprintf("Enable file scanning (default: %t).", cfg.ScanFiles))
	scanProcesses := flag.Bool("scan-processes", cfg.ScanProcesses, fmt.Sprintf("Enable process scanning (default: %t).", cfg.ScanProcesses))
	format := flag.String("format", cfg.OutputFormat, fmt.Sprintf("Output format: json or csv (default: %s).", cfg.OutputFormat))
	output := flag.String("output", cfg.OutputFileName, "Output file name (default: safnari-<timestamp>-<unix>.json).")
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
	configFile := flag.String("config", "", "Path to JSON configuration file (default: none).")
	extendedProcessInfo := flag.Bool("extended-process-info", cfg.ExtendedProcessInfo, fmt.Sprintf("Gather extended process information (requires elevated privileges) (default: %t).", cfg.ExtendedProcessInfo))
	includeDataTypes := flag.String("include-sensitive-data-types", "", "Comma-separated list of sensitive data types to include when scanning (default: none). Use 'all' to include all built-in types.")
	excludeDataTypes := flag.String("exclude-sensitive-data-types", "", "Comma-separated list of sensitive data types to exclude when scanning.")
	customPatterns := flag.String("custom-patterns", "", "Custom sensitive data patterns as a JSON object mapping names to regexes")
	fuzzyHash := flag.Bool("fuzzy-hash", cfg.FuzzyHash, fmt.Sprintf("Enable fuzzy hashing (ssdeep) (default: %t).", cfg.FuzzyHash))
	deltaScan := flag.Bool("delta-scan", cfg.DeltaScan, fmt.Sprintf("Only scan files modified since the last run (default: %t).", cfg.DeltaScan))
	lastScanFile := flag.String("last-scan-file", cfg.LastScanFile, fmt.Sprintf("Path to timestamp file for delta scans (default: %s).", cfg.LastScanFile))
	lastScanTime := flag.String("last-scan", cfg.LastScanTime, "Timestamp of last scan in RFC3339 format (default: none).")
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
		case "scan-processes":
			cfg.ScanProcesses = *scanProcesses
		case "format":
			cfg.OutputFormat = *format
		case "output":
			cfg.OutputFileName = *output
		case "concurrency":
			cfg.ConcurrencyLevel = *concurrency
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
		case "delta-scan":
			cfg.DeltaScan = *deltaScan
		case "last-scan-file":
			cfg.LastScanFile = *lastScanFile
		case "last-scan":
			cfg.LastScanTime = *lastScanTime
		case "skip-count":
			cfg.SkipCount = *skipCount
		}
	})

	if cfg.FuzzyHash {
		found := false
		for _, algo := range cfg.HashAlgorithms {
			if algo == "ssdeep" {
				found = true
				break
			}
		}
		if !found {
			cfg.HashAlgorithms = append(cfg.HashAlgorithms, "ssdeep")
		}
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
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return fmt.Errorf("invalid config file format: %v", err)
	}
	return nil
}

func (cfg *Config) validate() error {
	if !cfg.ScanFiles && !cfg.ScanProcesses {
		return fmt.Errorf("at least one of --scan-files or --scan-processes must be enabled")
	}
	if len(cfg.StartPaths) == 0 && !cfg.AllDrives && cfg.ScanFiles {
		return fmt.Errorf("either start path(s) or --all-drives must be specified for file scanning")
	}
	if cfg.AllDrives && runtime.GOOS != "windows" {
		return fmt.Errorf("--all-drives flag is only supported on Windows")
	}
	if cfg.OutputFormat != "json" && cfg.OutputFormat != "csv" {
		return fmt.Errorf("invalid output format: %s", cfg.OutputFormat)
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
