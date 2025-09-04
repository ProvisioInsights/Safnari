package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	StartPaths          []string `json:"start_paths"`
	AllDrives           bool     `json:"all_drives"`
	ScanFiles           bool     `json:"scan_files"`
	ScanProcesses       bool     `json:"scan_processes"`
	OutputFormat        string   `json:"output_format"`
	OutputFileName      string   `json:"output_file_name"`
	ConcurrencyLevel    int      `json:"concurrency_level"`
	NiceLevel           string   `json:"nice_level"`
	HashAlgorithms      []string `json:"hash_algorithms"`
	SearchTerms         []string `json:"search_terms"`
	IncludePatterns     []string `json:"include_patterns"`
	ExcludePatterns     []string `json:"exclude_patterns"`
	MaxFileSize         int64    `json:"max_file_size"`
	MaxOutputFileSize   int64    `json:"max_output_file_size"`
	LogLevel            string   `json:"log_level"`
	MaxIOPerSecond      int      `json:"max_io_per_second"`
	ConfigFile          string   `json:"config_file"`
	ExtendedProcessInfo bool     `json:"extended_process_info"`
	SensitiveDataTypes  []string `json:"sensitive_data_types"`
}

func LoadConfig() (*Config, error) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102-150405")
	cfg := &Config{
		StartPaths:         []string{"."},
		ScanFiles:          true,
		ScanProcesses:      true,
		OutputFormat:       "json",
		OutputFileName:     fmt.Sprintf("safnari-%s-%d.json", timestamp, now.Unix()),
		ConcurrencyLevel:   runtime.NumCPU(),
		NiceLevel:          "medium",
		HashAlgorithms:     []string{"md5", "sha1", "sha256"},
		SearchTerms:        []string{},
		MaxFileSize:        10485760,
		MaxOutputFileSize:  104857600,
		LogLevel:           "info",
		MaxIOPerSecond:     1000,
		SensitiveDataTypes: []string{},
	}

	startPath := flag.String("path", strings.Join(cfg.StartPaths, ","), "Start path(s) for scanning (comma-separated)")
	allDrives := flag.Bool("all-drives", cfg.AllDrives, "Scan all local drives (Windows only)")
	scanFiles := flag.Bool("scan-files", cfg.ScanFiles, "Enable or disable file scanning")
	scanProcesses := flag.Bool("scan-processes", cfg.ScanProcesses, "Enable or disable process scanning")
	format := flag.String("format", cfg.OutputFormat, "Output format: json or csv")
	output := flag.String("output", cfg.OutputFileName, "Output file name")
	concurrency := flag.Int("concurrency", cfg.ConcurrencyLevel, "Concurrency level")
	nice := flag.String("nice", cfg.NiceLevel, "Nice level: high, medium, low")
	hashes := flag.String("hashes", strings.Join(cfg.HashAlgorithms, ","), "Hash algorithms to use (comma-separated)")
	searches := flag.String("search", "", "Search terms (comma-separated)")
	includes := flag.String("include", "", "Include patterns (comma-separated)")
	excludes := flag.String("exclude", "", "Exclude patterns (comma-separated)")
	maxFileSize := flag.Int64("max-file-size", cfg.MaxFileSize, "Maximum file size to process (bytes)")
	maxOutputFileSize := flag.Int64("max-output-file-size", cfg.MaxOutputFileSize, "Maximum output file size before rotation (bytes)")
	logLevel := flag.String("log-level", cfg.LogLevel, "Log level: debug, info, warn, error, fatal, panic")
	maxIO := flag.Int("max-io-per-second", cfg.MaxIOPerSecond, "Maximum disk I/O operations per second")
	configFile := flag.String("config", "", "Path to JSON configuration file")
	extendedProcessInfo := flag.Bool("extended-process-info", cfg.ExtendedProcessInfo, "Gather extended process information (requires elevated privileges)")
	sensitiveDataTypes := flag.String("sensitive-data-types", "", "Sensitive data types to scan for (comma-separated)")

	flag.Usage = displayHelp
	flag.Parse()

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
		case "sensitive-data-types":
			cfg.SensitiveDataTypes = parseCommaSeparated(*sensitiveDataTypes)
		}
	})

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
