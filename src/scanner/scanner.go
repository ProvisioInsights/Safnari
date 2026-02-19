package scanner

import (
	"context"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/scanner/prefilter"
	"safnari/utils"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

type fileScanTask struct {
	path string
	info os.FileInfo
}

func ScanFiles(ctx context.Context, cfg *config.Config, metrics *output.Metrics, w *output.Writer) error {
	applyPerformanceProfile(cfg)

	var lastScanTime time.Time
	if cfg.LastScanTime != "" {
		t, err := time.Parse(time.RFC3339, cfg.LastScanTime)
		if err == nil {
			lastScanTime = t
		} else {
			logger.Warnf("Invalid last scan time: %v", err)
		}
	} else if cfg.DeltaScan && cfg.LastScanFile != "" {
		data, err := os.ReadFile(cfg.LastScanFile)
		if err == nil {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
			if err == nil {
				lastScanTime = t
			}
		}
	}
	// If cfg.AllDrives is true, get all local drives
	if cfg.AllDrives {
		drives, err := utils.GetLocalDrives()
		if err != nil {
			return err
		}
		cfg.StartPaths = drives
	}

	totalFiles := 0
	var bar *progressbar.ProgressBar

	matcher := utils.NewPatternMatcher(cfg.IncludePatterns, cfg.ExcludePatterns)
	setSIMDFastpathEnabled(cfg.SimdFastpath)
	prefilter.SetSIMDFastpath(cfg.SimdFastpath)

	if cfg.SkipCount {
		logger.Info("Skipping total file count")
		bar = progressbar.NewOptions(-1,
			progressbar.OptionSetDescription("Scanning files"),
			progressbar.OptionShowCount(),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionSetVisibility(progressVisible()),
			progressbar.OptionFullWidth(),
		)
	} else {
		// Display message about initial file count
		logger.Info("Counting total number of files...")
		for _, startPath := range cfg.StartPaths {
			count, err := countTotalFiles(ctx, startPath, cfg, lastScanTime, matcher)
			if err != nil {
				logger.Warnf("Failed to count files in %s: %v", startPath, err)
				continue
			}
			totalFiles += count
		}
		logger.Infof("Total files to scan: %d", totalFiles)

		// Update metrics with total file count
		metrics.TotalFiles = totalFiles

		bar = progressbar.NewOptions(totalFiles,
			progressbar.OptionSetDescription("Scanning files"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionSetVisibility(progressVisible()),
			progressbar.OptionFullWidth(),
		)
	}

	var wg sync.WaitGroup
	progressCh := make(chan int, maxInt(cfg.ConcurrencyLevel*4, 64))
	var progressWG sync.WaitGroup
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		for delta := range progressCh {
			_ = bar.Add(delta)
		}
	}()

	// Prepare sensitive data patterns
	sensitivePatterns := GetPatterns(cfg.IncludeDataTypes, cfg.CustomPatterns, cfg.ExcludeDataTypes)
	fileModules := buildFileModules(cfg, sensitivePatterns)

	// Implement I/O rate limiter
	var ioLimiter *rate.Limiter
	if cfg.MaxIOPerSecond > 0 {
		ioLimiter = rate.NewLimiter(rate.Limit(cfg.MaxIOPerSecond), cfg.MaxIOPerSecond)
	} else if cfg.AutoTune && !cfg.MaxIOSet {
		ioLimiter = rate.NewLimiter(rate.Inf, 1)
	}

	var tuneState *autoTuneState
	if cfg.AutoTune {
		tuneState = applyAutoTune(cfg, ioLimiter)
	} else {
		adjustConcurrency(cfg)
	}

	filesChan := make(chan fileScanTask, cfg.ConcurrencyLevel)
	var processedCounter atomic.Int64
	if cfg.AutoTune {
		startAutoTuneLoop(
			ctx,
			cfg,
			ioLimiter,
			tuneState,
			autoTuneTelemetry{
				queueDepthFn: func() int {
					return len(filesChan)
				},
				queueCapacityFn: func() int {
					return cap(filesChan)
				},
				processedCountFn: func() int64 {
					return processedCounter.Load()
				},
			},
		)
	}

	selectedWalker := selectWalker(cfg)

	// Start the file walking in a separate goroutine
	go func() {
		defer close(filesChan)
		for _, startPath := range cfg.StartPaths {
			err := selectedWalker.Walk(ctx, startPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					logger.Warnf("Failed to access %s: %v", path, err)
					return nil
				}
				if d == nil {
					return nil
				}

				if d.IsDir() {
					return nil
				}
				// Apply include/exclude filters
				if matcher.ShouldInclude(path) {
					info, err := d.Info()
					if err == nil {
						if cfg.DeltaScan && info.ModTime().Before(lastScanTime) {
							return nil
						}
						if cfg.MaxFileSize > 0 && info.Size() > cfg.MaxFileSize {
							return nil
						}
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case filesChan <- fileScanTask{path: path, info: info}:
						// Wait for permission from the limiter
						if ioLimiter != nil {
							if err := ioLimiter.Wait(ctx); err != nil {
								return err
							}
						}
					}
				}
				return nil
			})
			if err != nil {
				logger.Warnf("Error walking path %s: %v", startPath, err)
			}
		}
	}()

	// Start worker pool
	for range cfg.ConcurrencyLevel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range filesChan {
				select {
				case <-ctx.Done():
					return
				default:
					// Continue processing
				}
				processFile(ctx, task.path, task.info, cfg, w, sensitivePatterns, fileModules, false)
				processedCounter.Add(1)
				progressCh <- 1
			}
		}()
	}

	wg.Wait()
	close(progressCh)
	progressWG.Wait()
	metrics.FilesScanned = w.FilesScanned()
	metrics.FilesProcessed = w.FilesProcessed()
	if cfg.SkipCount {
		metrics.TotalFiles = metrics.FilesScanned
	}
	if cfg.DeltaScan && cfg.LastScanFile != "" {
		if err := os.WriteFile(cfg.LastScanFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
			logger.Warnf("Failed to write last scan time: %v", err)
		}
	}
	return nil
}

func countTotalFiles(ctx context.Context, startPath string, cfg *config.Config, lastScanTime time.Time, matcher *utils.PatternMatcher) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var total int
	selectedWalker := selectWalker(cfg)
	err := selectedWalker.Walk(ctx, startPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Warnf("Failed to access %s: %v", path, err)
			return nil
		}
		if d == nil {
			return nil
		}
		if !d.IsDir() && matcher.ShouldInclude(path) {
			info, err := d.Info()
			if err == nil {
				if cfg.DeltaScan && info.ModTime().Before(lastScanTime) {
					return nil
				}
				if cfg.MaxFileSize > 0 && info.Size() > cfg.MaxFileSize {
					return nil
				}
			}
			total++
		}
		return nil
	})
	return total, err
}

func adjustConcurrency(cfg *config.Config) {
	if cfg.ConcurrencySet {
		return
	}
	numCPU := runtime.NumCPU()
	switch cfg.NiceLevel {
	case "high":
		cfg.ConcurrencyLevel = numCPU
	case "medium":
		cfg.ConcurrencyLevel = numCPU / 2
		if cfg.ConcurrencyLevel < 1 {
			cfg.ConcurrencyLevel = 1
		}
	case "low":
		cfg.ConcurrencyLevel = 1
	}
}

func progressVisible() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("SAFNARI_DISABLE_PROGRESS")))
	return value != "1" && value != "true" && value != "yes" && value != "on"
}
