package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/utils"

	"golang.org/x/time/rate"
)

type fileScanTask struct {
	path         string
	info         os.FileInfo
	rootCache    *directoryRootCache
	relativePath string
}

func ScanFiles(ctx context.Context, cfg *config.Config, metrics *output.Metrics, w *output.Writer) error {
	if err := PrepareConfig(cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var lastScanTime time.Time
	if cfg.LastScanTime != "" {
		t, err := time.Parse(time.RFC3339, cfg.LastScanTime)
		if err == nil {
			lastScanTime = t
		} else {
			logger.Warnf("Invalid last scan time: %v", err)
		}
	} else if cfg.DeltaScan && cfg.LastScanFile != "" {
		data, err := readFileNoSymlink(cfg.LastScanFile)
		if err == nil {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
			if err == nil {
				lastScanTime = t
			}
		}
	}
	// If cfg.AllDrives is true, get all local drives

	totalFiles := 0

	matcher := utils.NewPatternMatcher(cfg.IncludePatterns, cfg.ExcludePatterns)
	artifactFilter := newInternalArtifactFilter(cfg)

	if cfg.SkipCount {
		logger.Info("Skipping total file count")
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

	}

	var wg sync.WaitGroup

	// Prepare sensitive data patterns
	sensitivePatterns := GetPatterns(cfg.IncludeDataTypes, cfg.CustomPatterns, cfg.ExcludeDataTypes)
	fileModules := buildFileModules(cfg, sensitivePatterns)
	deltaCache, err := openDeltaChunkCache(cfg)
	if err != nil {
		return err
	}
	if deltaCache != nil {
		defer deltaCache.Close()
	}

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
	scheduler := newSizeLaneScheduler(maxInt(cfg.ConcurrencyLevel*8, 64))
	var processedCounter atomic.Int64
	progressDone := make(chan struct{})
	if progressVisible() {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					logger.Infof("Files processed: %d", processedCounter.Load())
				case <-progressDone:
					return
				}
			}
		}()
	}
	defer close(progressDone)
	if cfg.AutoTune {
		startAutoTuneLoop(
			ctx,
			cfg,
			ioLimiter,
			tuneState,
			autoTuneTelemetry{
				queueDepthFn: func() int {
					return scheduler.Depth()
				},
				queueCapacityFn: func() int {
					return scheduler.Capacity()
				},
				processedCountFn: func() int64 {
					return processedCounter.Load()
				},
			},
		)
	}

	selectedWalker := selectWalker(cfg)
	useRootedOpens := runtime.GOOS != "windows" && !cfg.CollectXattrs && !cfg.CollectACL && !cfg.ScanADS
	rootCaches := make(map[string]*directoryRootCache, len(cfg.StartPaths))
	if useRootedOpens {
		for _, startPath := range cfg.StartPaths {
			if rootCaches[startPath] != nil {
				continue
			}
			info, err := os.Lstat(startPath)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			root, err := os.OpenRoot(startPath)
			if err != nil {
				continue
			}
			openedInfo, err := root.Stat(".")
			if err != nil || !os.SameFile(info, openedInfo) {
				_ = root.Close()
				continue
			}
			rootCaches[startPath] = newDirectoryRootCache(root)
		}
	}
	defer func() {
		for _, cache := range rootCaches {
			cache.Close()
		}
	}()
	go scheduler.Run(ctx, filesChan)

	// Start the file walking in a separate goroutine
	go func() {
		defer scheduler.Close()
		for _, startPath := range cfg.StartPaths {
			rootCache := rootCaches[startPath]
			err := selectedWalker.Walk(ctx, startPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					logger.Warnf("Failed to access %s: %v", path, err)
					return nil
				}
				if d == nil {
					return nil
				}

				if d.IsDir() {
					if artifactFilter.ShouldSkip(path) {
						return fs.SkipDir
					}
					return nil
				}
				if artifactFilter.ShouldSkip(path) {
					return nil
				}
				// Apply include/exclude filters
				if matcher.ShouldInclude(path) {
					info, err := d.Info()
					if err == nil {
						if cfg.DeltaScan && info.ModTime().Before(lastScanTime) {
							return nil
						}
					}
					task := fileScanTask{path: path, info: info}
					if rootCache != nil && info != nil {
						rel, relErr := filepath.Rel(startPath, path)
						if relErr == nil {
							task.rootCache = rootCache
							task.relativePath = rel
						}
					}
					if err := scheduler.Enqueue(ctx, task, cfg); err != nil {
						return err
					}
					// Wait for permission from the limiter
					if ioLimiter != nil {
						if err := ioLimiter.Wait(ctx); err != nil {
							return err
						}
					}
				}
				return nil
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warnf("Error walking path %s: %v", startPath, err)
			}
		}
	}()

	// Start worker pool
	var firstErr error
	var firstErrOnce sync.Once
	setScanError := func(err error) {
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}
		firstErrOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

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
				if err := processFileWithRootCache(ctx, task.path, task.info, cfg, w, sensitivePatterns, fileModules, deltaCache, task.rootCache == nil, task.rootCache, task.relativePath); err != nil {
					setScanError(err)
					return
				}
				processedCounter.Add(1)
			}
		}()
	}

	wg.Wait()
	if err := w.WaitIdle(); err != nil {
		return err
	}
	metrics.FilesScanned = w.FilesScanned()
	metrics.FilesProcessed = w.FilesProcessed()
	if cfg.SkipCount {
		metrics.TotalFiles = metrics.FilesScanned
	}
	if firstErr != nil {
		return firstErr
	}
	if cfg.DeltaScan && cfg.LastScanFile != "" {
		if err := writePrivateFileNoSymlink(cfg.LastScanFile, []byte(time.Now().UTC().Format(time.RFC3339))); err != nil {
			logger.Warnf("Failed to write last scan time: %v", err)
		}
	}
	return nil
}

// PrepareConfig resolves the effective scan coverage before the output writer
// calculates the policy digest. It is safe to call twice for direct API users.
func PrepareConfig(cfg *config.Config) error {
	applyPerformanceProfile(cfg)
	if cfg.AllDrives {
		drives, err := utils.GetLocalDrives()
		if err != nil {
			return err
		}
		cfg.StartPaths = drives
		cfg.AllDrives = false
	}
	return nil
}

func countTotalFiles(ctx context.Context, startPath string, cfg *config.Config, lastScanTime time.Time, matcher *utils.PatternMatcher) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var total int
	selectedWalker := selectWalker(cfg)
	artifactFilter := newInternalArtifactFilter(cfg)
	err := selectedWalker.Walk(ctx, startPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Warnf("Failed to access %s: %v", path, err)
			return nil
		}
		if d == nil {
			return nil
		}
		if d.IsDir() && artifactFilter.ShouldSkip(path) {
			return fs.SkipDir
		}
		if !d.IsDir() && artifactFilter.ShouldSkip(path) {
			return nil
		}
		if !d.IsDir() && matcher.ShouldInclude(path) {
			info, err := d.Info()
			if err == nil {
				if cfg.DeltaScan && info.ModTime().Before(lastScanTime) {
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
