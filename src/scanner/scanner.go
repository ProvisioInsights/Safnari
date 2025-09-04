package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/utils"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func ScanFiles(ctx context.Context, cfg *config.Config, metrics *output.Metrics, w *output.Writer) error {
	// If cfg.AllDrives is true, get all local drives
	if cfg.AllDrives {
		drives, err := utils.GetLocalDrives()
		if err != nil {
			return err
		}
		cfg.StartPaths = drives
	}

	// Display message about initial file count
	logger.Info("Counting total number of files...")
	totalFiles := 0
	for _, startPath := range cfg.StartPaths {
		count, err := countTotalFiles(startPath, cfg)
		if err != nil {
			logger.Warnf("Failed to count files in %s: %v", startPath, err)
			continue
		}
		totalFiles += count
	}
	logger.Infof("Total files to scan: %d", totalFiles)

	// Update metrics with total file count
	metrics.TotalFiles = totalFiles

	filesChan := make(chan string, cfg.ConcurrencyLevel)
	var wg sync.WaitGroup

	adjustConcurrency(cfg)

	// Prepare sensitive data patterns
	sensitivePatterns := GetPatterns(cfg.SensitiveDataTypes)

	// Initialize progress bar
	bar := progressbar.NewOptions(totalFiles,
		progressbar.OptionSetDescription("Scanning files"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionFullWidth(),
	)

	// Implement I/O rate limiter
	ioLimiter := rate.NewLimiter(rate.Limit(cfg.MaxIOPerSecond), cfg.MaxIOPerSecond)

	// Start the file walking in a separate goroutine
	go func() {
		defer close(filesChan)
		for _, startPath := range cfg.StartPaths {
			err := filepath.WalkDir(startPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					logger.Warnf("Failed to access %s: %v", path, err)
					return nil
				}

				// Apply include/exclude filters
				if utils.ShouldInclude(path, cfg.IncludePatterns, cfg.ExcludePatterns) {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case filesChan <- path:
						// Wait for permission from the limiter
						if err := ioLimiter.Wait(ctx); err != nil {
							return err
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
	for i := 0; i < cfg.ConcurrencyLevel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				select {
				case <-ctx.Done():
					return
				default:
					// Continue processing
				}
				ProcessFile(ctx, filePath, cfg, w, sensitivePatterns)
				bar.Add(1)
			}
		}()
	}

	wg.Wait()
	return nil
}

func countTotalFiles(startPath string, cfg *config.Config) (int, error) {
	var total int
	err := filepath.WalkDir(startPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Warnf("Failed to access %s: %v", path, err)
			return nil
		}
		if !d.IsDir() && utils.ShouldInclude(path, cfg.IncludePatterns, cfg.ExcludePatterns) {
			total++
		}
		return nil
	})
	return total, err
}

func adjustConcurrency(cfg *config.Config) {
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

	// Implement dynamic adjustment (simplified)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Placeholder for dynamic adjustment logic
			}
		}
	}()
}
