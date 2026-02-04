package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/scanner"
	"safnari/systeminfo"
	"safnari/tracing"
	"safnari/update"
	"safnari/version"
)

func main() {
	if err := tracing.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start trace: %v\n", err)
	} else {
		defer tracing.Stop()
	}

	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger.Init(cfg.LogLevel)

	if cfg.ScanSensitive && cfg.RedactSensitive == "" {
		logger.Warn("Sensitive data matches will be stored unredacted. Consider --redact-sensitive mask or hash.")
	}

	if cfg.TraceFlight {
		if err := tracing.StartFlightRecorder(cfg.TraceFlightMaxBytes, cfg.TraceFlightMinAge); err != nil {
			logger.Warnf("Failed to start flight recorder: %v", err)
		} else {
			defer func() {
				if err := tracing.WriteFlightRecorder(cfg.TraceFlightFile); err != nil {
					logger.Warnf("Failed to write flight recorder: %v", err)
				}
				tracing.StopFlightRecorder()
			}()
		}
	}

	if latest, notes, newer, err := update.CheckForUpdate(version.Version); err == nil && newer {
		if strings.Contains(strings.ToLower(notes), "security") {
			logger.Warnf("Update available: %s -> %s (security fixes included)", version.Version, latest)
		} else {
			logger.Infof("Update available: %s -> %s", version.Version, latest)
		}
	}

	// Record start time
	startTime := time.Now()

	// Prepare metrics
	metrics := output.Metrics{
		StartTime: startTime.Format(time.RFC3339),
	}

	// Gather system information if requested
	var sysInfo *systeminfo.SystemInfo
	if cfg.CollectSystemInfo || cfg.ScanProcesses {
		sysInfo, err = systeminfo.GetSystemInfo(cfg)
		if err != nil {
			logger.Errorf("Failed to gather system information: %v", err)
		}
	}

	// Prepare output
	writer, err := output.New(cfg, sysInfo, &metrics)
	if err != nil {
		logger.Fatalf("Failed to initialize output: %v", err)
	}
	defer writer.Close()

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	go handleSignals(cancel, &metrics, writer, cfg.TraceFlight, cfg.TraceFlightFile)

	// Start scanning
	if cfg.ScanFiles || cfg.ScanSensitive {
		err = scanner.ScanFiles(ctx, cfg, &metrics, writer)
		if err != nil {
			logger.Fatalf("Scanning failed: %v", err)
		}
	}

	// Record end time
	metrics.EndTime = time.Now().Format(time.RFC3339)

	// Update output with final metrics
	writer.SetMetrics(metrics)

	logger.Info("Scanning completed successfully.")
}

func handleSignals(cancelFunc context.CancelFunc, metrics *output.Metrics, w *output.Writer, traceFlight bool, traceFlightFile string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	logger.Info("Interrupt signal received. Shutting down...")

	// Record end time upon interruption
	metrics.EndTime = time.Now().Format(time.RFC3339)
	w.SetMetrics(*metrics)

	if traceFlight {
		if err := tracing.WriteFlightRecorder(traceFlightFile); err != nil {
			logger.Warnf("Failed to write flight recorder: %v", err)
		}
		tracing.StopFlightRecorder()
	}

	cancelFunc()
}
