package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/scanner"
	"safnari/systeminfo"
	"safnari/tracing"
)

func main() {
	if err := tracing.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start trace: %v\n", err)
	}
	defer tracing.Stop()

	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger.Init(cfg.LogLevel)

	// Record start time
	startTime := time.Now()

	// Prepare metrics
	metrics := output.Metrics{
		StartTime: startTime.Format(time.RFC3339),
	}

	// Gather system information
	sysInfo, err := systeminfo.GetSystemInfo(cfg)
	if err != nil {
		logger.Errorf("Failed to gather system information: %v", err)
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

	go handleSignals(cancel, &metrics, writer)

	// Start scanning
	err = scanner.ScanFiles(ctx, cfg, &metrics, writer)
	if err != nil {
		logger.Fatalf("Scanning failed: %v", err)
	}

	// Record end time
	metrics.EndTime = time.Now().Format(time.RFC3339)

	// Update output with final metrics
	writer.SetMetrics(metrics)

	logger.Info("Scanning completed successfully.")
}

func handleSignals(cancelFunc context.CancelFunc, metrics *output.Metrics, w *output.Writer) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	logger.Info("Interrupt signal received. Shutting down...")

	// Record end time upon interruption
	metrics.EndTime = time.Now().Format(time.RFC3339)
	w.SetMetrics(*metrics)

	cancelFunc()
}
