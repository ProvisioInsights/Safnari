package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/output"
	"safnari/systeminfo"
)

func TestHandleSignalEventCancelsContextAndSetsMetrics(t *testing.T) {
	logger.Init("error")

	outFile, err := os.CreateTemp("", "cmd-signal-*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	outFile.Close()
	defer os.Remove(outFile.Name())

	cfg := &config.Config{OutputFileName: outFile.Name()}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &output.Metrics{StartTime: time.Now().UTC().Format(time.RFC3339)}
	w, err := output.New(cfg, sysInfo, metrics)
	if err != nil {
		t.Fatalf("output init: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)

	done := make(chan struct{})
	go func() {
		handleSignalEvent(cancel, metrics, w, false, "", sigChan)
		close(done)
	}()

	sigChan <- syscall.SIGTERM

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected context to be canceled")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("signal handler did not return")
	}

	if metrics.EndTime == "" {
		t.Fatal("expected EndTime to be set")
	}
	if _, err := time.Parse(time.RFC3339, metrics.EndTime); err != nil {
		t.Fatalf("invalid EndTime format: %v", err)
	}
}
