//go:build !trace

package tracing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTraceStubNoOps(t *testing.T) {
	if err := Start(); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	Stop()

	ctx, endTask := StartTask(context.Background(), "unit-test-task")
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	endTask()

	endRegion := StartRegion(ctx, "unit-test-region")
	endRegion()

	Log(ctx, "category", "message")
}

func TestWriteFlightRecorderWithoutStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flight.out")
	if err := WriteFlightRecorder(path); err != nil {
		t.Fatalf("WriteFlightRecorder() returned error without recorder: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("expected no file to be written when recorder is disabled")
	}
}
