//go:build !trace

package tracing

import (
	"context"
	"os"
	"runtime/trace"
	"time"
)

var flightRecorder *trace.FlightRecorder

// Start is a no-op when tracing is disabled.
func Start() error {
	return nil
}

// Stop is a no-op when tracing is disabled.
func Stop() {}

// StartTask is a no-op when tracing is disabled.
func StartTask(ctx context.Context, name string) (context.Context, func()) {
	return ctx, func() {}
}

// StartRegion is a no-op when tracing is disabled.
func StartRegion(ctx context.Context, name string) func() {
	return func() {}
}

// Log is a no-op when tracing is disabled.
func Log(ctx context.Context, category, message string) {}

// StartFlightRecorder enables the in-memory flight recorder.
func StartFlightRecorder(maxBytes uint64, minAge time.Duration) error {
	cfg := trace.FlightRecorderConfig{
		MaxBytes: maxBytes,
		MinAge:   minAge,
	}
	flightRecorder = trace.NewFlightRecorder(cfg)
	return flightRecorder.Start()
}

// StopFlightRecorder stops the flight recorder if it is running.
func StopFlightRecorder() {
	if flightRecorder != nil {
		flightRecorder.Stop()
		flightRecorder = nil
	}
}

// WriteFlightRecorder writes the current flight recorder window to the given path.
func WriteFlightRecorder(path string) error {
	if flightRecorder == nil || !flightRecorder.Enabled() {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = flightRecorder.WriteTo(f)
	return err
}
