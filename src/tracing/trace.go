//go:build trace

package tracing

import (
	"context"
	"os"
	"runtime/trace"
)

var traceFile *os.File

// Start enables runtime tracing and writes trace data to trace.out.
func Start() error {
	var err error
	traceFile, err = os.Create("trace.out")
	if err != nil {
		return err
	}
	return trace.Start(traceFile)
}

// Stop stops runtime tracing and closes the trace file.
func Stop() {
	trace.Stop()
	if traceFile != nil {
		traceFile.Close()
	}
}

// StartTask begins a trace task and returns the derived context and a function
// to end the task.
func StartTask(ctx context.Context, name string) (context.Context, func()) {
	ctx, task := trace.NewTask(ctx, name)
	return ctx, task.End
}

// StartRegion marks the beginning of a region in the trace and returns a
// function that ends the region when invoked.
func StartRegion(ctx context.Context, name string) func() {
	region := trace.StartRegion(ctx, name)
	return region.End
}

// Log adds a trace event with the provided category and message.
func Log(ctx context.Context, category, message string) {
	trace.Log(ctx, category, message)
}
