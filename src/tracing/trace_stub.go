//go:build !trace

package tracing

import "context"

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
