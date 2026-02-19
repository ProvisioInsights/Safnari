package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"time"

	"safnari/logger"
)

type profileWriter interface {
	WriteTo(w io.Writer, debug int) error
}

type Options struct {
	SlowScanThreshold  time.Duration
	Dir                string
	GoroutineLeak      bool
	ProgressCountFn    func() int64
	DumpFlightRecorder func(path string) error
	NowFn              func() time.Time
	ProfileLookupFn    func(name string) profileWriter
}

type Controller struct {
	slowScanThreshold  time.Duration
	dir                string
	goroutineLeak      bool
	progressCountFn    func() int64
	dumpFlightRecorder func(path string) error
	nowFn              func() time.Time
	profileLookupFn    func(name string) profileWriter

	mu             sync.Mutex
	lastProgressAt time.Time
	lastProgress   int64
	lastDumpAt     time.Time

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewController(opts Options) *Controller {
	nowFn := opts.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	profileLookup := opts.ProfileLookupFn
	if profileLookup == nil {
		profileLookup = func(name string) profileWriter {
			return pprof.Lookup(name)
		}
	}
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}

	return &Controller{
		slowScanThreshold:  opts.SlowScanThreshold,
		dir:                dir,
		goroutineLeak:      opts.GoroutineLeak,
		progressCountFn:    opts.ProgressCountFn,
		dumpFlightRecorder: opts.DumpFlightRecorder,
		nowFn:              nowFn,
		profileLookupFn:    profileLookup,
	}
}

func (c *Controller) Start(ctx context.Context) {
	if c == nil {
		return
	}
	if c.slowScanThreshold <= 0 {
		return
	}
	if c.progressCountFn == nil {
		return
	}
	if c.stopCh != nil {
		return
	}

	now := c.nowFn()
	c.mu.Lock()
	c.lastProgress = c.progressCountFn()
	c.lastProgressAt = now
	c.lastDumpAt = time.Time{}
	c.mu.Unlock()

	c.stopCh = make(chan struct{})
	c.doneCh = make(chan struct{})
	interval := c.slowScanThreshold / 2
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	if interval > 2*time.Second {
		interval = 2 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(c.doneCh)

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.runProbe(c.nowFn())
			}
		}
	}()
}

func (c *Controller) Close() {
	if c == nil {
		return
	}
	if c.stopCh != nil {
		close(c.stopCh)
		if c.doneCh != nil {
			<-c.doneCh
		}
		c.stopCh = nil
		c.doneCh = nil
	}

	if c.goroutineLeak {
		if _, err := c.writeProfile("goroutine", 2); err != nil {
			logger.Warnf("Diagnostics goroutine profile dump failed: %v", err)
		}
	}
}

func (c *Controller) runProbe(now time.Time) {
	if c == nil || c.progressCountFn == nil || c.slowScanThreshold <= 0 {
		return
	}

	progress := c.progressCountFn()

	c.mu.Lock()
	if progress != c.lastProgress {
		c.lastProgress = progress
		c.lastProgressAt = now
		c.mu.Unlock()
		return
	}
	if c.lastProgressAt.IsZero() {
		c.lastProgressAt = now
		c.mu.Unlock()
		return
	}
	stalledFor := now.Sub(c.lastProgressAt)
	shouldDump := stalledFor >= c.slowScanThreshold &&
		(c.lastDumpAt.IsZero() || now.Sub(c.lastDumpAt) >= c.slowScanThreshold)
	if shouldDump {
		c.lastDumpAt = now
	}
	c.mu.Unlock()

	if shouldDump {
		if err := c.dumpSlowScanArtifacts(now, progress, stalledFor); err != nil {
			logger.Warnf("Diagnostics slow-scan dump failed: %v", err)
		}
	}
}

func (c *Controller) dumpSlowScanArtifacts(now time.Time, progress int64, stalledFor time.Duration) error {
	if err := os.MkdirAll(c.dir, 0755); err != nil {
		return err
	}
	ts := now.UTC().Format("20060102-150405.000")
	eventPath := filepath.Join(c.dir, fmt.Sprintf("safnari-slow-scan-%s.json", ts))
	event := map[string]interface{}{
		"event":               "slow_scan_threshold_exceeded",
		"timestamp":           now.UTC().Format(time.RFC3339Nano),
		"progress_count":      progress,
		"threshold_ms":        c.slowScanThreshold.Milliseconds(),
		"observed_stalled_ms": stalledFor.Milliseconds(),
	}
	b, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(eventPath, b, 0600); err != nil {
		return err
	}

	if c.dumpFlightRecorder != nil {
		tracePath := filepath.Join(c.dir, fmt.Sprintf("safnari-flight-%s.out", ts))
		if err := c.dumpFlightRecorder(tracePath); err != nil {
			logger.Warnf("Diagnostics flight recorder dump failed: %v", err)
		}
	}
	return nil
}

func (c *Controller) writeProfile(name string, debug int) (string, error) {
	if c == nil {
		return "", fmt.Errorf("diagnostics controller is nil")
	}
	if c.profileLookupFn == nil {
		return "", fmt.Errorf("profile lookup function is nil")
	}
	profile := c.profileLookupFn(name)
	if profile == nil {
		return "", fmt.Errorf("pprof profile %q unavailable", name)
	}
	if err := os.MkdirAll(c.dir, 0755); err != nil {
		return "", err
	}
	ts := c.nowFn().UTC().Format("20060102-150405.000")
	path := filepath.Join(c.dir, fmt.Sprintf("safnari-%s-profile-%s.pprof", name, ts))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := profile.WriteTo(f, debug); err != nil {
		return "", err
	}
	return path, nil
}
