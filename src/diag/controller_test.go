package diag

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeProfileWriter struct {
	content string
}

func (f fakeProfileWriter) WriteTo(w io.Writer, debug int) error {
	_, err := io.WriteString(w, f.content)
	return err
}

func TestRunProbeEmitsSlowScanArtifacts(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	progress := int64(42)
	dir := t.TempDir()

	controller := NewController(Options{
		SlowScanThreshold: 2 * time.Second,
		Dir:               dir,
		ProgressCountFn:   func() int64 { return progress },
		DumpFlightRecorder: func(path string) error {
			return os.WriteFile(path, []byte("flight"), 0600)
		},
		NowFn: func() time.Time { return now },
	})
	controller.lastProgress = progress
	controller.lastProgressAt = now

	controller.runProbe(now.Add(3 * time.Second))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected slow-scan and flight artifacts, got %d entries", len(entries))
	}
	var foundSlow, foundFlight bool
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "safnari-slow-scan-") && strings.HasSuffix(name, ".json") {
			foundSlow = true
		}
		if strings.HasPrefix(name, "safnari-flight-") && strings.HasSuffix(name, ".out") {
			foundFlight = true
		}
	}
	if !foundSlow {
		t.Fatal("expected slow-scan artifact")
	}
	if !foundFlight {
		t.Fatal("expected flight recorder artifact")
	}
}

func TestWriteProfileAvailableAndUnavailable(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	controller := NewController(Options{
		Dir: dir,
		NowFn: func() time.Time {
			return now
		},
		ProfileLookupFn: func(name string) profileWriter {
			if name == "goroutine" {
				return fakeProfileWriter{content: "goroutine-profile"}
			}
			return nil
		},
	})

	path, err := controller.writeProfile("goroutine", 0)
	if err != nil {
		t.Fatalf("write available profile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written profile: %v", err)
	}
	if string(data) != "goroutine-profile" {
		t.Fatalf("unexpected profile content: %q", string(data))
	}

	if _, err := controller.writeProfile("heap-missing", 0); err == nil {
		t.Fatal("expected unavailable profile to return error")
	}
}

func TestCloseWritesGoroutineLeakProfileWhenEnabled(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	controller := NewController(Options{
		Dir:           dir,
		GoroutineLeak: true,
		NowFn: func() time.Time {
			return now
		},
		ProfileLookupFn: func(name string) profileWriter {
			if name == "goroutine" {
				return fakeProfileWriter{content: "leak-profile"}
			}
			return nil
		},
	})

	controller.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "safnari-goroutine-profile-*.pprof"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 goroutine profile file, got %d", len(matches))
	}
}
