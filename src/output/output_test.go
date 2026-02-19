package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"safnari/config"
	"safnari/systeminfo"
)

type ndjsonTestRecord struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
}

func TestOutputLifecycle(t *testing.T) {
	tmp, err := os.CreateTemp("", "out*.ndjson")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	cfg := &config.Config{OutputFileName: tmp.Name(), OutputFormat: "json"}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &Metrics{}
	w, err := New(cfg, sysInfo, metrics)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	w.WriteData(map[string]interface{}{"path": "test"})
	w.SetMetrics(Metrics{})
	w.Close()

	records := readNDJSONRecords(t, tmp.Name())
	if len(records) < 3 {
		t.Fatalf("expected system_info, file and metrics records, got %d", len(records))
	}
	if records[0].SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %s", records[0].SchemaVersion)
	}
}

func TestWriteDataConcurrent(t *testing.T) {
	tmp, err := os.CreateTemp("", "concurrent*.ndjson")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	cfg := &config.Config{OutputFileName: tmp.Name(), OutputFormat: "json"}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	w, err := New(cfg, sysInfo, &Metrics{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w.WriteData(map[string]interface{}{"path": i})
		}(i)
	}
	wg.Wait()
	w.Close()

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range 5 {
		if !strings.Contains(string(content), strconv.Itoa(i)) {
			t.Fatalf("missing entry %d", i)
		}
	}
}

func TestOutputRotation(t *testing.T) {
	tmpDir := t.TempDir()
	base := filepath.Join(tmpDir, "out.ndjson")

	cfg := &config.Config{OutputFileName: base, OutputFormat: "json", MaxOutputFileSize: 200}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	w, err := New(cfg, sysInfo, &Metrics{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	large := strings.Repeat("a", 150)
	for i := 0; i < 5; i++ {
		w.WriteData(map[string]interface{}{"data": large})
	}
	w.Close()

	if _, err := os.Stat(base); err != nil {
		t.Fatalf("missing base file: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(base, ".ndjson") + ".1.ndjson"); err != nil {
		t.Fatalf("rotation file not created")
	}
}

func TestIncrementScanned(t *testing.T) {
	w := &Writer{metrics: &Metrics{}}
	w.IncrementScanned()
	if got := w.FilesScanned(); got != 1 {
		t.Fatalf("expected FilesScanned=1, got %d", got)
	}
}

func TestShouldSync(t *testing.T) {
	w := &Writer{recordsSinceSync: 1, lastSyncAt: time.Now()}
	if !w.shouldSync() {
		t.Fatal("expected sync on first record")
	}

	w.recordsSinceSync = flushEveryRecords
	if !w.shouldSync() {
		t.Fatal("expected sync at flush threshold")
	}

	w.recordsSinceSync = 2
	w.lastSyncAt = time.Now().Add(-flushMaxInterval - time.Millisecond)
	if !w.shouldSync() {
		t.Fatal("expected time-based sync")
	}

	w.recordsSinceSync = 2
	w.lastSyncAt = time.Now()
	if w.shouldSync() {
		t.Fatal("expected no sync when below thresholds")
	}
}

func TestSetMetricsUsesAtomicCounters(t *testing.T) {
	w := &Writer{}
	w.filesScanned.Store(3)
	w.filesProcessed.Store(2)

	w.SetMetrics(Metrics{TotalFiles: 10})
	if w.metrics == nil {
		t.Fatal("expected metrics to be set")
	}
	if w.metrics.TotalFiles != 10 {
		t.Fatalf("expected TotalFiles=10, got %d", w.metrics.TotalFiles)
	}
	if w.metrics.FilesScanned != 3 {
		t.Fatalf("expected FilesScanned=3, got %d", w.metrics.FilesScanned)
	}
	if w.metrics.FilesProcessed != 2 {
		t.Fatalf("expected FilesProcessed=2, got %d", w.metrics.FilesProcessed)
	}
}

func readNDJSONRecords(t *testing.T, path string) []ndjsonTestRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	var records []ndjsonTestRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec ndjsonTestRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode ndjson: %v", err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan ndjson: %v", err)
	}
	return records
}
