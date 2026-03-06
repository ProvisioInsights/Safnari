package output

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	if err := w.WriteData(map[string]interface{}{"path": "test"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.SetMetrics(Metrics{})
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	records := readNDJSONRecords(t, tmp.Name())
	if len(records) < 3 {
		t.Fatalf("expected system_info, file and metrics records, got %d", len(records))
	}
	if records[0].SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %s", records[0].SchemaVersion)
	}
	if records[len(records)-1].RecordType != "metrics" {
		t.Fatalf("expected metrics record last, got %q", records[len(records)-1].RecordType)
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
			if err := w.WriteData(map[string]interface{}{"path": i}); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	records := readNDJSONRecords(t, tmp.Name())
	if got := countRecordType(records, "file"); got != 5 {
		t.Fatalf("expected 5 file records, got %d", got)
	}
	for i := range 5 {
		if !containsPayload(records, strconv.Itoa(i)) {
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
		if err := w.WriteData(map[string]interface{}{"data": large}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(base); err != nil {
		t.Fatalf("missing base file: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(base, ".ndjson") + ".1.ndjson"); err != nil {
		t.Fatalf("rotation file not created")
	}

	records := readRotatedNDJSONRecords(t, base)
	if got := countRecordType(records, "file"); got != 5 {
		t.Fatalf("expected 5 rotated file records, got %d", got)
	}
	if records[len(records)-1].RecordType != "metrics" {
		t.Fatalf("expected metrics record last after rotation, got %q", records[len(records)-1].RecordType)
	}
}

func TestCloseDrainsAcceptedWrites(t *testing.T) {
	tmp, err := os.CreateTemp("", "drain*.ndjson")
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

	const (
		writers   = 8
		perWriter = 512
	)

	var accepted atomic.Int64
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	start := make(chan struct{})
	payload := strings.Repeat("x", 128)

	for i := range writers {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			<-start
			for seq := range perWriter {
				err := w.WriteData(map[string]interface{}{
					"writer": writerID,
					"seq":    seq,
					"data":   payload,
				})
				if err != nil {
					if !errors.Is(err, errWriterClosed) {
						errCh <- err
					}
					return
				}
				accepted.Add(1)
			}
		}(i)
	}

	close(start)
	time.Sleep(5 * time.Millisecond)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- w.Close()
	}()

	wg.Wait()
	if err := <-closeDone; err != nil {
		t.Fatalf("close: %v", err)
	}
	close(errCh)
	for err := range errCh {
		t.Fatalf("unexpected write error: %v", err)
	}

	records := readNDJSONRecords(t, tmp.Name())
	if got := countRecordType(records, "file"); got != int(accepted.Load()) {
		t.Fatalf("expected %d drained file records, got %d", accepted.Load(), got)
	}
	if records[len(records)-1].RecordType != "metrics" {
		t.Fatalf("expected metrics record last after drain, got %q", records[len(records)-1].RecordType)
	}
}

func TestWriteDataAfterCloseReturnsClosedError(t *testing.T) {
	tmp, err := os.CreateTemp("", "closed*.ndjson")
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
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := w.WriteData(map[string]interface{}{"path": "late"}); !errors.Is(err, errWriterClosed) {
		t.Fatalf("expected closed writer error, got %v", err)
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

func readRotatedNDJSONRecords(t *testing.T, base string) []ndjsonTestRecord {
	t.Helper()

	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	paths := []string{base}

	rotated, err := filepath.Glob(stem + ".*" + ext)
	if err != nil {
		t.Fatalf("glob rotated output: %v", err)
	}
	paths = append(paths, rotated...)
	slices.SortFunc(paths, func(a, b string) int {
		return rotationIndex(a, stem, ext) - rotationIndex(b, stem, ext)
	})

	var records []ndjsonTestRecord
	for _, path := range paths {
		records = append(records, readNDJSONRecords(t, path)...)
	}
	return records
}

func rotationIndex(path, stem, ext string) int {
	if path == stem+ext {
		return 0
	}
	trimmed := strings.TrimPrefix(path, stem+".")
	trimmed = strings.TrimSuffix(trimmed, ext)
	index, err := strconv.Atoi(trimmed)
	if err != nil {
		return 1 << 30
	}
	return index
}

func countRecordType(records []ndjsonTestRecord, recordType string) int {
	count := 0
	for _, record := range records {
		if record.RecordType == recordType {
			count++
		}
	}
	return count
}

func containsPayload(records []ndjsonTestRecord, want string) bool {
	for _, record := range records {
		if record.RecordType != "file" {
			continue
		}
		if strings.Contains(string(record.Payload), want) {
			return true
		}
	}
	return false
}
