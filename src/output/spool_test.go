package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
	"safnari/config"
)

func TestDurableOTELReplayPreservesIdentityAndPrivacy(t *testing.T) {
	var accept atomic.Bool
	var received atomic.Int64
	var body atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if !accept.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body.Store(data)
		received.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := &config.Config{
		OutputFileName: filepath.Join(dir, "scan.ndjson"),
		SpoolDir:       filepath.Join(dir, "spool"), OtelEndpoint: server.URL + "/v1/logs",
		OtelTimeout: 100 * time.Millisecond, DeviceID: "device-1",
	}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteData(map[string]interface{}{
		"path": "/private/secret.txt", "name": "secret.txt",
		"sensitive_data":              map[string]interface{}{"email": []string{"secret@example.com"}},
		"sensitive_data_match_counts": map[string]int{"email": 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrPendingDelivery) {
		t.Fatalf("expected pending delivery after outage, got %v", err)
	}
	pending, err := filepath.Glob(filepath.Join(cfg.SpoolDir, "*.ready"))
	if err != nil || len(pending) == 0 {
		t.Fatalf("expected committed pending batches, got %v, %v", pending, err)
	}
	for _, path := range pending {
		stored, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) > spoolBatchBytes {
			t.Fatalf("batch %s exceeds 1 MiB", path)
		}
		if bytes.Contains(stored, []byte("secret@example.com")) ||
			bytes.Contains(stored, []byte("/private/secret.txt")) {
			t.Fatal("private value entered durable spool")
		}
	}
	accept.Store(true)
	if err := ReplayPending(cfg); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if received.Load() == 0 {
		t.Fatal("receiver got no batch")
	}
	wire, _ := body.Load().([]byte)
	for _, forbidden := range []string{"/private/secret.txt", "secret.txt", "secret@example.com"} {
		if bytes.Contains(wire, []byte(forbidden)) {
			t.Fatalf("private value leaked: %q", forbidden)
		}
	}
	for _, required := range []string{"device-1", "safnari.event_id", "sensitive_data_match_counts"} {
		if !bytes.Contains(wire, []byte(required)) {
			t.Fatalf("missing exported evidence: %q", required)
		}
	}
	if err := ReplayPending(cfg); err != nil {
		t.Fatalf("repeat replay: %v", err)
	}
}

func TestDurableOTELRejectsDestinationChange(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		OutputFileName: filepath.Join(dir, "scan.ndjson"), SpoolDir: filepath.Join(dir, "spool"),
		OtelEndpoint: "http://127.0.0.1:1/v1/logs", OtelTimeout: 100 * time.Millisecond,
	}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrPendingDelivery) {
		t.Fatalf("expected pending, got %v", err)
	}
	cfg.OtelEndpoint = "http://127.0.0.1:2/v1/logs"
	if err := ReplayPending(cfg); err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("expected destination mismatch, got %v", err)
	}
}

func TestDurableOTELPartialSuccessIsNotRetried(t *testing.T) {
	var attempts atomic.Int64
	partial, err := proto.Marshal(&collector.ExportLogsServiceResponse{
		PartialSuccess: &collector.ExportLogsPartialSuccess{RejectedLogRecords: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(partial)
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := &config.Config{
		OutputFileName: filepath.Join(dir, "out.ndjson"), SpoolDir: filepath.Join(dir, "spool"),
		OtelEndpoint: server.URL + "/v1/logs", OtelTimeout: time.Second,
	}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrRejectedDelivery) {
		t.Fatalf("expected terminal rejection, got %v", err)
	}
	first := attempts.Load()
	if first == 0 {
		t.Fatal("receiver was not called")
	}
	if err := ReplayPending(cfg); !errors.Is(err, ErrRejectedDelivery) {
		t.Fatalf("expected retained rejection, got %v", err)
	}
	if attempts.Load() != first {
		t.Fatal("rejected batch retried")
	}
}

func TestDurableOTELPermanentHTTPRejectionIsRetained(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := &config.Config{
		OutputFileName: filepath.Join(dir, "out.ndjson"), SpoolDir: filepath.Join(dir, "spool"),
		OtelEndpoint: server.URL + "/v1/logs", OtelTimeout: time.Second,
	}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrRejectedDelivery) {
		t.Fatalf("expected terminal rejection, got %v", err)
	}
	if err := ReplayPending(cfg); !errors.Is(err, ErrRejectedDelivery) {
		t.Fatalf("expected retained rejection, got %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("rejected batch was retried %d times", attempts.Load())
	}
}

func TestSchemaV3StableEventIdentity(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{OutputFileName: filepath.Join(dir, "one.ndjson"), SpoolDir: filepath.Join(dir, "state")}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records := readNDJSONRecords(t, cfg.OutputFileName)
	if len(records) < 2 || records[0].SchemaVersion != "3" {
		t.Fatalf("unexpected records: %#v", records)
	}
	var ids []string
	for _, record := range records {
		if record.EventID == "" || record.DeviceID == "" || record.ScanID == "" {
			t.Fatalf("missing identity: %#v", record)
		}
		ids = append(ids, record.EventID)
	}
	if ids[0] == ids[1] {
		t.Fatal("duplicate event IDs")
	}
}

func TestDurableOTELSpoolRejectsConcurrentInvocation(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		OutputFileName: filepath.Join(dir, "first.ndjson"),
		SpoolDir:       filepath.Join(dir, "spool"),
		OtelEndpoint:   "http://127.0.0.1:1/v1/logs",
		OtelTimeout:    50 * time.Millisecond,
	}
	w, err := New(cfg, nil, &Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReplayPending(cfg); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected exclusive spool lock, got %v", err)
	}
	_ = w.Close()
}

func TestDurableOTELSpoolRejectsCorruptCommittedBatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		SpoolDir:     filepath.Join(dir, "spool"),
		OtelEndpoint: "http://127.0.0.1:1/v1/logs",
	}
	if err := os.Mkdir(cfg.SpoolDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.SpoolDir, "bad.ready"), []byte("{\"items\":["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ReplayPending(cfg); err == nil || !strings.Contains(err.Error(), "invalid spool batch") {
		t.Fatalf("expected corrupt batch error, got %v", err)
	}
}

func TestDurableOTELSpoolCapacityDoesNotEvict(t *testing.T) {
	dir := t.TempDir()
	s := &durableSpool{dir: dir, destination: "receiver", bytes: spoolMaxBytes}
	item := spoolItem{RecordType: "scan_start", Payload: []byte(`{"status":"running"}`)}
	if err := s.commit([]spoolItem{item}); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("expected capacity error, got %v", err)
	}
	ready, err := filepath.Glob(filepath.Join(dir, "*.ready"))
	if err != nil || len(ready) != 0 {
		t.Fatalf("unexpected committed batch at capacity: %v, %v", ready, err)
	}
}

func TestDurableOTELConcurrentEnqueueAndCloseCommitsAcceptedRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := &config.Config{
		SpoolDir:     filepath.Join(t.TempDir(), "spool"),
		OtelEndpoint: server.URL + "/v1/logs", OtelTimeout: 50 * time.Millisecond,
	}
	otel, err := newOtelLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer otel.Shutdown()
	spool, err := openDurableSpool(cfg, otel)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.enqueueRecord(ndjsonRecord{
		RecordType: "file", Payload: map[string]any{"size": 1},
	}); err != nil {
		t.Fatal(err)
	}
	const producers = 512
	start := make(chan struct{})
	var wg sync.WaitGroup
	var accepted atomic.Int64
	accepted.Store(1)
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := spool.enqueueRecord(ndjsonRecord{
				RecordType: "file", Payload: map[string]any{"size": 1},
			})
			if err == nil {
				accepted.Add(1)
			} else if err.Error() != "spool closed" {
				t.Errorf("unexpected enqueue error: %v", err)
			}
		}()
	}
	close(start)
	closeErr := spool.close()
	wg.Wait()
	if !errors.Is(closeErr, ErrPendingDelivery) {
		t.Fatalf("expected pending delivery, got %v", closeErr)
	}
	paths, err := filepath.Glob(filepath.Join(cfg.SpoolDir, "*.ready"))
	if err != nil {
		t.Fatal(err)
	}
	var committed int
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var batch spoolBatch
		if err := json.Unmarshal(data, &batch); err != nil || !validBatch(batch) {
			t.Fatalf("invalid committed batch %s: %v", path, err)
		}
		committed += len(batch.Items)
	}
	if committed != int(accepted.Load()) {
		t.Fatalf("committed %d of %d accepted records", committed, accepted.Load())
	}
}
