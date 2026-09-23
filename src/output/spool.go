package output

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"safnari/config"
	"safnari/internal/securefile"
)

const (
	spoolBatchRecords = 512
	spoolBatchBytes   = 1 << 20
	spoolMaxBytes     = 1 << 30
)

var ErrPendingDelivery = errors.New("OTEL delivery remains pending")
var ErrRejectedDelivery = errors.New("OTEL receiver rejected a batch")

func ReplayPending(cfg *config.Config) error {
	otel, err := newOtelLogger(cfg)
	if err != nil {
		return err
	}
	if otel == nil {
		return errors.New("OTEL endpoint is required for replay")
	}
	defer otel.Shutdown()
	spool, err := openDurableSpool(cfg, otel)
	if err != nil {
		return err
	}
	return spool.close()
}

type spoolItem struct {
	RecordType     string          `json:"record_type"`
	Payload        json.RawMessage `json:"payload"`
	DeviceID       string          `json:"device_id"`
	ScanID         string          `json:"scan_id"`
	Sequence       uint64          `json:"sequence"`
	EventID        string          `json:"event_id"`
	ObservedAt     string          `json:"observed_at"`
	ScannerVersion string          `json:"scanner_version"`
	PolicyDigest   string          `json:"policy_digest"`
	encodedBytes   int             `json:"-"`
}

type spoolBatch struct {
	Destination string      `json:"destination"`
	Checksum    string      `json:"checksum"`
	Items       []spoolItem `json:"items"`
}

type durableSpool struct {
	dir          string
	destination  string
	otel         *otelLogger
	lockFile     *os.File
	input        chan spoolItem
	changed      chan struct{}
	done         chan struct{}
	stop         chan struct{}
	exportCancel context.CancelFunc
	mu           sync.Mutex
	writeErr     error
	rejected     bool
	bytes        int64
	closed       bool
	enqueueWG    sync.WaitGroup
	writerWG     sync.WaitGroup
}

func openDurableSpool(cfg *config.Config, otel *otelLogger) (*durableSpool, error) {
	if otel == nil {
		return nil, nil
	}
	dir := cfg.SpoolDir
	if dir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(cache, "safnari", "spool")
	}
	if err := ensurePrivateSpoolDir(dir); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open spool lock: %w", err)
	}
	if err := lockSpoolFile(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("spool already in use: %w", err)
	}
	// The receiver identity includes the endpoint and credential headers without
	// persisting their values. Changing either requires an explicit state move.
	headers, _ := json.Marshal(struct {
		Explicit   map[string]string
		LogsEnv    string
		GenericEnv string
	}{cfg.OtelHeaders, os.Getenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS"), os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")})
	digest := sha256.Sum256(append([]byte(otel.Endpoint()+"\x00"), headers...))
	s := &durableSpool{
		dir: dir, destination: hex.EncodeToString(digest[:]), otel: otel,
		lockFile: lock, input: make(chan spoolItem, 4), changed: make(chan struct{}, 1), done: make(chan struct{}), stop: make(chan struct{}),
	}
	if err := s.validateExisting(); err != nil {
		_ = unlockSpoolFile(lock)
		_ = lock.Close()
		return nil, err
	}
	s.writerWG.Add(1)
	go s.writeLoop()
	go s.exportLoop()
	return s, nil
}

func (s *durableSpool) validateExisting() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			if err := os.Remove(filepath.Join(s.dir, e.Name())); err != nil {
				return err
			}
			continue
		}
		if strings.HasSuffix(e.Name(), ".failed") {
			s.rejected = true
		}
		if !strings.HasSuffix(e.Name(), ".ready") && !strings.HasSuffix(e.Name(), ".failed") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		data, err := securefile.ReadNoSymlinkMax(path, 2<<20)
		if err != nil {
			return err
		}
		var batch spoolBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return fmt.Errorf("invalid spool batch %s: %w", e.Name(), err)
		}
		if batch.Destination != s.destination || !validBatch(batch) {
			return fmt.Errorf("spool batch %s has different destination or invalid checksum", e.Name())
		}
		s.bytes += int64(len(data))
	}
	return nil
}

func validBatch(batch spoolBatch) bool {
	data, err := json.Marshal(batch.Items)
	if err != nil || len(batch.Items) == 0 {
		return false
	}
	sum := sha256.Sum256(data)
	return batch.Checksum == hex.EncodeToString(sum[:])
}

func (s *durableSpool) enqueueRecord(record ndjsonRecord) error {
	if s == nil {
		return nil
	}
	safe := sanitizePayload(record.RecordType, record.Payload, s.otel.policy)
	data, err := json.Marshal(safe)
	if err != nil {
		return err
	}
	item := spoolItem{
		RecordType: record.RecordType, Payload: data, DeviceID: record.DeviceID,
		ScanID: record.ScanID, Sequence: record.Sequence, EventID: record.EventID,
		ObservedAt: record.ObservedAt, PolicyDigest: record.PolicyDigest,
		ScannerVersion: record.ScannerVersion,
	}
	encodedItem, err := json.Marshal(item)
	if err != nil {
		return err
	}
	item.encodedBytes = len(encodedItem)
	if item.encodedBytes+256 > spoolBatchBytes {
		return fmt.Errorf("OTEL record exceeds 1 MiB batch limit")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("spool closed")
	}
	err = s.writeErr
	if err == nil {
		s.enqueueWG.Add(1)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	defer s.enqueueWG.Done()
	s.input <- item
	return s.currentError()
}

func (s *durableSpool) currentError() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeErr
}

func (s *durableSpool) setError(err error) {
	s.mu.Lock()
	if s.writeErr == nil {
		s.writeErr = err
	}
	s.mu.Unlock()
}

func (s *durableSpool) writeLoop() {
	defer s.writerWG.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var items []spoolItem
	var size int
	commit := func() {
		if len(items) == 0 || s.currentError() != nil {
			return
		}
		if err := s.commit(items); err != nil {
			s.setError(err)
		}
		items = nil
		size = 0
	}
	for {
		select {
		case item, ok := <-s.input:
			if !ok {
				commit()
				return
			}
			if size+item.encodedBytes+1 > spoolBatchBytes-256 {
				commit()
			}
			items = append(items, item)
			size += item.encodedBytes + 1
			if len(items) >= spoolBatchRecords || size >= spoolBatchBytes-256 {
				commit()
			}
		case <-ticker.C:
			commit()
		}
	}
}

func (s *durableSpool) commit(items []spoolItem) error {
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	batch := spoolBatch{Destination: s.destination, Checksum: hex.EncodeToString(sum[:]), Items: items}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(encoded) > spoolBatchBytes {
		return errors.New("OTEL batch exceeds 1 MiB limit")
	}
	s.mu.Lock()
	if s.bytes+int64(len(encoded)) > spoolMaxBytes {
		s.mu.Unlock()
		return errors.New("OTEL spool capacity exceeded")
	}
	s.bytes += int64(len(encoded))
	s.mu.Unlock()
	committed := false
	defer func() {
		if !committed {
			s.mu.Lock()
			s.bytes -= int64(len(encoded))
			s.mu.Unlock()
		}
	}()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%x", time.Now().UnixNano(), id)
	tmp := filepath.Join(s.dir, name+".tmp")
	f, err := securefile.OpenPrivateNoSymlink(tmp)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(encoded)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	writeErr = errors.Join(writeErr, f.Close())
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if err := renameSpoolFile(tmp, filepath.Join(s.dir, name+".ready")); err != nil {
		return err
	}
	committed = true
	if err := syncSpoolDir(s.dir); err != nil {
		return err
	}
	signal(s.changed)
	return nil
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *durableSpool) exportLoop() {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.changed:
		case <-ticker.C:
		}
		err := s.exportReady()
		if err != nil && !errors.Is(err, ErrPendingDelivery) && !errors.Is(err, ErrRejectedDelivery) {
			s.setError(err)
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
	}
}

func (s *durableSpool) exportReady() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ready") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		select {
		case <-s.stop:
			return ErrPendingDelivery
		default:
		}
		path := filepath.Join(s.dir, name)
		data, err := securefile.ReadNoSymlinkMax(path, 2<<20)
		if err != nil {
			return err
		}
		var batch spoolBatch
		if err := json.Unmarshal(data, &batch); err != nil || !validBatch(batch) || batch.Destination != s.destination {
			return fmt.Errorf("invalid spool batch %s", name)
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.otel.timeout)
		s.mu.Lock()
		s.exportCancel = cancel
		s.mu.Unlock()
		err = s.otel.ExportBatch(ctx, batch.Items)
		cancel()
		s.mu.Lock()
		s.exportCancel = nil
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, ErrRejectedDelivery) {
				if renameErr := renameSpoolFile(path, strings.TrimSuffix(path, ".ready")+".failed"); renameErr != nil {
					return renameErr
				}
				if syncErr := syncSpoolDir(s.dir); syncErr != nil {
					return syncErr
				}
				receipt, _ := json.Marshal(map[string]interface{}{
					"status": "rejected", "http_status": s.otel.status.Load(),
					"at": time.Now().UTC().Format(time.RFC3339),
				})
				if receiptErr := securefile.WritePrivateNoSymlink(strings.TrimSuffix(path, ".ready")+".failure.json", receipt); receiptErr != nil {
					return receiptErr
				}
				s.mu.Lock()
				s.rejected = true
				s.mu.Unlock()
			}
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		s.mu.Lock()
		s.bytes -= int64(len(data))
		s.mu.Unlock()
		if err := syncSpoolDir(s.dir); err != nil {
			return err
		}
	}
	return nil
}

func (s *durableSpool) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
	}
	s.mu.Unlock()
	// Every accepted producer must finish its send before the input closes.
	// Add occurs under the same lock that marks the spool closed.
	s.enqueueWG.Wait()
	close(s.input)
	s.writerWG.Wait()
	signal(s.changed)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		s.mu.Lock()
		if s.exportCancel != nil {
			s.exportCancel()
		}
		close(s.stop)
		s.mu.Unlock()
		<-s.done
	}
	err := s.currentError()
	s.mu.Lock()
	pending := s.bytes > 0
	rejected := s.rejected
	s.mu.Unlock()
	if pending {
		err = errors.Join(err, ErrPendingDelivery)
	}
	if rejected {
		err = errors.Join(err, ErrRejectedDelivery)
	}
	err = errors.Join(err, unlockSpoolFile(s.lockFile), s.lockFile.Close())
	return err
}
