package output

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safnari/config"
	"safnari/systeminfo"
	"safnari/version"
)

type Metrics struct {
	StartTime      string `json:"start_time"`
	EndTime        string `json:"end_time"`
	TotalFiles     int    `json:"total_files"`
	FilesScanned   int    `json:"files_scanned"`
	FilesProcessed int    `json:"files_processed"`
	TotalProcesses int    `json:"total_processes"`
}

type ndjsonRecord struct {
	RecordType     string `json:"record_type"`
	SchemaVersion  string `json:"schema_version"`
	DeviceID       string `json:"device_id"`
	ScanID         string `json:"scan_id"`
	Sequence       uint64 `json:"sequence"`
	EventID        string `json:"event_id"`
	ObservedAt     string `json:"observed_at"`
	ScannerVersion string `json:"scanner_version"`
	PolicyDigest   string `json:"policy_digest"`
	Payload        any    `json:"payload,omitempty"`
}

type writeRequest struct {
	payload any
	barrier chan struct{}
}

type Writer struct {
	file           *os.File
	buf            *bufio.Writer
	mu             sync.Mutex
	closed         bool
	writeErr       error
	metrics        *Metrics
	cfg            *config.Config
	sysInfo        *systeminfo.SystemInfo
	otel           *otelLogger
	spool          *durableSpool
	base           string
	ext            string
	index          int
	deviceID       string
	scanID         string
	policyDigest   string
	sequence       uint64
	completion     string
	completionCode string

	queue     chan writeRequest
	stopSends chan struct{}
	stopOnce  sync.Once
	writerWG  sync.WaitGroup
	enqueueWG sync.WaitGroup

	bytesWritten       int64
	recordsSinceSync   int
	lastSyncAt         time.Time
	filesScanned       atomic.Int64
	filesProcessed     atomic.Int64
	contentBytes       atomic.Int64
	contentTruncated   atomic.Int64
	sensitiveTruncated atomic.Int64
	filesWithWarnings  atomic.Int64
	fileErrors         atomic.Int64
}

const (
	flushEveryRecords = 64
	flushMaxInterval  = 500 * time.Millisecond
	writerQueueDepth  = 256
)

var (
	errWriterClosed             = errors.New("writer is closed")
	errWriterQueueUninitialized = errors.New("writer queue is not initialized")
)

func New(cfg *config.Config, sysInfo *systeminfo.SystemInfo, m *Metrics) (*Writer, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ext := filepath.Ext(cfg.OutputFileName)
	base := strings.TrimSuffix(cfg.OutputFileName, ext)
	if ext == "" {
		ext = ".ndjson"
	}

	if sysInfo == nil {
		sysInfo = &systeminfo.SystemInfo{}
	}

	w := &Writer{
		metrics: m,
		cfg:     cfg,
		sysInfo: sysInfo,
		base:    base,
		ext:     ext,
	}
	var err error
	if cfg.DeviceID != "" {
		w.deviceID = cfg.DeviceID
	} else {
		w.deviceID, err = loadInstallationID(cfg)
		if err != nil {
			return nil, err
		}
	}
	w.scanID, err = randomID()
	if err != nil {
		return nil, err
	}
	w.policyDigest = effectivePolicyDigest(cfg)
	otel, err := newOtelLogger(cfg)
	if err != nil {
		return nil, err
	}
	w.otel = otel
	w.spool, err = openDurableSpool(cfg, otel)
	if err != nil {
		otel.Shutdown()
		return nil, err
	}

	if err := w.openFile(); err != nil {
		_ = w.spool.close()
		return nil, err
	}
	if err := w.writeRecord("scan_start", map[string]interface{}{
		"status": "running", "scan_files": cfg.ScanFiles,
		"scan_sensitive": cfg.ScanSensitive, "scan_processes": cfg.ScanProcesses,
		"collect_system_info":    cfg.CollectSystemInfo,
		"hash_algorithms":        cfg.HashAlgorithms,
		"max_file_size":          cfg.MaxFileSize,
		"content_scan_max_bytes": cfg.ContentScanMaxBytes,
		"sensitive_engine":       cfg.SensitiveEngine,
		"sensitive_longtail":     cfg.SensitiveLongtail,
		"sensitive_match_mode":   cfg.SensitiveMatchMode,
		"custom_pattern_count":   len(cfg.CustomPatterns),
		"search_term_count":      len(cfg.SearchTerms),
	}); err != nil {
		_ = w.closeFile()
		_ = w.spool.close()
		return nil, err
	}
	if err := w.emitInitialRecords(); err != nil {
		_ = w.closeFile()
		_ = w.spool.close()
		return nil, err
	}
	w.startAsyncWriter()
	if m != nil {
		m.TotalProcesses = len(sysInfo.RunningProcesses)
		w.filesScanned.Store(int64(m.FilesScanned))
		w.filesProcessed.Store(int64(m.FilesProcessed))
	}
	return w, nil
}

func (w *Writer) openFile() error {
	name := w.base + w.ext
	if w.index > 0 {
		name = fmt.Sprintf("%s.%d%s", w.base, w.index, w.ext)
	}
	f, err := openPrivateFileNoSymlink(name)
	if err != nil {
		return err
	}
	w.file = f
	w.buf = bufio.NewWriterSize(f, 1024*1024)
	w.bytesWritten = 0
	w.recordsSinceSync = 0
	w.lastSyncAt = time.Now()
	return nil
}

func (w *Writer) writeRecord(recordType string, payload any) error {
	w.sequence++
	eventID := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", w.deviceID, w.scanID, w.sequence)))
	record := ndjsonRecord{
		RecordType:     recordType,
		SchemaVersion:  SchemaVersion,
		DeviceID:       w.deviceID,
		ScanID:         w.scanID,
		Sequence:       w.sequence,
		EventID:        hex.EncodeToString(eventID[:]),
		ObservedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		ScannerVersion: version.Version,
		PolicyDigest:   w.policyDigest,
		Payload:        payload,
	}
	data, err := jsonMarshal(record)
	if err != nil {
		return err
	}
	n, err := w.buf.Write(data)
	w.bytesWritten += int64(n)
	if err != nil {
		return err
	}
	n, err = w.buf.WriteString("\n")
	w.bytesWritten += int64(n)
	if err != nil {
		return err
	}
	return w.spool.enqueueRecord(record)
}

func (w *Writer) WriteData(data any) error {
	if err := w.currentWriteErr(); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return errWriterClosed
	}
	queue := w.queue
	stopSends := w.stopSends
	// Close waits on enqueueWG before closing the queue so accepted sends are
	// never dropped during shutdown.
	w.enqueueWG.Add(1)
	w.mu.Unlock()
	defer w.enqueueWG.Done()
	if queue == nil {
		return errWriterQueueUninitialized
	}

	select {
	case queue <- writeRequest{payload: data}:
		return w.currentWriteErr()
	case <-stopSends:
		if err := w.currentWriteErr(); err != nil {
			return err
		}
		return errWriterClosed
	}
}

func (w *Writer) WaitIdle() error {
	if err := w.currentWriteErr(); err != nil {
		return err
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return w.currentWriteErr()
	}
	queue := w.queue
	stopSends := w.stopSends
	w.enqueueWG.Add(1)
	w.mu.Unlock()
	defer w.enqueueWG.Done()

	if queue == nil {
		return errWriterQueueUninitialized
	}

	barrier := make(chan struct{})
	select {
	case queue <- writeRequest{barrier: barrier}:
	case <-stopSends:
		if err := w.currentWriteErr(); err != nil {
			return err
		}
		return errWriterClosed
	}

	<-barrier
	return w.currentWriteErr()
}

func (w *Writer) SetMetrics(m Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	m.FilesScanned = int(w.filesScanned.Load())
	m.FilesProcessed = int(w.filesProcessed.Load())
	w.metrics = &m
}

func (w *Writer) SetCompletion(status string) {
	w.mu.Lock()
	w.completion = status
	w.mu.Unlock()
}

func (w *Writer) SetCompletionCode(code string) {
	w.mu.Lock()
	w.completionCode = code
	w.mu.Unlock()
}

func (w *Writer) IncrementScanned() {
	w.filesScanned.Add(1)
}

func (w *Writer) RecordCoverage(contentBytes int64, contentTruncated, sensitiveTruncated, hasWarnings bool) {
	w.contentBytes.Add(contentBytes)
	if contentTruncated {
		w.contentTruncated.Add(1)
	}
	if sensitiveTruncated {
		w.sensitiveTruncated.Add(1)
	}
	if hasWarnings {
		w.filesWithWarnings.Add(1)
	}
}

func (w *Writer) RecordFileError() {
	w.fileErrors.Add(1)
}

func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	queue := w.queue
	w.mu.Unlock()

	// Stop accepting new producers first, then wait for in-flight sends to
	// either enqueue or observe shutdown before closing the queue.
	w.signalStopSends()
	w.enqueueWG.Wait()

	if queue != nil {
		close(queue)
		w.writerWG.Wait()
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncMetricCountersLocked()
	var closeErr error
	if err := w.emitMetricsLocked(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	status := w.completion
	if status == "" {
		status = "complete"
	}
	if w.writeErr != nil || w.spool.currentError() != nil {
		status = "incomplete"
		w.completionCode = "output_failed"
	}
	errorCount := w.fileErrors.Load()
	warningCodes := []string{}
	if status != "complete" {
		errorCount++
		if w.completionCode != "" {
			warningCodes = append(warningCodes, w.completionCode)
		}
	}
	if err := w.writeRecord("scan_complete", map[string]interface{}{
		"status": status, "files_scanned": w.filesScanned.Load(),
		"files_processed": w.filesProcessed.Load(),
		"error_count":     errorCount, "warning_codes": warningCodes,
		"content_scanned_bytes":     w.contentBytes.Load(),
		"content_truncated_files":   w.contentTruncated.Load(),
		"sensitive_truncated_files": w.sensitiveTruncated.Load(),
		"files_with_warnings":       w.filesWithWarnings.Load(),
	}); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	if err := w.closeFile(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	closeErr = errors.Join(closeErr, w.spool.close())
	if w.otel != nil {
		w.otel.Shutdown()
	}
	return errors.Join(closeErr, w.writeErr)
}

func (w *Writer) rotate() error {
	if err := w.closeFile(); err != nil {
		return err
	}
	w.index++
	return w.openFile()
}

func (w *Writer) closeFile() error {
	var closeErr error
	if err := w.flush(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		if err := w.file.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		w.file = nil
	}
	w.buf = nil
	return closeErr
}

func (w *Writer) flush() error {
	if w.buf != nil {
		if err := w.buf.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) emitInitialRecords() error {
	if w.sysInfo == nil {
		return nil
	}
	if err := w.writeRecord("system_info", w.sysInfo); err != nil {
		return err
	}
	for i := range w.sysInfo.RunningProcesses {
		proc := w.sysInfo.RunningProcesses[i]
		if err := w.writeRecord("process", &proc); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) emitMetricsLocked() error {
	if w.metrics == nil {
		return nil
	}
	w.syncMetricCountersLocked()
	if err := w.writeRecord("metrics", w.metrics); err != nil {
		return err
	}
	return nil
}

func (w *Writer) shouldSync() bool {
	if w.recordsSinceSync >= flushEveryRecords {
		return true
	}
	return time.Since(w.lastSyncAt) >= flushMaxInterval
}

func (w *Writer) FilesScanned() int {
	return int(w.filesScanned.Load())
}

func (w *Writer) FilesProcessed() int {
	return int(w.filesProcessed.Load())
}

func (w *Writer) syncMetricCountersLocked() {
	if w.metrics == nil {
		return
	}
	w.metrics.FilesScanned = int(w.filesScanned.Load())
	w.metrics.FilesProcessed = int(w.filesProcessed.Load())
}

func (w *Writer) startAsyncWriter() {
	w.mu.Lock()
	if w.queue != nil {
		w.mu.Unlock()
		return
	}
	w.queue = make(chan writeRequest, writerQueueDepth)
	w.stopSends = make(chan struct{})
	queue := w.queue
	w.writerWG.Add(1)
	w.mu.Unlock()

	go func() {
		defer w.writerWG.Done()
		for req := range queue {
			if req.barrier != nil {
				if err := w.currentWriteErr(); err == nil {
					if err := w.flush(); err != nil {
						w.setWriteErr(err)
					}
				}
				close(req.barrier)
				continue
			}
			if err := w.currentWriteErr(); err != nil {
				continue
			}
			if err := w.writeRecord("file", req.payload); err != nil {
				w.setWriteErr(err)
				continue
			}
			w.filesProcessed.Add(1)

			w.recordsSinceSync++
			if w.shouldSync() {
				if err := w.flush(); err != nil {
					w.setWriteErr(err)
					continue
				}
				w.recordsSinceSync = 0
				w.lastSyncAt = time.Now()
			}

			if w.cfg.MaxOutputFileSize > 0 && w.bytesWritten >= w.cfg.MaxOutputFileSize {
				if err := w.rotate(); err != nil {
					w.setWriteErr(err)
					continue
				}
			}
		}
	}()
}

func (w *Writer) setWriteErr(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.writeErr == nil {
		w.writeErr = err
	}
	w.mu.Unlock()
	w.signalStopSends()
}

func (w *Writer) signalStopSends() {
	w.stopOnce.Do(func() {
		if w.stopSends != nil {
			close(w.stopSends)
		}
	})
}

func (w *Writer) currentWriteErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr
}
