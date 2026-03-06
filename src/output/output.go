package output

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"safnari/config"
	"safnari/logger"
	"safnari/systeminfo"
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
	RecordType    string `json:"record_type"`
	SchemaVersion string `json:"schema_version"`
	Payload       any    `json:"payload,omitempty"`
}

type writeRequest struct {
	payload any
}

type Writer struct {
	file     *os.File
	buf      *bufio.Writer
	mu       sync.Mutex
	closed   bool
	writeErr error
	metrics  *Metrics
	cfg      *config.Config
	sysInfo  *systeminfo.SystemInfo
	otel     *otelLogger
	base     string
	ext      string
	index    int

	queue     chan writeRequest
	stopSends chan struct{}
	stopOnce  sync.Once
	writerWG  sync.WaitGroup
	enqueueWG sync.WaitGroup

	bytesWritten     int64
	recordsSinceSync int
	lastSyncAt       time.Time
	filesScanned     atomic.Int64
	filesProcessed   atomic.Int64
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
	otel, err := newOtelLogger(cfg)
	if err != nil {
		logger.Warnf("OTEL export disabled: %v", err)
	} else {
		w.otel = otel
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}
	if err := w.emitInitialRecords(); err != nil {
		_ = w.closeFile()
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
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
	record := ndjsonRecord{
		RecordType:    recordType,
		SchemaVersion: SchemaVersion,
		Payload:       payload,
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
	return err
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

func (w *Writer) SetMetrics(m Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	m.FilesScanned = int(w.filesScanned.Load())
	m.FilesProcessed = int(w.filesProcessed.Load())
	w.metrics = &m
}

func (w *Writer) IncrementScanned() {
	w.filesScanned.Add(1)
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
	if err := w.closeFile(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
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
	w.emitRecord("system_info", w.sysInfo)
	for i := range w.sysInfo.RunningProcesses {
		proc := w.sysInfo.RunningProcesses[i]
		if err := w.writeRecord("process", &proc); err != nil {
			return err
		}
		w.emitRecord("process", &proc)
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
	w.emitRecord("metrics", w.metrics)
	return nil
}

func (w *Writer) emitRecord(recordType string, payload interface{}) {
	if w.otel == nil {
		return
	}
	w.otel.Emit(recordType, payload)
}

func (w *Writer) shouldSync() bool {
	if w.recordsSinceSync <= 1 {
		return true
	}
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
			if err := w.currentWriteErr(); err != nil {
				continue
			}
			if err := w.writeRecord("file", req.payload); err != nil {
				w.setWriteErr(err)
				continue
			}
			w.filesProcessed.Add(1)
			w.emitRecord("file", req.payload)

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
