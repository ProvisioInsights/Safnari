package output

import (
	"bufio"
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

type Writer struct {
	file    *os.File
	buf     *bufio.Writer
	mu      sync.Mutex
	metrics *Metrics
	cfg     *config.Config
	sysInfo *systeminfo.SystemInfo
	otel    *otelLogger
	base    string
	ext     string
	index   int

	bytesWritten     int64
	recordsSinceSync int
	lastSyncAt       time.Time
	filesScanned     atomic.Int64
	filesProcessed   atomic.Int64
}

const (
	flushEveryRecords = 64
	flushMaxInterval  = 500 * time.Millisecond
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
	w.emitInitialRecords()
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

func (w *Writer) WriteData(data any) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writeRecord("file", data); err != nil {
		return
	}
	w.filesProcessed.Add(1)
	w.emitRecordLocked("file", data)

	w.recordsSinceSync++
	if w.shouldSync() {
		w.flush()
		w.recordsSinceSync = 0
		w.lastSyncAt = time.Now()
	}

	if w.cfg.MaxOutputFileSize > 0 && w.bytesWritten >= w.cfg.MaxOutputFileSize {
		w.rotate()
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

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncMetricCountersLocked()
	w.emitMetricsLocked()
	w.closeFile()
	if w.otel != nil {
		w.otel.Shutdown()
	}
}

func (w *Writer) rotate() {
	w.closeFile()
	w.index++
	_ = w.openFile()
}

func (w *Writer) closeFile() {
	w.flush()
	_ = w.file.Sync()
	_ = w.file.Close()
}

func (w *Writer) flush() {
	if w.buf != nil {
		_ = w.buf.Flush()
	}
}

func (w *Writer) emitInitialRecords() {
	if w.sysInfo == nil {
		return
	}
	_ = w.writeRecord("system_info", w.sysInfo)
	w.emitRecordLocked("system_info", w.sysInfo)
	for i := range w.sysInfo.RunningProcesses {
		proc := w.sysInfo.RunningProcesses[i]
		_ = w.writeRecord("process", &proc)
		w.emitRecordLocked("process", &proc)
	}
}

func (w *Writer) emitMetricsLocked() {
	if w.metrics == nil {
		return
	}
	w.syncMetricCountersLocked()
	_ = w.writeRecord("metrics", w.metrics)
	w.emitRecordLocked("metrics", w.metrics)
}

func (w *Writer) emitRecordLocked(recordType string, payload interface{}) {
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
