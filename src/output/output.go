package output

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

type Writer struct {
	file    *os.File
	buf     *bufio.Writer
	csvw    *csv.Writer
	mu      sync.Mutex
	first   bool
	metrics *Metrics
	cfg     *config.Config
	sysInfo *systeminfo.SystemInfo
	otel    *otelLogger
	base    string
	ext     string
	index   int
	format  string

	bytesWritten     int64
	recordsSinceSync int
	lastSyncAt       time.Time
}

const (
	flushEveryRecords = 64
	flushMaxInterval  = 500 * time.Millisecond
)

func New(cfg *config.Config, sysInfo *systeminfo.SystemInfo, m *Metrics) (*Writer, error) {
	ext := filepath.Ext(cfg.OutputFileName)
	base := strings.TrimSuffix(cfg.OutputFileName, ext)
	format := strings.ToLower(cfg.OutputFormat)
	if format == "" {
		format = "json"
	}

	if sysInfo == nil {
		sysInfo = &systeminfo.SystemInfo{}
	}

	w := &Writer{
		first:   true,
		metrics: m,
		cfg:     cfg,
		sysInfo: sysInfo,
		otel:    nil,
		base:    base,
		ext:     ext,
		format:  format,
	}
	if cfg != nil {
		otel, err := newOtelLogger(cfg)
		if err != nil {
			logger.Warnf("OTEL export disabled: %v", err)
		} else {
			w.otel = otel
			if otel != nil {
				logger.Warnf("OTEL export enabled for endpoint: %s", otel.Endpoint())
				if strings.HasPrefix(strings.ToLower(otel.Endpoint()), "http://") {
					logger.Warn("OTEL export is using http://; transport is not encrypted.")
				}
			}
		}
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	w.emitInitialRecords()
	if m != nil {
		m.TotalProcesses = len(sysInfo.RunningProcesses)
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
	w.csvw = nil
	w.first = true
	w.bytesWritten = 0
	w.recordsSinceSync = 0
	w.lastSyncAt = time.Now()

	switch w.format {
	case "csv":
		w.csvw = csv.NewWriter(w.buf)
		if err := w.writeCSVHeader(); err != nil {
			return err
		}
	default:
		if err := w.writeString("{\n"); err != nil {
			return err
		}
		if err := w.writeHeader(); err != nil {
			return err
		}
	}
	return w.buf.Flush()
}

func (w *Writer) writeHeader() error {
	if err := w.writeString("  \"schema_version\": "); err != nil {
		return err
	}
	if err := w.writeString(fmt.Sprintf("%q", SchemaVersion)); err != nil {
		return err
	}
	if err := w.writeString(",\n"); err != nil {
		return err
	}
	sysBytes, err := jsonMarshalIndent(w.sysInfo, "  ", "  ")
	if err != nil {
		return err
	}
	if err := w.writeString("  \"system_info\": "); err != nil {
		return err
	}
	if err := w.writeBytes(sysBytes); err != nil {
		return err
	}
	if err := w.writeString(",\n"); err != nil {
		return err
	}

	procBytes, err := jsonMarshalIndent(w.sysInfo.RunningProcesses, "  ", "  ")
	if err != nil {
		return err
	}
	if err := w.writeString("  \"processes\": "); err != nil {
		return err
	}
	if err := w.writeBytes(procBytes); err != nil {
		return err
	}
	if err := w.writeString(",\n"); err != nil {
		return err
	}

	if err := w.writeString("  \"files\": [\n"); err != nil {
		return err
	}
	return nil
}

func (w *Writer) WriteData(data map[string]interface{}) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case "csv":
		if err := w.writeCSVRow("file", data, nil, nil, nil); err != nil {
			return
		}
	default:
		if !w.first {
			_ = w.writeString(",\n")
		}
		bytes, err := jsonMarshalIndent(data, "    ", "  ")
		if err == nil {
			_ = w.writeString("    ")
			_ = w.writeBytes(bytes)
		}
		w.first = false
	}
	if w.metrics != nil {
		w.metrics.FilesProcessed++
	}
	w.emitRecordLocked("file", data)

	w.recordsSinceSync++
	if w.shouldSync() {
		w.flush()
		w.recordsSinceSync = 0
		w.lastSyncAt = time.Now()
	}

	if w.cfg.MaxOutputFileSize > 0 {
		rotate := false
		if w.format == "csv" {
			// CSV writes are buffered and size is not tracked precisely; sync before checking.
			w.flush()
			if info, err := w.file.Stat(); err == nil && info.Size() >= w.cfg.MaxOutputFileSize {
				rotate = true
			}
		} else if w.bytesWritten >= w.cfg.MaxOutputFileSize {
			rotate = true
		}
		if rotate {
			w.rotate()
		}
	}
}

func (w *Writer) SetMetrics(m Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.metrics = &m
}

func (w *Writer) IncrementScanned() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.metrics != nil {
		w.metrics.FilesScanned++
	}
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.emitMetricsLocked()
	w.closeFile()
	if w.otel != nil {
		w.otel.Shutdown()
	}
}

func (w *Writer) rotate() {
	w.closeFile()
	w.index++
	w.openFile()
}

func (w *Writer) closeFile() {
	switch w.format {
	case "csv":
		if w.metrics != nil {
			_ = w.writeCSVRow("metrics", nil, nil, nil, w.metrics)
		}
		w.flush()
	default:
		_ = w.writeString("\n  ]")
		if w.metrics != nil {
			mBytes, err := jsonMarshalIndent(w.metrics, "  ", "  ")
			if err == nil {
				_ = w.writeString(",\n  \"metrics\": ")
				_ = w.writeBytes(mBytes)
			}
		}
		_ = w.writeString("\n}\n")
		w.flush()
	}
	_ = w.file.Sync()
	_ = w.file.Close()
}

func (w *Writer) flush() {
	if w.csvw != nil {
		w.csvw.Flush()
	}
	if w.buf != nil {
		_ = w.buf.Flush()
	}
}

func (w *Writer) writeCSVHeader() error {
	header := []string{
		"record_type",
		"schema_version",
		"path",
		"name",
		"size",
		"mod_time",
		"creation_time",
		"access_time",
		"change_time",
		"attributes",
		"permissions",
		"owner",
		"file_id",
		"mime_type",
		"hashes",
		"fuzzy_hashes",
		"metadata",
		"xattrs",
		"acl",
		"alternate_data_streams",
		"sensitive_data",
		"search_hits",
		"system_info",
		"process",
		"metrics",
	}
	if err := w.csvw.Write(header); err != nil {
		return err
	}
	if w.sysInfo != nil {
		sysInfo := *w.sysInfo
		sysInfo.RunningProcesses = nil
		if err := w.writeCSVRow("system_info", nil, &sysInfo, nil, nil); err != nil {
			return err
		}
		for i := range w.sysInfo.RunningProcesses {
			proc := w.sysInfo.RunningProcesses[i]
			if err := w.writeCSVRow("process", nil, nil, &proc, nil); err != nil {
				return err
			}
		}
	}
	w.csvw.Flush()
	return w.csvw.Error()
}

func (w *Writer) emitInitialRecords() {
	if w.otel == nil || w.sysInfo == nil {
		return
	}
	w.emitRecordLocked("system_info", w.sysInfo)
	for i := range w.sysInfo.RunningProcesses {
		proc := w.sysInfo.RunningProcesses[i]
		w.emitRecordLocked("process", &proc)
	}
}

func (w *Writer) emitMetricsLocked() {
	if w.metrics == nil {
		return
	}
	w.emitRecordLocked("metrics", w.metrics)
}

func (w *Writer) emitRecordLocked(recordType string, payload interface{}) {
	if w.otel == nil {
		return
	}
	w.otel.Emit(recordType, payload)
}

func (w *Writer) writeCSVRow(recordType string, data map[string]interface{}, sysInfo *systeminfo.SystemInfo, proc *systeminfo.ProcessInfo, metrics *Metrics) error {
	row := []string{
		recordType,
		SchemaVersion,
		getField(data, "path"),
		getField(data, "name"),
		getField(data, "size"),
		getField(data, "mod_time"),
		getField(data, "creation_time"),
		getField(data, "access_time"),
		getField(data, "change_time"),
		jsonString(getValue(data, "attributes")),
		getField(data, "permissions"),
		getField(data, "owner"),
		getField(data, "file_id"),
		getField(data, "mime_type"),
		jsonString(getValue(data, "hashes")),
		jsonString(getValue(data, "fuzzy_hashes")),
		jsonString(getValue(data, "metadata")),
		jsonString(getValue(data, "xattrs")),
		jsonString(getValue(data, "acl")),
		jsonString(getValue(data, "alternate_data_streams")),
		jsonString(getValue(data, "sensitive_data")),
		jsonString(getValue(data, "search_hits")),
		jsonString(sysInfo),
		jsonString(proc),
		jsonString(metrics),
	}
	if err := w.csvw.Write(row); err != nil {
		return err
	}
	return nil
}

func (w *Writer) writeString(s string) error {
	if w.buf == nil {
		return nil
	}
	n, err := w.buf.WriteString(s)
	w.bytesWritten += int64(n)
	return err
}

func (w *Writer) writeBytes(b []byte) error {
	if w.buf == nil {
		return nil
	}
	n, err := w.buf.Write(b)
	w.bytesWritten += int64(n)
	return err
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

func getField(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	val, ok := data[key]
	if !ok || val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func getValue(data map[string]interface{}, key string) interface{} {
	if data == nil {
		return nil
	}
	return data[key]
}

func jsonString(value interface{}) string {
	if value == nil {
		return ""
	}
	bytes, err := jsonMarshal(value)
	if err != nil {
		return ""
	}
	return string(bytes)
}
