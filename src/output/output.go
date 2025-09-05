package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"safnari/config"
	"safnari/systeminfo"
)

type Metrics struct {
	StartTime      string `json:"start_time"`
	EndTime        string `json:"end_time"`
	TotalFiles     int    `json:"total_files"`
	FilesProcessed int    `json:"files_processed"`
	TotalProcesses int    `json:"total_processes"`
}

type Writer struct {
	file    *os.File
	mu      sync.Mutex
	first   bool
	metrics *Metrics
	cfg     *config.Config
	sysInfo *systeminfo.SystemInfo
	base    string
	ext     string
	index   int
}

func New(cfg *config.Config, sysInfo *systeminfo.SystemInfo, m *Metrics) (*Writer, error) {
	ext := filepath.Ext(cfg.OutputFileName)
	base := strings.TrimSuffix(cfg.OutputFileName, ext)

	w := &Writer{
		first:   true,
		metrics: m,
		cfg:     cfg,
		sysInfo: sysInfo,
		base:    base,
		ext:     ext,
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
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
	w.first = true

	if _, err := w.file.WriteString("{\n"); err != nil {
		return err
	}
	if err := w.writeHeader(); err != nil {
		return err
	}
	return w.file.Sync()
}

func (w *Writer) writeHeader() error {
	sysBytes, err := json.MarshalIndent(w.sysInfo, "  ", "  ")
	if err != nil {
		return err
	}
	if _, err := w.file.WriteString("  \"system_info\": "); err != nil {
		return err
	}
	if _, err := w.file.Write(sysBytes); err != nil {
		return err
	}
	if _, err := w.file.WriteString(",\n"); err != nil {
		return err
	}

	procBytes, err := json.MarshalIndent(w.sysInfo.RunningProcesses, "  ", "  ")
	if err != nil {
		return err
	}
	if _, err := w.file.WriteString("  \"processes\": "); err != nil {
		return err
	}
	if _, err := w.file.Write(procBytes); err != nil {
		return err
	}
	if _, err := w.file.WriteString(",\n"); err != nil {
		return err
	}

	if _, err := w.file.WriteString("  \"files\": [\n"); err != nil {
		return err
	}
	return nil
}

func (w *Writer) WriteData(data map[string]interface{}) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.first {
		w.file.WriteString(",\n")
	}

	bytes, err := json.MarshalIndent(data, "    ", "  ")
	if err == nil {
		w.file.WriteString("    ")
		w.file.Write(bytes)
	}

	w.first = false
	if w.metrics != nil {
		w.metrics.FilesProcessed++
	}

	w.file.Sync()

	if w.cfg.MaxOutputFileSize > 0 {
		if info, err := w.file.Stat(); err == nil && info.Size() >= w.cfg.MaxOutputFileSize {
			w.rotate()
		}
	}
}

func (w *Writer) SetMetrics(m Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.metrics = &m
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeFile()
}

func (w *Writer) rotate() {
	w.closeFile()
	w.index++
	w.openFile()
}

func (w *Writer) closeFile() {
	w.file.WriteString("\n  ]")
	if w.metrics != nil {
		mBytes, err := json.MarshalIndent(w.metrics, "  ", "  ")
		if err == nil {
			w.file.WriteString(",\n  \"metrics\": ")
			w.file.Write(mBytes)
		}
	}
	w.file.WriteString("\n}\n")
	w.file.Sync()
	w.file.Close()
}
