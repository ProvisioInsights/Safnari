package output

import (
	"encoding/json"
	"os"
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
}

func New(cfg *config.Config, sysInfo *systeminfo.SystemInfo, m *Metrics) (*Writer, error) {
	f, err := os.OpenFile(cfg.OutputFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}

	w := &Writer{file: f, first: true, metrics: m}
	if m != nil {
		m.TotalProcesses = len(sysInfo.RunningProcesses)
	}

	if _, err := w.file.WriteString("{\n"); err != nil {
		return nil, err
	}

	sysBytes, err := json.MarshalIndent(sysInfo, "  ", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := w.file.WriteString("  \"system_info\": "); err != nil {
		return nil, err
	}
	if _, err := w.file.Write(sysBytes); err != nil {
		return nil, err
	}
	if _, err := w.file.WriteString(",\n"); err != nil {
		return nil, err
	}

	procBytes, err := json.MarshalIndent(sysInfo.RunningProcesses, "  ", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := w.file.WriteString("  \"processes\": "); err != nil {
		return nil, err
	}
	if _, err := w.file.Write(procBytes); err != nil {
		return nil, err
	}
	if _, err := w.file.WriteString(",\n"); err != nil {
		return nil, err
	}

	if _, err := w.file.WriteString("  \"files\": [\n"); err != nil {
		return nil, err
	}

	return w, w.file.Sync()
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
}

func (w *Writer) SetMetrics(m Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.metrics = &m
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

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
