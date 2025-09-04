package output

import (
	"os"
	"testing"

	"safnari/config"
	"safnari/systeminfo"
)

func TestOutputLifecycle(t *testing.T) {
	tmp, err := os.CreateTemp("", "out*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	cfg := &config.Config{OutputFileName: tmp.Name()}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	metrics := &Metrics{}
	if err := Init(cfg, sysInfo, metrics); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer Close()

	WriteData(map[string]interface{}{"path": "test"})
	SetMetrics(Metrics{})
}

func TestJSONWriterFlush(t *testing.T) {
	tmp, err := os.CreateTemp("", "flush*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	w := NewJSONWriter(tmp)
	w.data.Files = append(w.data.Files, map[string]interface{}{"a": 1})
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}
