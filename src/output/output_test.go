package output

import (
	"os"
	"strconv"
	"strings"
	"sync"
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
	w, err := New(cfg, sysInfo, metrics)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	w.WriteData(map[string]interface{}{"path": "test"})
	w.SetMetrics(Metrics{})
	w.Close()
}

func TestWriteDataStreaming(t *testing.T) {
	tmp, err := os.CreateTemp("", "stream*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	cfg := &config.Config{OutputFileName: tmp.Name()}
	sysInfo := &systeminfo.SystemInfo{RunningProcesses: []systeminfo.ProcessInfo{}}
	w, err := New(cfg, sysInfo, &Metrics{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	w.WriteData(map[string]interface{}{"path": "early"})

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(content), "\"path\": \"early\"") {
		t.Fatalf("expected written data, got: %s", string(content))
	}

	w.Close()
}

func TestWriteDataConcurrent(t *testing.T) {
	tmp, err := os.CreateTemp("", "concurrent*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	cfg := &config.Config{OutputFileName: tmp.Name()}
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
			w.WriteData(map[string]interface{}{"path": i})
		}(i)
	}
	wg.Wait()
	w.Close()

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range 5 {
		if !strings.Contains(string(content), "\"path\": "+strconv.Itoa(i)) {
			t.Fatalf("missing entry %d", i)
		}
	}
}
