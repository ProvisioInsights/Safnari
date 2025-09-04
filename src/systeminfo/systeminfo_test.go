package systeminfo

import (
	"testing"

	"safnari/config"
	"safnari/logger"
)

func init() {
	logger.Init("error")
}

func TestGetSystemInfo(t *testing.T) {
	cfg := &config.Config{}
	info, err := GetSystemInfo(cfg)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if info == nil {
		t.Fatal("nil info")
	}
}

func TestGatherRunningProcesses(t *testing.T) {
	sys := &SystemInfo{}
	if err := gatherRunningProcesses(sys, false); err != nil {
		t.Fatalf("gather: %v", err)
	}
	sys2 := &SystemInfo{}
	if err := gatherRunningProcesses(sys2, true); err != nil {
		t.Fatalf("gather extended: %v", err)
	}
}
