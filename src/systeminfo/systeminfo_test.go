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

func TestGetSystemInfoProcessFlag(t *testing.T) {
	cfg := &config.Config{ScanProcesses: true}
	info, err := GetSystemInfo(cfg)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(info.RunningProcesses) == 0 {
		t.Fatal("expected running processes when enabled")
	}

	cfg = &config.Config{CollectSystemInfo: true, ScanProcesses: false}
	info, err = GetSystemInfo(cfg)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(info.RunningProcesses) != 0 {
		t.Fatal("expected no running processes when disabled")
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

func TestGatherNetworkInterfaces(t *testing.T) {
	sys := &SystemInfo{}
	if err := gatherNetworkInterfaces(sys); err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	if len(sys.NetworkInterfaces) == 0 {
		t.Fatal("expected at least one interface")
	}
}

func TestGatherOpenConnections(t *testing.T) {
	sys := &SystemInfo{}
	if err := gatherOpenConnections(sys); err != nil {
		t.Fatalf("connections: %v", err)
	}
}

func TestGatherRunningServices(t *testing.T) {
	sys := &SystemInfo{}
	if err := gatherRunningServices(sys); err != nil {
		t.Fatalf("services: %v", err)
	}
}
