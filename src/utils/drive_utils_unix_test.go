package utils

import "testing"

func TestGetLocalDrives(t *testing.T) {
	drives, err := GetLocalDrives()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(drives) == 0 {
		t.Fatal("expected at least one drive")
	}
}
