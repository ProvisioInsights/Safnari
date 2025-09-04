package hasher

import (
	"os"
	"testing"

	"safnari/logger"
)

func TestComputeHashes(t *testing.T) {
	logger.Init("info")
	tmp, err := os.CreateTemp("", "hash-test")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("hello world")
	tmp.Close()

	hashes := ComputeHashes(tmp.Name(), []string{"md5", "sha1", "sha256", "unknown"})
	if hashes["md5"] != "5eb63bbbe01eeed093cb22bb8f5acdc3" {
		t.Errorf("md5 mismatch: %s", hashes["md5"])
	}
	if hashes["sha1"] != "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" {
		t.Errorf("sha1 mismatch: %s", hashes["sha1"])
	}
	if hashes["sha256"] != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Errorf("sha256 mismatch: %s", hashes["sha256"])
	}
	if _, ok := hashes["unknown"]; ok {
		t.Errorf("unexpected hash for unknown algorithm")
	}
}
