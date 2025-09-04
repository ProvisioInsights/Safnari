package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/glaslos/ssdeep"
	"safnari/logger"
)

func TestComputeHashes(t *testing.T) {
	logger.Init("info")
	tmp, err := os.CreateTemp("", "hash-test")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	data := make([]byte, 5000)
	for i := range data {
		data[i] = 'a'
	}
	if _, err := tmp.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	tmp.Close()

	hashes := ComputeHashes(tmp.Name(), []string{"md5", "sha1", "sha256", "ssdeep", "unknown"})

	expectedMD5 := fmt.Sprintf("%x", md5.Sum(data))
	if hashes["md5"] != expectedMD5 {
		t.Errorf("md5 mismatch: %s", hashes["md5"])
	}
	expectedSHA1 := fmt.Sprintf("%x", sha1.Sum(data))
	if hashes["sha1"] != expectedSHA1 {
		t.Errorf("sha1 mismatch: %s", hashes["sha1"])
	}
	expectedSHA256 := fmt.Sprintf("%x", sha256.Sum256(data))
	if hashes["sha256"] != expectedSHA256 {
		t.Errorf("sha256 mismatch: %s", hashes["sha256"])
	}
	f, _ := os.Open(tmp.Name())
	expectedSSDEEP, err := ssdeep.FuzzyFile(f)
	f.Close()
	if err == nil {
		if hashes["ssdeep"] != expectedSSDEEP {
			t.Errorf("ssdeep mismatch: %s", hashes["ssdeep"])
		}
	} else if hashes["ssdeep"] != "" {
		t.Errorf("expected empty ssdeep on error")
	}
	if _, ok := hashes["unknown"]; ok {
		t.Errorf("unexpected hash for unknown algorithm")
	}
}
