package scanner

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/exp/mmap"
)

func TestReadFileContentWithModeParity(t *testing.T) {
	tmp, err := os.CreateTemp("", "content-reader-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(tmp.Name())

	want := []byte("hello mmap parity")
	if _, err := tmp.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	stream, err := readFileContentWithMode(tmp.Name(), int64(len(want)+10), "stream", 1, 256*1024, 512)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	mapped, err := readFileContentWithMode(tmp.Name(), int64(len(want)+10), "mmap", 1, 256*1024, 512)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	auto, err := readFileContentWithMode(tmp.Name(), int64(len(want)+10), "auto", 1, 256*1024, 512)
	if err != nil {
		t.Fatalf("auto: %v", err)
	}

	if string(stream) != string(want) {
		t.Fatalf("unexpected stream content: %q", string(stream))
	}
	if string(mapped) != string(want) {
		t.Fatalf("unexpected mmap content: %q", string(mapped))
	}
	if string(auto) != string(want) {
		t.Fatalf("unexpected auto content: %q", string(auto))
	}
}

func TestReadFileContentWithModeAutoFallback(t *testing.T) {
	tmp, err := os.CreateTemp("", "content-fallback-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("fallback content"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	originalOpen := openMmapReader
	openMmapReader = func(string) (*mmap.ReaderAt, error) {
		return nil, errors.New("forced mmap failure")
	}
	defer func() { openMmapReader = originalOpen }()

	content, err := readFileContentWithMode(tmp.Name(), 1024, "auto", 1, 256*1024, 512)
	if err != nil {
		t.Fatalf("auto fallback: %v", err)
	}
	if string(content) != "fallback content" {
		t.Fatalf("expected standard fallback content, got %q", string(content))
	}
}

func TestReadFileContentMmapNoDescriptorLeak(t *testing.T) {
	tmp, err := os.CreateTemp("", "content-mmap-leak-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString("descriptor leak check"); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for i := 0; i < 16; i++ {
		if _, err := readFileContentWithMode(path, 1<<20, "mmap", 1, 256*1024, 512); err != nil {
			t.Fatalf("mmap read failed: %v", err)
		}
	}

	// On Windows this will fail if a descriptor is leaked; on Unix it validates close hygiene.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove failed (possible descriptor leak): %v", err)
	}
}
