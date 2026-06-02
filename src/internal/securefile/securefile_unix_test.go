//go:build !windows
// +build !windows

package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenPrivateNoSymlinkRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	parentLink := filepath.Join(root, "linked-parent")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := OpenPrivateNoSymlink(filepath.Join(parentLink, "out.ndjson")); err == nil {
		t.Fatal("expected symlink parent to be rejected")
	}
	if _, err := os.Stat(filepath.Join(outside, "out.ndjson")); !os.IsNotExist(err) {
		t.Fatalf("expected no file through symlink parent, got err=%v", err)
	}
}

func TestOpenPrivateNoSymlinkTightensAndTruncatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.ndjson")
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	f, err := OpenPrivateNoSymlink(path)
	if err != nil {
		t.Fatalf("open private file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close private file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private file: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected existing file to be truncated, got size %d", info.Size())
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected mode 0600, got %04o", got)
	}
}

func TestReadNoSymlinkRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "manifest.json"), []byte("{}"), 0600); err != nil {
		t.Fatalf("write outside manifest: %v", err)
	}
	parentLink := filepath.Join(root, "linked-parent")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := ReadNoSymlink(filepath.Join(parentLink, "manifest.json")); err == nil {
		t.Fatal("expected symlink parent read to be rejected")
	}
}

func TestReadNoSymlinkMaxRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 16)), 0600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := ReadNoSymlinkMax(path, 8); err == nil {
		t.Fatal("expected oversized read to be rejected")
	}
}
