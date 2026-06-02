package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsPathWithin(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a", "b.txt")
	outside := filepath.Join(filepath.Dir(root), "outside.txt")

	if !IsPathWithin(child, []string{root}) {
		t.Fatalf("expected %s to be within %s", child, root)
	}
	if IsPathWithin(outside, []string{root}) {
		t.Fatalf("did not expect %s to be within %s", outside, root)
	}
}

func TestPathGuardContainsMultipleRoots(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	inB := filepath.Join(rootB, "nested", "file.txt")

	guard := getPathGuard([]string{rootA, rootB})
	if !guard.Contains(inB) {
		t.Fatalf("expected guard to include path under second root")
	}
}

func TestIsPathWithinRejectsSymlinkParentEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on many Windows systems")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if IsPathWithin(filepath.Join(link, "secret.txt"), []string{root}) {
		t.Fatal("expected symlinked parent escape to be outside canonical root")
	}
}
