package utils

import (
	"path/filepath"
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
