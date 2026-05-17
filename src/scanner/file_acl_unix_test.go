//go:build !windows
// +build !windows

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTrustedACLCommandIgnoresProcessPath(t *testing.T) {
	tmpDir := t.TempDir()
	fake := filepath.Join(tmpDir, "ls")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatalf("write fake ls: %v", err)
	}
	t.Setenv("PATH", tmpDir)
	resolved := resolveTrustedACLCommand("ls")
	if filepath.Dir(resolved) == tmpDir {
		t.Fatalf("resolved ACL command from untrusted PATH: %s", resolved)
	}
	if resolved == "ls" {
		t.Fatal("expected ACL command to resolve to a trusted absolute path or sentinel")
	}
}
