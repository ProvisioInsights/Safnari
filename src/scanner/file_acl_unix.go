//go:build !windows
// +build !windows

package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const trustedACLCommandPath = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/opt/homebrew/bin"

func getFileACL(path string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return runACLCommand("ls", "-led", path)
	case "linux":
		return runACLCommand("getfacl", "-cp", path)
	default:
		return "", errNotSupported
	}
}

func runACLCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolvedName := resolveTrustedACLCommand(name)
	cmd := exec.CommandContext(ctx, resolvedName, args...)
	cmd.Env = withTrustedACLPath(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return "", errNotSupported
		}
		return "", err
	}
	acl := strings.TrimSpace(string(out))
	if acl == "" {
		return "", nil
	}
	return acl, nil
}

func resolveTrustedACLCommand(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	for _, dir := range filepath.SplitList(trustedACLCommandPath) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			continue
		}
		return candidate
	}
	return filepath.Join("__safnari_command_not_found__", name)
}

func withTrustedACLPath(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if strings.HasPrefix(item, "PATH=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, "PATH="+trustedACLCommandPath)
}
