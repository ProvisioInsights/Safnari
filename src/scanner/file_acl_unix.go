//go:build !windows
// +build !windows

package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/opt/homebrew/bin")
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
