//go:build !windows
// +build !windows

package securefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

func OpenPrivateNoSymlink(path string) (*os.File, error) {
	dirfd, base, cleanup, err := openParentNoSymlink(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	fd, err := unix.Openat(dirfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := ensureRegular(fd, path); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func ReadNoSymlink(path string) ([]byte, error) {
	return ReadNoSymlinkMax(path, 0)
}

func ReadNoSymlinkMax(path string, maxBytes int64) ([]byte, error) {
	dirfd, base, cleanup, err := openParentNoSymlink(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	fd, err := unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := ensureRegular(fd, path); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if maxBytes > 0 {
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if info.Size() > maxBytes {
			return nil, fmt.Errorf("file too large: %s", path)
		}
		data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf("file too large: %s", path)
		}
		return data, nil
	}
	return io.ReadAll(f)
}

func WritePrivateNoSymlink(path string, data []byte) error {
	f, err := OpenPrivateNoSymlink(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func openParentNoSymlink(path string) (int, string, func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return -1, "", nil, err
	}
	abs = filepath.Clean(abs)
	base := filepath.Base(abs)
	if base == "." || base == string(filepath.Separator) {
		return -1, "", nil, fmt.Errorf("invalid file path: %s", path)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return -1, "", nil, err
	}
	resolvedPath := filepath.Join(resolvedParent, base)
	if canonicalDarwinPath(abs) != resolvedPath {
		return -1, "", nil, fmt.Errorf("refusing symlink parent: %s", path)
	}
	abs = resolvedPath

	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", nil, err
	}
	cleanup := func() { _ = unix.Close(fd) }

	dir := strings.Trim(filepath.Dir(abs), string(filepath.Separator))
	if dir == "" {
		return fd, base, cleanup, nil
	}
	for _, part := range strings.Split(dir, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			cleanup()
			return -1, "", nil, err
		}
		_ = unix.Close(fd)
		fd = next
		cleanup = func() { _ = unix.Close(fd) }
	}
	return fd, base, cleanup, nil
}

func canonicalDarwinPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, prefix := range []string{"/var", "/tmp", "/etc"} {
		if path == prefix {
			return "/private" + prefix
		}
		if strings.HasPrefix(path, prefix+"/") {
			return "/private" + path
		}
	}
	return path
}

func ensureRegular(fd int, path string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("refusing non-regular file: %s", path)
	}
	return nil
}
