//go:build windows
// +build windows

package securefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func OpenPrivateNoSymlink(path string) (*os.File, error) {
	if err := rejectSymlinkParents(path); err != nil {
		return nil, err
	}
	if err := rejectExistingSymlink(path); err != nil {
		return nil, err
	}
	handle, err := createFile(path, windows.GENERIC_WRITE, windows.CREATE_ALWAYS)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	if err := ensureRegular(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func ReadNoSymlink(path string) ([]byte, error) {
	return ReadNoSymlinkMax(path, 0)
}

func ReadNoSymlinkMax(path string, maxBytes int64) ([]byte, error) {
	if err := rejectSymlinkParents(path); err != nil {
		return nil, err
	}
	if err := rejectExistingSymlink(path); err != nil {
		return nil, err
	}
	handle, err := createFile(path, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	defer f.Close()
	if err := ensureRegular(f, path); err != nil {
		return nil, err
	}
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

func createFile(path string, access uint32, disposition uint32) (windows.Handle, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	p, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func rejectExistingSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink path: %s", path)
	}
	return nil
}

func rejectSymlinkParents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	volume := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, volume)
	rest = strings.Trim(rest, `\/`)
	if rest == "" {
		return fmt.Errorf("invalid file path: %s", path)
	}
	parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' })
	current := volume + string(filepath.Separator)
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink parent: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("refusing non-directory parent: %s", current)
		}
	}
	return nil
}

func ensureRegular(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular file: %s", path)
	}
	return nil
}
