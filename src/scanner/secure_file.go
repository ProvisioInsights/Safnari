package scanner

import (
	"fmt"
	"os"
)

func rejectSymlinkTarget(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to overwrite non-regular file: %s", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func writePrivateFileNoSymlink(path string, data []byte) error {
	if err := rejectSymlinkTarget(path); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func readFileNoSymlink(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read through symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file: %s", path)
	}
	return os.ReadFile(path)
}
