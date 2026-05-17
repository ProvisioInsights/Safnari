package output

import (
	"fmt"
	"os"
)

func openPrivateFileNoSymlink(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to write through symlink: %s", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to overwrite non-regular file: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}
