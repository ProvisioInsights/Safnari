//go:build !windows

package output

import (
	"fmt"
	"os"
)

func ensurePrivateSpoolDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("spool directory must be private and not a symlink: %s", dir)
	}
	return nil
}
