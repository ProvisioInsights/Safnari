//go:build !windows

package output

import "os"

func renameSpoolFile(from, to string) error {
	return os.Rename(from, to)
}
