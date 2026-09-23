//go:build !windows

package output

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockSpoolFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockSpoolFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
