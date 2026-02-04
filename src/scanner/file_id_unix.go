//go:build !windows
// +build !windows

package scanner

import (
	"fmt"
	"os"
	"syscall"
)

func getFileID(path string, info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return ""
	}
	return fmt.Sprintf("dev=%d,inode=%d", stat.Dev, stat.Ino)
}
