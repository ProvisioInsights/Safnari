//go:build !windows
// +build !windows

package scanner

import (
	"fmt"
	"os"
	"syscall"
)

func getFileOwnership(path string) (string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil
	}
	uid := stat.Uid
	gid := stat.Gid
	return fmt.Sprintf("uid=%d, gid=%d", uid, gid), nil
}
