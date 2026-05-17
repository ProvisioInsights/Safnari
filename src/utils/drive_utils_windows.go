//go:build windows
// +build windows

package utils

import (
	"golang.org/x/sys/windows"
)

func GetLocalDrives() ([]string, error) {
	drives := []string{}
	driveBits, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	for i := uint(0); i < 26; i++ {
		if driveBits&(1<<i) != 0 {
			driveLetter := string('A' + rune(i))
			root := driveLetter + ":\\"
			if windows.GetDriveType(windows.StringToUTF16Ptr(root)) == windows.DRIVE_FIXED {
				drives = append(drives, root)
			}
		}
	}
	return drives, nil
}
