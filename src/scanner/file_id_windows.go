//go:build windows
// +build windows

package scanner

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func getFileID(path string, info os.FileInfo) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var data windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &data); err != nil {
		return ""
	}
	high := uint64(data.FileIndexHigh)
	low := uint64(data.FileIndexLow)
	fileID := (high << 32) | low
	return fmt.Sprintf("vol=%d,file=%d", data.VolumeSerialNumber, fileID)
}
