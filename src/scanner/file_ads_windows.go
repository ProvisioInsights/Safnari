//go:build windows
// +build windows

package scanner

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxStreamName = windows.MAX_PATH + 36

type win32FindStreamData struct {
	StreamSize int64
	StreamName [maxStreamName]uint16
}

func getAlternateDataStreams(path string) ([]string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	k32 := windows.NewLazySystemDLL("kernel32.dll")
	procFindFirst := k32.NewProc("FindFirstStreamW")
	procFindNext := k32.NewProc("FindNextStreamW")
	procFindClose := k32.NewProc("FindClose")

	var data win32FindStreamData
	handle, _, err := procFindFirst.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&data)),
		uintptr(0),
	)
	if handle == uintptr(windows.InvalidHandle) {
		if err == windows.ERROR_HANDLE_EOF || err == windows.ERROR_FILE_NOT_FOUND {
			return nil, nil
		}
		return nil, err
	}
	defer procFindClose.Call(handle)

	streams := []string{}
	for {
		name := windows.UTF16ToString(data.StreamName[:])
		if name != "" && name != "::$DATA" {
			streams = append(streams, normalizeStreamName(name))
		}
		r1, _, err := procFindNext.Call(handle, uintptr(unsafe.Pointer(&data)))
		if r1 == 0 {
			if err == windows.ERROR_HANDLE_EOF {
				break
			}
			return streams, err
		}
	}
	if len(streams) == 0 {
		return nil, nil
	}
	return streams, nil
}

func normalizeStreamName(name string) string {
	if strings.HasPrefix(name, ":") {
		name = name[1:]
	}
	if strings.HasSuffix(name, ":$DATA") {
		name = strings.TrimSuffix(name, ":$DATA")
	}
	return name
}
