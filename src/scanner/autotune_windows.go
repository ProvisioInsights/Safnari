//go:build windows
// +build windows

package scanner

func detectDiskType() string {
	return "unknown"
}
