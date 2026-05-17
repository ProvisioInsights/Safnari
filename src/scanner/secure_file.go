package scanner

import (
	"safnari/internal/securefile"
)

func writePrivateFileNoSymlink(path string, data []byte) error {
	return securefile.WritePrivateNoSymlink(path, data)
}

func readFileNoSymlink(path string) ([]byte, error) {
	return securefile.ReadNoSymlink(path)
}

func readFileNoSymlinkMax(path string, maxBytes int64) ([]byte, error) {
	return securefile.ReadNoSymlinkMax(path, maxBytes)
}
