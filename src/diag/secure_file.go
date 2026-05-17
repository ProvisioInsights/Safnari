package diag

import (
	"os"

	"safnari/internal/securefile"
)

func openPrivateFileNoSymlink(path string) (*os.File, error) {
	return securefile.OpenPrivateNoSymlink(path)
}

func writePrivateFileNoSymlink(path string, data []byte) error {
	return securefile.WritePrivateNoSymlink(path, data)
}
