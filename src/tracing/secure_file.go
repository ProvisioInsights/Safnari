package tracing

import (
	"os"

	"safnari/internal/securefile"
)

func openPrivateFileNoSymlink(path string) (*os.File, error) {
	return securefile.OpenPrivateNoSymlink(path)
}
