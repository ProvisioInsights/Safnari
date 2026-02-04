//go:build !windows
// +build !windows

package scanner

func getFileACL(path string) (string, error) {
	return "", errNotSupported
}
