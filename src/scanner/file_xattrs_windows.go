//go:build windows
// +build windows

package scanner

func getXattrs(path string, maxValueSize int) (map[string]string, error) {
	return nil, errNotSupported
}
