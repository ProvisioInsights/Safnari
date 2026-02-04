//go:build !windows
// +build !windows

package scanner

func getAlternateDataStreams(path string) ([]string, error) {
	return nil, errNotSupported
}
