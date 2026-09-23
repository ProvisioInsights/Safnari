//go:build windows

package output

// Windows file flush and atomic rename provide the supported spool boundary;
// a directory handle cannot be flushed through os.File.Sync on Windows.
func syncSpoolDir(string) error { return nil }
