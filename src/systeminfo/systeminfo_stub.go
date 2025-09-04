//go:build !windows
// +build !windows

package systeminfo

func gatherOSVersion(sysInfo *SystemInfo) error {
	// Stub implementation for non-Windows platforms
	sysInfo.OSVersion = "Unknown OS"
	return nil
}

func gatherInstalledPatches(sysInfo *SystemInfo) error {
	// Stub implementation
	return nil
}

func gatherStartupPrograms(sysInfo *SystemInfo) error {
	// Stub implementation
	return nil
}

func gatherInstalledApps(sysInfo *SystemInfo) error {
	// Stub implementation
	return nil
}

func gatherRunningServices(sysInfo *SystemInfo) error {
	// Stub implementation
	return nil
}
