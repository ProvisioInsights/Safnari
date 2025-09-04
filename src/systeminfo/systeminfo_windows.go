//go:build windows
// +build windows

package systeminfo

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/shirou/gopsutil/v3/winservices"
	"golang.org/x/sys/windows/registry"
)

func gatherOSVersion(sysInfo *SystemInfo) error {
	out, err := exec.Command("cmd", "/C", "ver").Output()
	if err != nil {
		return fmt.Errorf("failed to get OS version: %v", err)
	}
	sysInfo.OSVersion = strings.TrimSpace(string(out))
	return nil
}

func gatherInstalledPatches(sysInfo *SystemInfo) error {
	out, err := exec.Command("wmic", "qfe", "get", "HotFixID").Output()
	if err != nil {
		return fmt.Errorf("failed to get installed patches: %v", err)
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		patch := strings.TrimSpace(line)
		if patch != "" {
			sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, patch)
		}
	}
	return nil
}

func gatherStartupPrograms(sysInfo *SystemInfo) error {
	// Read startup entries from registry
	keys := []string{
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}

	for _, keyPath := range keys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
		if err == nil {
			defer k.Close()
			names, err := k.ReadValueNames(0)
			if err == nil {
				sysInfo.StartupPrograms = append(sysInfo.StartupPrograms, names...)
			}
		}
	}
	return nil
}

func gatherInstalledApps(sysInfo *SystemInfo) error {
	// Read installed applications from registry
	uninstallPaths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	for _, path := range uninstallPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()

		subkeys, err := k.ReadSubKeyNames(0)
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			appKey, err := registry.OpenKey(k, subkey, registry.READ)
			if err != nil {
				continue
			}
			name, _, err := appKey.GetStringValue("DisplayName")
			if err == nil && name != "" {
				sysInfo.InstalledApps = append(sysInfo.InstalledApps, name)
			}
			appKey.Close()
		}
	}
	return nil
}

func gatherRunningServices(sysInfo *SystemInfo) error {
	services, err := winservices.ListServices()
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}
	for _, s := range services {
		status, err := s.Status()
		if err != nil {
			continue
		}
		sysInfo.RunningServices = append(sysInfo.RunningServices, ServiceInfo{Name: s.Name, Status: status})
	}
	return nil
}
