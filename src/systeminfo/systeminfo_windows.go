//go:build windows
// +build windows

package systeminfo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/winservices"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

func gatherOSVersion(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("cmd", "/C", "ver")
	if err != nil {
		return fmt.Errorf("failed to get OS version: %v", err)
	}
	sysInfo.OSVersion = strings.TrimSpace(string(out))
	return nil
}

func gatherInstalledPatches(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("wmic", "qfe", "get", "HotFixID")
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
	for _, keyPath := range keys {
		k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
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
	for i := range services {
		svcInfo := &services[i]
		if err := svcInfo.GetServiceDetail(); err != nil {
			continue
		}
		state := serviceStateToString(svcInfo.Status.State)
		sysInfo.RunningServices = append(sysInfo.RunningServices, ServiceInfo{Name: svcInfo.Name, Status: state})
	}
	return nil
}

func safeCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PATH=C:\\Windows\\System32;C:\\Windows")
	return cmd
}

func gatherUsers(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("net", "user")
	if err != nil {
		return err
	}
	sysInfo.Users = append(sysInfo.Users, parseNetList(out)...)
	return nil
}

func gatherGroups(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("net", "localgroup")
	if err != nil {
		return err
	}
	sysInfo.Groups = append(sysInfo.Groups, parseNetList(out)...)
	return nil
}

func gatherAdmins(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("net", "localgroup", "administrators")
	if err != nil {
		return err
	}
	sysInfo.Admins = append(sysInfo.Admins, parseNetList(out)...)
	return nil
}

func gatherScheduledTasks(sysInfo *SystemInfo) error {
	out, err := runCommandOutput("schtasks", "/Query", "/FO", "LIST")
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TaskName:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "TaskName:"))
			if name != "" {
				sysInfo.ScheduledTasks = append(sysInfo.ScheduledTasks, name)
			}
		}
	}
	return nil
}

func parseNetList(out []byte) []string {
	lines := strings.Split(string(out), "\n")
	results := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "The command") || strings.HasPrefix(line, "----") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			results = append(results, fields...)
		}
	}
	return results
}

func runCommandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := safeCommand(ctx, name, args...)
	return cmd.Output()
}

func serviceStateToString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "ContinuePending"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}
