//go:build !windows
// +build !windows

package systeminfo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func gatherOSVersion(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/etc/os-release")
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				sysInfo.OSVersion = strings.Trim(line[len("PRETTY_NAME="):], "\"")
				return nil
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	case "darwin":
		nameOut, err := exec.Command("sw_vers", "-productName").Output()
		if err != nil {
			return err
		}
		verOut, err := exec.Command("sw_vers", "-productVersion").Output()
		if err != nil {
			return err
		}
		sysInfo.OSVersion = fmt.Sprintf("%s %s", strings.TrimSpace(string(nameOut)), strings.TrimSpace(string(verOut)))
		return nil
	}
	sysInfo.OSVersion = runtime.GOOS
	return nil
}

func gatherInstalledPatches(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("dpkg-query", "-f", "${Package}\n", "-W").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, line)
				}
			}
			return nil
		}
		if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\n").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, line)
				}
			}
		}
	case "darwin":
		if out, err := exec.Command("softwareupdate", "--history").Output(); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "Software Update Tool") {
					sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, line)
				}
			}
		}
	}
	return nil
}

func gatherStartupPrograms(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		dirs := []string{"/etc/init.d", "/etc/rc.d", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range entries {
				sysInfo.StartupPrograms = append(sysInfo.StartupPrograms, e.Name())
			}
		}
	case "darwin":
		dirs := []string{"/Library/LaunchAgents", "/Library/LaunchDaemons", filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")}
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range entries {
				sysInfo.StartupPrograms = append(sysInfo.StartupPrograms, e.Name())
			}
		}
	}
	return nil
}

func gatherInstalledApps(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("dpkg-query", "-f", "${Package}\n", "-W").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledApps = append(sysInfo.InstalledApps, line)
				}
			}
			return nil
		}
		if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\n").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledApps = append(sysInfo.InstalledApps, line)
				}
			}
		}
	case "darwin":
		if entries, err := os.ReadDir("/Applications"); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".app") {
					sysInfo.InstalledApps = append(sysInfo.InstalledApps, strings.TrimSuffix(e.Name(), ".app"))
				}
			}
		}
		if out, err := exec.Command("brew", "list").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledApps = append(sysInfo.InstalledApps, line)
				}
			}
		}
	}
	return nil
}

func gatherRunningServices(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "list-units", "--type", "service", "--state", "running", "--no-legend", "--no-pager").Output()
		if err != nil {
			return nil
		}
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				sysInfo.RunningServices = append(sysInfo.RunningServices, ServiceInfo{Name: fields[0], Status: fields[2]})
			}
		}
	case "darwin":
		out, err := exec.Command("launchctl", "list").Output()
		if err != nil {
			return nil
		}
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "PID") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				status := "stopped"
				if fields[0] != "-" && fields[0] != "0" {
					status = "running"
				}
				sysInfo.RunningServices = append(sysInfo.RunningServices, ServiceInfo{Name: fields[2], Status: status})
			}
		}
	}
	return nil
}
