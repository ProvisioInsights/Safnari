//go:build !windows
// +build !windows

package systeminfo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	usersFilePath  = "/etc/passwd"
	groupsFilePath = "/etc/group"

	linuxScheduledTaskDirs = []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
	}
	linuxCrontabPath = "/etc/crontab"

	darwinScheduledTaskDirs = func() []string {
		return []string{
			"/Library/LaunchAgents",
			"/Library/LaunchDaemons",
			filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents"),
		}
	}
	darwinCrontabOutput = func() ([]byte, error) {
		return runCommandOutput("crontab", "-l")
	}
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
		nameOut, err := runCommandOutput("sw_vers", "-productName")
		if err != nil {
			return err
		}
		verOut, err := runCommandOutput("sw_vers", "-productVersion")
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
		if out, err := runCommandOutput("dpkg-query", "-f", "${Package}\n", "-W"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, line)
				}
			}
			return nil
		}
		if out, err := runCommandOutput("rpm", "-qa", "--qf", "%{NAME}\n"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledPatches = append(sysInfo.InstalledPatches, line)
				}
			}
		}
	case "darwin":
		if out, err := runCommandOutput("softwareupdate", "--history"); err == nil {
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
		if out, err := runCommandOutput("dpkg-query", "-f", "${Package}\n", "-W"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					sysInfo.InstalledApps = append(sysInfo.InstalledApps, line)
				}
			}
			return nil
		}
		if out, err := runCommandOutput("rpm", "-qa", "--qf", "%{NAME}\n"); err == nil {
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
		if out, err := runCommandOutput("brew", "list"); err == nil {
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
		out, err := runCommandOutput("systemctl", "list-units", "--type", "service", "--state", "running", "--no-legend", "--no-pager")
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
		out, err := runCommandOutput("launchctl", "list")
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

func gatherUsers(sysInfo *SystemInfo) error {
	users, err := readColonFile(usersFilePath)
	if err != nil {
		return err
	}
	sysInfo.Users = append(sysInfo.Users, users...)
	return nil
}

func gatherGroups(sysInfo *SystemInfo) error {
	groups, err := readColonFile(groupsFilePath)
	if err != nil {
		return err
	}
	sysInfo.Groups = append(sysInfo.Groups, groups...)
	return nil
}

func gatherAdmins(sysInfo *SystemInfo) error {
	groups, err := readColonFile(groupsFilePath)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if g == "sudo" || g == "wheel" || g == "admin" {
			sysInfo.Admins = append(sysInfo.Admins, g)
		}
	}
	return nil
}

func gatherScheduledTasks(sysInfo *SystemInfo) error {
	switch runtime.GOOS {
	case "linux":
		sysInfo.ScheduledTasks = append(sysInfo.ScheduledTasks, collectScheduledTaskPaths(linuxScheduledTaskDirs)...)
		if data, err := os.ReadFile(linuxCrontabPath); err == nil {
			sysInfo.ScheduledTasks = appendParsedCronTasks(sysInfo.ScheduledTasks, data)
		}
	case "darwin":
		sysInfo.ScheduledTasks = append(sysInfo.ScheduledTasks, collectScheduledTaskPaths(darwinScheduledTaskDirs())...)
		if out, err := darwinCrontabOutput(); err == nil {
			sysInfo.ScheduledTasks = appendParsedCronTasks(sysInfo.ScheduledTasks, out)
		}
	}
	return nil
}

func collectScheduledTaskPaths(dirs []string) []string {
	tasks := make([]string, 0)
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			tasks = append(tasks, filepath.Join(d, e.Name()))
		}
	}
	return tasks
}

func appendParsedCronTasks(tasks []string, data []byte) []string {
	return append(tasks, parseCronLines(data)...)
}

func safeCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/opt/homebrew/bin")
	return cmd
}

func runCommandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := safeCommand(ctx, name, args...)
	return cmd.Output()
}

func readColonFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) > 0 && parts[0] != "" {
			lines = append(lines, parts[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return lines, err
	}
	return lines, nil
}

func parseCronLines(data []byte) []string {
	lines := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
