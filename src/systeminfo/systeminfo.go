package systeminfo

import (
	"fmt"
	"net"
	"time"

	"safnari/config"
	"safnari/logger"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type SystemInfo struct {
	OSVersion         string           `json:"os_version"`
	InstalledPatches  []string         `json:"installed_patches"`
	RunningProcesses  []ProcessInfo    `json:"running_processes"`
	StartupPrograms   []string         `json:"startup_programs"`
	InstalledApps     []string         `json:"installed_apps"`
	NetworkInterfaces []InterfaceInfo  `json:"network_interfaces"`
	OpenConnections   []ConnectionInfo `json:"open_connections"`
	RunningServices   []ServiceInfo    `json:"running_services"`
	Users             []string         `json:"users"`
	Groups            []string         `json:"groups"`
	Admins            []string         `json:"admins"`
	ScheduledTasks    []string         `json:"scheduled_tasks"`
}

type ProcessInfo struct {
	PID           int32   `json:"pid"`
	PPID          int32   `json:"ppid,omitempty"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float32 `json:"memory_percent,omitempty"`
	Cmdline       string  `json:"cmdline,omitempty"`
	Username      string  `json:"username,omitempty"`
	Exe           string  `json:"exe,omitempty"`
	StartTime     string  `json:"start_time,omitempty"`
}

func GetSystemInfo(cfg *config.Config) (*SystemInfo, error) {
	sysInfo := &SystemInfo{}

	if cfg.CollectSystemInfo {
		if err := gatherOSVersion(sysInfo); err != nil {
			logger.Warnf("Failed to gather OS version: %v", err)
		}

		if err := gatherInstalledPatches(sysInfo); err != nil {
			logger.Warnf("Failed to gather installed patches: %v", err)
		}

		if err := gatherStartupPrograms(sysInfo); err != nil {
			logger.Warnf("Failed to gather startup programs: %v", err)
		}

		if err := gatherInstalledApps(sysInfo); err != nil {
			logger.Warnf("Failed to gather installed applications: %v", err)
		}

		if err := gatherNetworkInterfaces(sysInfo); err != nil {
			logger.Warnf("Failed to gather network interfaces: %v", err)
		}

		if err := gatherOpenConnections(sysInfo); err != nil {
			logger.Warnf("Failed to gather network connections: %v", err)
		}

		if err := gatherRunningServices(sysInfo); err != nil {
			logger.Warnf("Failed to gather running services: %v", err)
		}
		if cfg.CollectUsers {
			if err := gatherUsers(sysInfo); err != nil {
				logger.Warnf("Failed to gather users: %v", err)
			}
		}
		if cfg.CollectGroups {
			if err := gatherGroups(sysInfo); err != nil {
				logger.Warnf("Failed to gather groups: %v", err)
			}
		}
		if cfg.CollectAdmins {
			if err := gatherAdmins(sysInfo); err != nil {
				logger.Warnf("Failed to gather admins: %v", err)
			}
		}
		if cfg.CollectScheduled {
			if err := gatherScheduledTasks(sysInfo); err != nil {
				logger.Warnf("Failed to gather scheduled tasks: %v", err)
			}
		}
	}

	if cfg.ScanProcesses {
		if err := gatherRunningProcesses(sysInfo, cfg.ExtendedProcessInfo); err != nil {
			logger.Warnf("Failed to gather running processes: %v", err)
		}
	}

	return sysInfo, nil
}

func gatherRunningProcesses(sysInfo *SystemInfo, extended bool) error {
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("failed to get running processes: %v", err)
	}

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		procInfo := ProcessInfo{
			PID:  p.Pid,
			Name: name,
		}

		if extended {
			cpuPercent, err := p.CPUPercent()
			if err == nil {
				procInfo.CPUPercent = cpuPercent
			}

			memPercent, err := p.MemoryPercent()
			if err == nil {
				procInfo.MemoryPercent = memPercent
			}

			cmdline, err := p.Cmdline()
			if err == nil {
				procInfo.Cmdline = cmdline
			}

			username, err := p.Username()
			if err == nil {
				procInfo.Username = username
			}

			exe, err := p.Exe()
			if err == nil {
				procInfo.Exe = exe
			}

			ppid, err := p.Ppid()
			if err == nil {
				procInfo.PPID = ppid
			}
			startMillis, err := p.CreateTime()
			if err == nil && startMillis > 0 {
				procInfo.StartTime = time.Unix(0, startMillis*int64(time.Millisecond)).UTC().Format(time.RFC3339)
			}
		}

		sysInfo.RunningProcesses = append(sysInfo.RunningProcesses, procInfo)
	}

	return nil
}

type InterfaceInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

type ConnectionInfo struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	Status     string `json:"status"`
	PID        int32  `json:"pid"`
}

type ServiceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func gatherNetworkInterfaces(sysInfo *SystemInfo) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}
	for _, iface := range ifaces {
		info := InterfaceInfo{Name: iface.Name, MAC: iface.HardwareAddr.String()}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}
		sysInfo.NetworkInterfaces = append(sysInfo.NetworkInterfaces, info)
	}
	return nil
}

func gatherOpenConnections(sysInfo *SystemInfo) error {
	conns, err := gnet.Connections("all")
	if err != nil {
		return nil
	}
	for _, c := range conns {
		connInfo := ConnectionInfo{
			LocalAddr:  fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
			Status:     c.Status,
			PID:        c.Pid,
		}
		sysInfo.OpenConnections = append(sysInfo.OpenConnections, connInfo)
	}
	return nil
}

// Implement gatherOSVersion, gatherInstalledPatches, gatherStartupPrograms, gatherInstalledApps as per previous implementations or stubs
