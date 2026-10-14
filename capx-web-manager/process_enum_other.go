//go:build !windows

package main

import (
	"os"
	"strconv"
)

// platformEnumerateAllProcesses walks /proc and returns process metadata
// (PID, executable path, full command line) for every process the current user
// can inspect. This is the Linux data source behind getProcessInfosWithin; the
// WMI script argument used on Windows is ignored because callers post-filter the
// returned set by executable base name and/or PID.
//
// Processes that cannot be read (permission denied, or exited mid-scan) are
// skipped rather than failing the whole enumeration, matching how WMI silently
// omits inaccessible processes.
func platformEnumerateAllProcesses() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	infos := make([]procInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		info, err := procInfoFromProc(pid)
		if err != nil {
			continue
		}
		infos = append(infos, info)
	}
	return infos, nil
}
