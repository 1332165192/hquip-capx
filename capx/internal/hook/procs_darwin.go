//go:build darwin

package hook

import (
	"os/exec"
	"strconv"
	"strings"
)

func (m *Manager) ListProcesses() ([]Process, error) {
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return []Process{}, nil
	}
	var procs []Process
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		name := fields[1]
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		procs = append(procs, Process{PID: uint32(pid), Name: name})
	}
	return procs, nil
}
