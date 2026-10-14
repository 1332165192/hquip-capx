//go:build linux

package api

// Linux process enumeration via /proc: pid, name (comm), owner (Uid → name),
// and the full command line.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// listProcesses enumerates /proc to return pid, name, user, and cmdline.
func listProcesses() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc: %w", err)
	}
	procs := make([]procInfo, 0, len(entries)/2)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		p := procInfo{PID: uint32(pid)}
		p.Name = readComm(e.Name())
		p.User = readUser(e.Name())
		p.Cmd = readCmdline(e.Name())
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

func readComm(pid string) string {
	b, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readCmdline(pid string) string {
	b, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return ""
	}
	// cmdline is NUL-separated; join with spaces for display.
	s := strings.ReplaceAll(string(b), "\x00", " ")
	return strings.TrimSpace(s)
}

func readUser(pid string) string {
	f, err := os.Open(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return uidToName(fields[1])
			}
		}
	}
	return ""
}

func uidToName(uid string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return uid
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) >= 3 && parts[2] == uid {
			return parts[0]
		}
	}
	return uid
}
