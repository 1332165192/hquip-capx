package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// findLoopbackListenerPIDFromProc is the Linux equivalent of the netstat-based
// discovery used on Windows. It finds the socket inode that is LISTENing on
// 127.0.0.1:port (or the IPv6 loopback) in /proc/net/tcp{,6}, then maps that
// inode back to the owning PID by scanning /proc/<pid>/fd. Its error semantics
// mirror parseNetstatListenerPID: a missing listener and multiple conflicting
// owners are both rejected.
func findLoopbackListenerPIDFromProc(port int) (int, error) {
	inodes := map[string]struct{}{}
	readAny := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		readAny = true
		found, err := parseProcNetListenerInodes(string(data), port)
		if err != nil {
			return 0, err
		}
		for _, inode := range found {
			inodes[inode] = struct{}{}
		}
	}
	if !readAny {
		return 0, fmt.Errorf("query TCP listeners via /proc/net/tcp: not available")
	}
	if len(inodes) == 0 {
		return 0, fmt.Errorf("no TCP listener found on 127.0.0.1:%d", port)
	}
	return procListenerInodeToPID(inodes, port)
}

// parseProcNetListenerInodes extracts the socket inodes of LISTEN sockets bound
// to a loopback address on the given port. The content is the raw text of a
// /proc/net/tcp or /proc/net/tcp6 file. Kept independent of any filesystem
// access so it can be unit-tested on every platform.
func parseProcNetListenerInodes(content string, port int) ([]string, error) {
	const listenState = "0A" // TCP_LISTEN in /proc/net/tcp
	var inodes []string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if !strings.EqualFold(fields[3], listenState) {
			continue
		}
		localAddr := fields[1]
		colon := strings.LastIndex(localAddr, ":")
		if colon <= 0 || colon == len(localAddr)-1 {
			continue
		}
		hexPort := localAddr[colon+1:]
		parsedPort, err := strconv.ParseInt(hexPort, 16, 32)
		if err != nil || int(parsedPort) != port {
			continue
		}
		if !isProcLoopbackAddr(localAddr[:colon]) {
			continue
		}
		inodes = append(inodes, fields[9])
	}
	return inodes, nil
}

// isProcLoopbackAddr reports whether a hex-encoded /proc/net address is a
// loopback address. Only 127.0.0.1 and ::1 (plus the IPv4-mapped form) are
// accepted, mirroring the Windows parser's strict "127.0.0.1" check.
func isProcLoopbackAddr(hexAddr string) bool {
	switch strings.ToUpper(hexAddr) {
	case "0100007F": // IPv4 127.0.0.1 (little-endian words)
		return true
	case "00000000000000000000000001000000": // IPv6 ::1
		return true
	case "0000000000000000FFFF00000100007F": // IPv4-mapped ::ffff:127.0.0.1
		return true
	default:
		return false
	}
}

// procListenerInodeToPID resolves the PID that owns any of the given socket
// inodes by scanning every /proc/<pid>/fd symlink for "socket:[<inode>]".
func procListenerInodeToPID(inodes map[string]struct{}, port int) (int, error) {
	targets := make(map[string]struct{}, len(inodes))
	for inode := range inodes {
		targets["socket:["+inode+"]"] = struct{}{}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}
	selectedPID := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := "/proc/" + entry.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or fd table is not readable
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if _, ok := targets[link]; ok {
				if selectedPID != 0 && selectedPID != pid {
					return 0, fmt.Errorf("multiple processes listen on 127.0.0.1:%d", port)
				}
				selectedPID = pid
				break
			}
		}
	}
	if selectedPID == 0 {
		return 0, fmt.Errorf("no process owns the listener on 127.0.0.1:%d", port)
	}
	return selectedPID, nil
}
