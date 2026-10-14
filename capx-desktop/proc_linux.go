//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

func backendProcessInfo(pid int) (string, []string, error) {
	if pid <= 0 {
		return "", nil, fmt.Errorf("invalid process id")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", nil, err
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", nil, err
	}
	return exe, strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"), nil
}
