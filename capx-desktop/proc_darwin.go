//go:build darwin

package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func backendProcessInfo(pid int) (string, []string, error) {
	if pid <= 0 {
		return "", nil, fmt.Errorf("invalid process id")
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil, err
	}
	return decodeDarwinProcessArgs(raw)
}
