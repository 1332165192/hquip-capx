//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// hideChildWindow is a no-op on non-Windows platforms (no console-window popups).
func hideChildWindow(cmd *exec.Cmd) {}

func detachBackendProcess(cmd *exec.Cmd) {}

func backendProcessPath(pid int) (string, bool) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return path, err == nil
}

type unixBackendProcess struct{ runtime desktopRuntime }

func openOwnedBackend(rt desktopRuntime) (backendStopProcess, error) {
	p := &unixBackendProcess{rt}
	if !p.Running() {
		return nil, nil
	}
	if !p.matches() {
		return nil, errors.New("cannot verify backend executable and generation")
	}
	return p, nil
}
func (p *unixBackendProcess) Running() bool {
	err := syscall.Kill(p.runtime.PID, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
func (p *unixBackendProcess) matches() bool {
	exe, ok := backendProcessPath(p.runtime.PID)
	if !ok {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.runtime.PID))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	for i, arg := range args {
		if strings.ContainsAny(arg, " \t") {
			args[i] = `"` + arg + `"`
		}
	}
	return backendIdentityMatches(p.runtime, exe, strings.Join(args, " "))
}
func (p *unixBackendProcess) Terminate() error {
	if !p.Running() {
		return nil
	}
	if !p.matches() {
		return errors.New("backend identity changed before force termination")
	}
	process, err := os.FindProcess(p.runtime.PID)
	if err != nil {
		return err
	}
	return process.Kill()
}
func (p *unixBackendProcess) Close() {}
