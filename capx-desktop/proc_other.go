//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// hideChildWindow is a no-op on non-Windows platforms (no console-window popups).
func hideChildWindow(cmd *exec.Cmd) {}

func detachBackendProcess(cmd *exec.Cmd) {}

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
	exe, args, err := backendProcessInfo(p.runtime.PID)
	if err != nil {
		return false
	}
	return backendIdentityMatchesArgs(p.runtime, exe, args)
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
