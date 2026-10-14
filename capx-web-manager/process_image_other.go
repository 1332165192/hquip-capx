//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// processExecutablePath resolves a PID to its on-disk executable by reading the
// kernel-maintained /proc/<pid>/exe symlink. This is the Linux counterpart to
// QueryFullProcessImageName on Windows and requires no external tooling.
func processExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("positive PID is required")
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("read process %d image: %w", pid, err)
	}
	// A replaced-on-disk binary is reported as "/path/to/exe (deleted)".
	target = strings.TrimSuffix(target, " (deleted)")
	if target == "" {
		return "", fmt.Errorf("process %d returned an empty executable path", pid)
	}
	return target, nil
}

// procInfoFromProc reads the executable path and full command line for a PID
// from /proc. The command line stored in /proc/<pid>/cmdline is NUL-delimited;
// it is rejoined with spaces so the shared identity matchers (which look for
// substrings such as "--capx-instance-id=") behave the same as on Windows.
func procInfoFromProc(pid int) (procInfo, error) {
	if pid <= 0 {
		return procInfo{}, errors.New("positive PID is required")
	}
	exe, err := processExecutablePath(pid)
	if err != nil {
		return procInfo{}, err
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return procInfo{}, fmt.Errorf("read process %d command line: %w", pid, err)
	}
	cmdline := strings.TrimRight(string(raw), "\x00")
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
	return procInfo{ProcessID: pid, ExecutablePath: exe, CommandLine: cmdline}, nil
}

// processAlive reports whether a PID currently exists using signal 0, which
// performs permission/existence checks without delivering a signal.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// waitProcessExit polls until the PID exits or the timeout elapses. It returns
// true if the process is gone.
func waitProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !processAlive(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type linuxManagedBrowserProcessHandle struct {
	pid int
}

// openManagedBrowserProcessHandle validates the PID exists and returns a handle
// that can query the image and terminate the managed browser. Unlike Windows
// there is no OS handle to hold open; the PID is used directly with signals.
func openManagedBrowserProcessHandle(pid int) (managedBrowserProcessHandle, error) {
	if pid <= 0 {
		return nil, errors.New("positive PID is required")
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return nil, fmt.Errorf("open managed browser process %d: %w", pid, err)
	}
	return &linuxManagedBrowserProcessHandle{pid: pid}, nil
}

func (process *linuxManagedBrowserProcessHandle) imagePath() (string, error) {
	return processExecutablePath(process.pid)
}

// terminate sends SIGTERM so Chrome can shut down cleanly (propagating to its
// child processes), then escalates to SIGKILL if the process is still present
// after a grace period. It returns false when the process had already exited.
func (process *linuxManagedBrowserProcessHandle) terminate() (bool, error) {
	if !processAlive(process.pid) {
		return false, nil
	}
	if err := syscall.Kill(process.pid, syscall.SIGTERM); err != nil {
		if err == syscall.ESRCH {
			return false, nil
		}
		return false, fmt.Errorf("terminate managed browser process %d: %w", process.pid, err)
	}
	if waitProcessExit(process.pid, 5*time.Second) {
		return true, nil
	}
	if err := syscall.Kill(process.pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return false, fmt.Errorf("force terminate managed browser process %d: %w", process.pid, err)
	}
	_ = waitProcessExit(process.pid, 2*time.Second)
	return true, nil
}

func (process *linuxManagedBrowserProcessHandle) close() {}
