//go:build !windows

package main

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

// terminateProcessVerified is the Linux counterpart to the Windows
// implementation. It re-reads the process identity from /proc immediately
// before signalling so a recycled PID that now belongs to an unrelated process
// is never killed. The contract mirrors Windows exactly:
//   - (false, nil)   the PID is already gone (nothing to do)
//   - (false, error) the PID exists but its identity no longer matches, or a
//     syscall failed — the caller must treat this as a refusal to terminate
//   - (true, nil)    the verified process was terminated
func terminateProcessVerified(pid int, matches func(procInfo) bool) (bool, error) {
	if pid <= 0 {
		return false, errors.New("positive PID is required")
	}
	info, err := procInfoFromProc(pid)
	if err != nil {
		// The process disappeared between the caller's check and now, or is no
		// longer inspectable. Either way there is nothing verified to kill.
		return false, nil
	}
	if !matches(info) {
		return false, errors.New("process identity changed before termination")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if err == syscall.ESRCH {
			return false, nil
		}
		return false, fmt.Errorf("terminate process %d: %w", pid, err)
	}
	if waitProcessExit(pid, 5*time.Second) {
		return true, nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return false, fmt.Errorf("force terminate process %d: %w", pid, err)
	}
	_ = waitProcessExit(pid, 2*time.Second)
	return true, nil
}
