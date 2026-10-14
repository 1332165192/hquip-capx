//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func terminateProcessVerified(pid int, matches func(procInfo) bool) (bool, error) {
	if pid <= 0 {
		return false, errors.New("positive PID is required")
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil
		}
		return false, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	infos, err := getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, pid))
	if err != nil {
		return false, err
	}
	if len(infos) != 1 {
		return false, nil
	}
	if !matches(infos[0]) {
		return false, errors.New("process identity changed before termination")
	}
	if err := windows.TerminateProcess(handle, 1); err != nil {
		if status, waitErr := windows.WaitForSingleObject(handle, 0); waitErr == nil && status == windows.WAIT_OBJECT_0 {
			return false, nil
		}
		return false, fmt.Errorf("terminate process %d: %w", pid, err)
	}
	_, _ = windows.WaitForSingleObject(handle, 5000)
	return true, nil
}
