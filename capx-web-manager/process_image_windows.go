//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func processExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("positive PID is required")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	return processExecutablePathFromHandle(handle, pid)
}

type windowsManagedBrowserProcessHandle struct {
	pid    int
	handle windows.Handle
}

func openManagedBrowserProcessHandle(pid int) (managedBrowserProcessHandle, error) {
	if pid <= 0 {
		return nil, errors.New("positive PID is required")
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, fmt.Errorf("open managed browser process %d: %w", pid, err)
	}
	return &windowsManagedBrowserProcessHandle{pid: pid, handle: handle}, nil
}

func (process *windowsManagedBrowserProcessHandle) imagePath() (string, error) {
	return processExecutablePathFromHandle(process.handle, process.pid)
}

func (process *windowsManagedBrowserProcessHandle) terminate() (bool, error) {
	if status, err := windows.WaitForSingleObject(process.handle, 0); err == nil && status == windows.WAIT_OBJECT_0 {
		return false, nil
	}
	if err := windows.TerminateProcess(process.handle, 1); err != nil {
		if status, waitErr := windows.WaitForSingleObject(process.handle, 0); waitErr == nil && status == windows.WAIT_OBJECT_0 {
			return false, nil
		}
		return false, fmt.Errorf("terminate managed browser process %d: %w", process.pid, err)
	}
	_, _ = windows.WaitForSingleObject(process.handle, 5000)
	return true, nil
}

func (process *windowsManagedBrowserProcessHandle) close() {
	_ = windows.CloseHandle(process.handle)
}

func processExecutablePathFromHandle(handle windows.Handle, pid int) (string, error) {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", fmt.Errorf("query process %d image: %w", pid, err)
	}
	if size == 0 {
		return "", fmt.Errorf("process %d returned an empty executable path", pid)
	}
	return windows.UTF16ToString(buffer[:size]), nil
}
