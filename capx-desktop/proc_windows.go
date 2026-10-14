//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

type windowsBackendProcess struct{ handle windows.Handle }

func openOwnedBackend(rt desktopRuntime) (backendStopProcess, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(rt.PID))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &windowsBackendProcess{h}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d" | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress`, rt.PID))
	hideChildWindow(cmd)
	out, err := cmd.Output()
	var info struct {
		ExecutablePath string
		CommandLine    string
	}
	if err != nil || json.Unmarshal(out, &info) != nil || !backendIdentityMatches(rt, info.ExecutablePath, info.CommandLine) {
		p.Close()
		return nil, errors.New("process generation, executable or command line does not match desktop runtime")
	}
	// The held handle refers to the original process even if its numeric PID is
	// subsequently recycled. Both waiting and force termination use this handle.
	return p, nil
}

func (p *windowsBackendProcess) Running() bool {
	status, err := windows.WaitForSingleObject(p.handle, 0)
	return err != nil || status != windows.WAIT_OBJECT_0
}
func (p *windowsBackendProcess) Terminate() error {
	if !p.Running() {
		return nil
	}
	if err := windows.TerminateProcess(p.handle, 1); err != nil {
		return err
	}
	status, err := windows.WaitForSingleObject(p.handle, 5000)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 {
		return errors.New("backend did not exit after termination")
	}
	return nil
}
func (p *windowsBackendProcess) Close() { _ = windows.CloseHandle(p.handle) }

// hideChildWindow stops a spawned console process (capx-captured.exe / taskkill /
// powershell) from popping up its own black console window when launched from
// this GUI app. CREATE_NO_WINDOW prevents the child from allocating a console.
func hideChildWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}

// detachBackendProcess starts capx-captured.exe as an independent background
// process. The backend must keep running after the Wails desktop window exits.
func detachBackendProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CreationFlags: 0x00000008 | // DETACHED_PROCESS
			0x00000200 | // CREATE_NEW_PROCESS_GROUP
			0x08000000, // CREATE_NO_WINDOW
	}
}

func backendProcessPath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	for {
		n := uint32(len(buf))
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), true
		}
		if len(buf) >= 32768 {
			return "", false
		}
		buf = make([]uint16, len(buf)*2)
	}
}
