//go:build windows

package main

import "syscall"

// hiddenSysProcAttr returns the Windows SysProcAttr that hides the console
// window and detaches child processes from the parent console. It is applied
// to short-lived helper commands (PowerShell/netstat/adb) so the manager does
// not flash console windows on the desktop.
func hiddenSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
