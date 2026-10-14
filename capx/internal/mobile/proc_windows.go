//go:build windows

package mobile

import "syscall"

// hiddenSysProcAttr keeps adb.exe from flashing a console window when capx runs
// as a background daemon. 0x08000000 is CREATE_NO_WINDOW.
func hiddenSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
