//go:build !windows

package main

import "syscall"

// hiddenSysProcAttr is a no-op on non-Windows platforms: there is no console
// window to hide, so child processes inherit the default attributes. The
// callers guard the assignment behind runtime.GOOS == "windows", so this value
// is never actually attached to a command off Windows; it exists so the shared
// call sites compile on every platform.
func hiddenSysProcAttr() *syscall.SysProcAttr {
	return nil
}
