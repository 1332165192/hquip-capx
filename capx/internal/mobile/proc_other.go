//go:build !windows

package mobile

import "syscall"

// hiddenSysProcAttr is a no-op outside Windows.
func hiddenSysProcAttr() *syscall.SysProcAttr { return nil }
