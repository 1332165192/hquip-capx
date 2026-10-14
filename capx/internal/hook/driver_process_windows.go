//go:build windows

package hook

import (
	"os/exec"
	"syscall"
)

func hideDriverWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
