//go:build windows

package backgroundprocess

import (
	"os/exec"
	"syscall"
)

// Hide prevents console allocation, preserving process-tree, command-line and
// handle settings installed by the caller. HideWindow alone only hides an
// allocated console and may flash when the parent is a GUI application.
func Hide(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
}
