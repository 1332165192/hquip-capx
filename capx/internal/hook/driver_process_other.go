//go:build !windows

package hook

import "os/exec"

func hideDriverWindow(cmd *exec.Cmd) {}
