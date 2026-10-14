//go:build !windows

package backgroundprocess

import "os/exec"

func Hide(_ *exec.Cmd) {}
