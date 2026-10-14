//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func openSystemTarget(target string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", target).Start()
	}
	if runtime.GOOS == "linux" {
		return exec.Command("xdg-open", target).Start()
	}
	return fmt.Errorf("opening system targets is unsupported on %s", runtime.GOOS)
}
