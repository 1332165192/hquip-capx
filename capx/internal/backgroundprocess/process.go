// Package backgroundprocess constructs subprocesses that communicate through
// pipes without creating a separate Windows console. Visible application
// windows must use their own launch path rather than these helpers.
package backgroundprocess

import (
	"context"
	"os/exec"
)

func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	Hide(cmd)
	return cmd
}

func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	Hide(cmd)
	return cmd
}
