//go:build windows

package backgroundprocess

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestHidePreservesAttributes(t *testing.T) {
	attributes := &syscall.SysProcAttr{CreationFlags: 0x00000004, CmdLine: "custom command line", NoInheritHandles: true}
	cmd := exec.Command("unused.exe")
	cmd.SysProcAttr = attributes
	Hide(cmd)
	Hide(cmd)
	if cmd.SysProcAttr != attributes || attributes.CreationFlags != 0x08000004 || !attributes.HideWindow || attributes.CmdLine != "custom command line" || !attributes.NoInheritHandles {
		t.Fatalf("background configuration lost caller attributes: %+v", cmd.SysProcAttr)
	}
}

func TestBackgroundProcessHasNoConsole(t *testing.T) {
	if os.Getenv("BACKGROUND_PROCESS_CONSOLE_PROBE") == "1" {
		console, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
		fmt.Printf("console=%d", console)
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := CommandContext(ctx, exe, "-test.run=^TestBackgroundProcessHasNoConsole$")
	cmd.Env = append(os.Environ(), "BACKGROUND_PROCESS_CONSOLE_PROBE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe failed: %v: %s", err, output)
	}
	if !bytes.Equal(output, []byte("console=0")) {
		t.Fatalf("background subprocess allocated a Windows console: %s", output)
	}
}
