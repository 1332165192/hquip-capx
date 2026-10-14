//go:build linux || darwin

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBackendIdentityFixtureChild(t *testing.T) {
	if os.Getenv("CAPX_PROCESS_IDENTITY_FIXTURE") != "1" {
		return
	}
	fmt.Println("ready")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestUnixBackendOwnershipAndStopOwnChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt := desktopRuntime{Exe: exe, StateDir: filepath.Join(root, `state "quote" space`), BaseURL: "http://127.0.0.1:19137", InstanceID: "owned-test", Generation: "owned-generation"}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBackendIdentityFixtureChild$", "--", "--addr", "127.0.0.1:19137", "--state-dir", rt.StateDir, "--instance-id", rt.InstanceID, "--generation", rt.Generation)
	cmd.Env = append(os.Environ(), "CAPX_PROCESS_IDENTITY_FIXTURE=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || reader.Text() != "ready" {
		t.Fatal("fixture child did not start")
	}
	rt.PID = cmd.Process.Pid
	owner, err := openOwnedBackend(rt)
	if err != nil || owner == nil {
		t.Fatalf("own child identity rejected: %v", err)
	}
	defer owner.Close()
	replacement := rt
	replacement.Generation = "replacement"
	if _, err := openOwnedBackend(replacement); err == nil {
		t.Fatal("replacement generation accepted")
	}
	if err := owner.Terminate(); err != nil {
		t.Fatal("stop owned child:", err)
	}
}
