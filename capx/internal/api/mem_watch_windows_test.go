//go:build windows && amd64

package api

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// childSrc is a tiny target: it prints the address of a global it then writes
// to in a loop, so the watcher has a stable address to break on.
const childSrc = `package main
import ("fmt";"os";"sync/atomic";"time";"unsafe")
var Target int64
func main(){
	fmt.Printf("ADDR=0x%x\n", uintptr(unsafe.Pointer(&Target)))
	os.Stdout.Sync()
	for { atomic.AddInt64(&Target, 1); time.Sleep(2*time.Millisecond) }
}
`

// TestWindowsWatcherCatchesWrites builds a target that writes to a known global
// in a loop, arms a write watchpoint on it, and asserts the watcher records the
// faulting instruction. Skips when the debugger cannot attach (restricted env).
func TestWindowsWatcherCatchesWrites(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "target.go")
	if err := os.WriteFile(src, []byte(childSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "target.exe")
	build := exec.Command("go", "build", "-o", exe, src)
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build target (%v): %s", err, out)
	}

	cmd := exec.Command(exe)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// Read the target address the child prints.
	br := bufio.NewReader(stdout)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ADDR=0x") {
		t.Fatalf("bad child output %q (err %v)", line, err)
	}
	addr, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "ADDR=0x")), 16, 64)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}

	wt, err := startWatcher(uint32(cmd.Process.Pid), []watchSpec{{Addr: addr, Size: 8, Mode: "w"}})
	if err != nil {
		t.Skipf("watcher could not attach (need same-user/admin debug rights): %v", err)
	}
	defer wt.Stop()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if hits := wt.Hits(); len(hits) > 0 {
			if hits[0].Count == 0 {
				t.Fatalf("hit recorded with zero count")
			}
			t.Logf("caught writer rip=%s insn=%q count=%d", hits[0].RIP, hits[0].Insn, hits[0].Count)
			return // success: at least one writing instruction was captured
		}
		if err := wt.Err(); err != nil {
			t.Fatalf("watcher error: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("no write hits captured within timeout")
}
