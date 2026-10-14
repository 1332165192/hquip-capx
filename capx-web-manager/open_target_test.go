package main

import (
	"runtime"
	"testing"
)

func TestOpenSystemTargetRejectsEmbeddedNUL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ShellExecute validation")
	}
	if err := openSystemTarget("http://127.0.0.1:18990/\x00invalid"); err == nil {
		t.Fatal("embedded NUL target was accepted")
	}
}
