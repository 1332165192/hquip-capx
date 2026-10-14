package main

import (
	"encoding/binary"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDarwinArgsKeepEmptyArgumentsAndExcludeEnvironment(t *testing.T) {
	exe := "/Applications/capx desktop.app/Contents/MacOS/capx-captured"
	args := []string{exe, "--addr", "127.0.0.1:19091", "", "--state-dir", `/tmp/state "quoted" space`, "--generation=g", "--instance-id=d"}
	raw := make([]byte, 4)
	binary.NativeEndian.PutUint32(raw, uint32(len(args)))
	raw = append(raw, []byte(exe+"\x00\x00\x00")...)
	for _, arg := range args {
		raw = append(raw, []byte(arg+"\x00")...)
	}
	raw = append(raw, []byte("PRIVATE_ENV=must-not-be-arguments\x00")...)
	gotExe, gotArgs, err := decodeDarwinProcessArgs(raw)
	if err != nil || gotExe != exe || !reflect.DeepEqual(gotArgs, args) {
		t.Fatalf("process argument decoding failed: %v", err)
	}
	if _, _, err := decodeDarwinProcessArgs(raw[:len(raw)-len("PRIVATE_ENV=must-not-be-arguments\x00")-1]); err == nil {
		t.Fatal("accepted truncated argv")
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0}, {0, 0, 0, 0, 'x', 0}, {255, 255, 255, 255, 'x', 0}} {
		if _, _, err := decodeDarwinProcessArgs(bad); err == nil {
			t.Fatal("accepted invalid process data")
		}
	}
}

func TestBackendArgumentIdentityRejectsReplacementAndDuplicateFlags(t *testing.T) {
	root := t.TempDir()
	rt := desktopRuntime{PID: 42, Exe: filepath.Join(root, "captured"), StateDir: filepath.Join(root, `state "quote" space`), BaseURL: "http://127.0.0.1:19091", Generation: "g", InstanceID: "d"}
	args := []string{rt.Exe, "--addr=127.0.0.1:19091", "--generation", "g", "--instance-id", "d", "--state-dir", rt.StateDir}
	if !backendIdentityMatchesArgs(rt, rt.Exe, args) {
		t.Fatal("valid argument-vector identity rejected")
	}
	if backendIdentityMatchesArgs(rt, rt.Exe, append(append([]string{}, args...), "--generation=other")) {
		t.Fatal("duplicate identity flag accepted")
	}
	other := append([]string{}, args...)
	other[3] = "other"
	if backendIdentityMatchesArgs(rt, rt.Exe, other) {
		t.Fatal("replacement generation accepted")
	}
	if backendIdentityMatchesArgs(rt, filepath.Join(root, "other"), args) {
		t.Fatal("different executable accepted")
	}
}
