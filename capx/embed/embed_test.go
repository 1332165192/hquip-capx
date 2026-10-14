package embed

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStartSurfacesPersistenceFailureAndReleasesListener(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "LOCALAPPDATA"} {
		t.Setenv(key, root)
	}
	t.Setenv("CAPX_DATA_DIR", filepath.Join(root, "ca"))
	t.Setenv("CAPX_TOKEN", "fixture-token")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "http_history.sqlite"), 0700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	instance, err := Start(Options{APIAddr: addr, ProxyAddr: "127.0.0.1:0", StateDir: state})
	if err == nil || instance != nil {
		if instance != nil {
			instance.Stop()
		}
		t.Fatal("persistence failure was swallowed")
	}
	probe, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("failed startup leaked API listener", err)
	}
	probe.Close()
}
