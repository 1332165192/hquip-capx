package runtimecfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopStateDirectoryStableAndIsolated(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("CAPX_STATE_DIR", "")
	first := ResolveDesktopStateDir("auto")
	if first == "" || first != ResolveDesktopStateDir("") {
		t.Fatal("desktop default not stable")
	}
	if first == ResolveStateDir("auto", "127.0.0.1:19091") {
		t.Fatal("desktop reuses daemon default state")
	}
	if ResolveDesktopStateDir("none") != "" {
		t.Fatal("in-memory option lost")
	}
	custom := filepath.Join(t.TempDir(), "custom")
	t.Setenv("CAPX_STATE_DIR", custom)
	if ResolveDesktopStateDir("auto") != custom {
		t.Fatal("explicit environment state lost")
	}
}

func TestDesktopStateTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPX_TOKEN", "")
	EnsureInstanceTokenEnv(dir)
	first := os.Getenv("CAPX_TOKEN")
	if first == "" {
		t.Fatal("no token")
	}
	EnsureInstanceTokenEnv(dir)
	if os.Getenv("CAPX_TOKEN") != first || ReadInstanceToken(filepath.Join(dir, "token")) != first {
		t.Fatal("token changed on restart")
	}
}
