package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureInstanceTokenEnvReusesStateDirToken(t *testing.T) {
	stateDir := t.TempDir()
	want := "111122223333444455556666777788889999aaaabbbbcccc"
	if err := os.WriteFile(filepath.Join(stateDir, "token"), []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CAPX_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ensureInstanceTokenEnv(stateDir)

	if got := os.Getenv("CAPX_TOKEN"); got != want {
		t.Fatalf("CAPX_TOKEN = %q, want state-dir token %q", got, want)
	}
}

func TestEnsureInstanceTokenEnvPersistsGeneratedToken(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("CAPX_TOKEN", "")

	ensureInstanceTokenEnv(stateDir)
	first := os.Getenv("CAPX_TOKEN")
	if first == "" {
		t.Fatal("CAPX_TOKEN was not generated")
	}

	t.Setenv("CAPX_TOKEN", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	ensureInstanceTokenEnv(stateDir)
	if got := os.Getenv("CAPX_TOKEN"); got != first {
		t.Fatalf("CAPX_TOKEN after restart = %q, want persisted token %q", got, first)
	}
}

func TestShouldFallbackAddr(t *testing.T) {
	if !shouldFallbackAddr("127.0.0.1:19091", false) {
		t.Fatal("default address should fall back when strict mode is disabled")
	}
	if shouldFallbackAddr("127.0.0.1:19091", true) {
		t.Fatal("strict mode must not fall back")
	}
	if shouldFallbackAddr("127.0.0.1:19123", false) {
		t.Fatal("a non-default address must not silently fall back")
	}
}
