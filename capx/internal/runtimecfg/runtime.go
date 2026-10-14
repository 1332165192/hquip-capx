// Package runtimecfg shares desktop/daemon state isolation and credentials.
package runtimecfg

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func ResolveStateDir(raw, listenAddr string) string {
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(raw) {
	case "none", "off", "memory", "mem", "in-memory":
		return ""
	}
	if raw != "" && !strings.EqualFold(raw, "auto") && raw != "自动" {
		return raw
	}
	if v := strings.TrimSpace(os.Getenv("CAPX_STATE_DIR")); v != "" {
		return v
	}
	name := "state"
	if _, port, err := net.SplitHostPort(listenAddr); err == nil && port != "" && port != "19091" {
		name = "state-" + port
	}
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return filepath.Join(v, "capx", name)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".capx", name)
	}
	return ""
}

func EnsureInstanceTokenEnv(stateDir string) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return
	}
	path := filepath.Join(stateDir, "token")
	if t := ReadInstanceToken(path); t != "" {
		_ = os.Setenv("CAPX_TOKEN", t)
		return
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return
	}
	t := hex.EncodeToString(b)

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Printf("capx: could not persist instance API token at %s: %v", path, err)
		_ = os.Setenv("CAPX_TOKEN", t)
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		if old := ReadInstanceToken(path); old != "" {
			_ = os.Setenv("CAPX_TOKEN", old)
			return
		}
		if err := os.WriteFile(path, []byte(t), 0o600); err != nil {
			log.Printf("capx: could not persist instance API token at %s: %v", path, err)
		}
		_ = os.Setenv("CAPX_TOKEN", t)
		return
	}
	if err != nil {
		log.Printf("capx: could not persist instance API token at %s: %v", path, err)
		_ = os.Setenv("CAPX_TOKEN", t)
		return
	}
	if _, err := f.WriteString(t); err != nil {
		log.Printf("capx: could not write instance API token at %s: %v", path, err)
		_ = f.Close()
		_ = os.Setenv("CAPX_TOKEN", t)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("capx: could not close instance API token at %s: %v", path, err)
	}
	_ = os.Setenv("CAPX_TOKEN", t)
}

func ReadInstanceToken(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ResolveDesktopStateDir uses a stable directory rather than the ephemeral UI
// port, so closing and reopening a desktop preserves its capture history.
func ResolveDesktopStateDir(raw string) string {
	if strings.TrimSpace(raw) != "" && !strings.EqualFold(raw, "auto") && raw != "自动" {
		return ResolveStateDir(raw, "")
	}
	if v := strings.TrimSpace(os.Getenv("CAPX_STATE_DIR")); v != "" {
		return v
	}
	base := ResolveStateDir("auto", "")
	if base == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(base), "state-desktop")
}

// AcquireFileLock is a non-blocking, process-wide OS-backed lock. The file is
// deliberately retained; removing a lock file could create a second inode.
func AcquireFileLock(path string) (func(), error) { return acquireStateLockClaim(path) }

func ProcessAlive(pid int) bool { return stateLockProcessAlive(pid) }

func NewGeneration() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
