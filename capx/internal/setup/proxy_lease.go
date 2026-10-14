package setup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hquip/capx/internal/runtimecfg"
)

// The system proxy is user-wide, not state-dir-wide. One OS file lock protects
// its original snapshot and owner across all Capx instances in that user account.
type proxyLease struct {
	Version  int           `json:"version"`
	Owner    string        `json:"owner"`
	PID      int           `json:"pid"`
	Original proxySnapshot `json:"original"`
	Applied  proxySnapshot `json:"applied"`
}

type proxyLeaseController struct {
	path  string
	owner string
	pid   int
	read  func() (proxySnapshot, error)
	apply func(proxySnapshot) error
	alive func(int) bool
}

var processProxyOwner = newProxyOwner()

func newProxyOwner() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(b))
}

func backupPath() string { return filepath.Join(dataDir(), "sysproxy-backup.json") }
func proxyController() proxyLeaseController {
	return proxyLeaseController{backupPath(), processProxyOwner, os.Getpid(), readSystemProxy, applySystemProxy, runtimecfg.ProcessAlive}
}

func (c proxyLeaseController) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		release, err := runtimecfg.AcquireFileLock(c.path + ".lock")
		if err == nil {
			return release, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("lock system proxy: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (c proxyLeaseController) load() (*proxyLease, error) {
	b, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lease proxyLease
	if err := json.Unmarshal(b, &lease); err != nil {
		return nil, fmt.Errorf("read system proxy backup: %w", err)
	}
	if lease.Version != 1 {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(b, &fields)
		if lease.Version != 0 || fields["Enable"] == nil || fields["Server"] == nil {
			return nil, fmt.Errorf("unsupported or malformed system proxy backup at %s", c.path)
		}
		// Preserve pre-upgrade flat snapshots. Only explicitly enabling the exact
		// already-selected capture address may claim/migrate such a backup.
		if err := json.Unmarshal(b, &lease.Original); err != nil {
			return nil, err
		}
		lease.Version = 0
	}
	return &lease, nil
}

func (c proxyLeaseController) save(lease *proxyLease) error {
	if lease == nil {
		err := os.Remove(c.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var value any = lease
	if lease.Version == 0 {
		value = lease.Original
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), ".sysproxy-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), c.path)
}

func (c proxyLeaseController) enable(addr string) error {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid proxy address: %w", err)
	}
	release, err := c.lock()
	if err != nil {
		return err
	}
	defer release()
	old, err := c.load()
	if err != nil {
		return err
	}
	if old != nil && old.Owner != c.owner && c.alive(old.PID) {
		return fmt.Errorf("system proxy is owned by another Capx instance (pid %d)", old.PID)
	}
	current, err := c.read()
	if err != nil {
		return err
	}
	original := current
	if old != nil && old.Version == 0 {
		if current.Enable == 0 || current.Server != addr {
			return fmt.Errorf("legacy proxy backup at %s has no owner; select its existing capture address before claiming it", c.path)
		}
		original = old.Original
	}
	if old != nil && current == old.Applied {
		original = old.Original
	}
	applied := targetSystemProxy(current, addr)
	lease := &proxyLease{1, c.owner, c.pid, original, applied}
	if err := c.save(lease); err != nil {
		return err
	}
	if err := c.apply(applied); err != nil {
		if rollbackErr := c.apply(current); rollbackErr != nil {
			if partial, readErr := c.read(); readErr == nil {
				lease.Applied = partial
				_ = c.save(lease)
			}
			return fmt.Errorf("set system proxy: %v; restore failed: %w", err, rollbackErr)
		}
		if saveErr := c.save(old); saveErr != nil {
			return fmt.Errorf("set system proxy: %v; restore lease: %w", err, saveErr)
		}
		return err
	}
	return nil
}

func (c proxyLeaseController) restore(recoverStale bool) error {
	return c.restoreAddress(recoverStale, "")
}

func (c proxyLeaseController) restoreAddress(recoverStale bool, expectedAddr string) error {
	release, err := c.lock()
	if err != nil {
		return err
	}
	defer release()
	lease, err := c.load()
	if err != nil {
		return err
	}
	if lease == nil {
		return nil
	}
	if lease.Version == 0 {
		if !recoverStale {
			return nil
		}
		return fmt.Errorf("legacy proxy backup at %s has no verified owner; first enable the currently selected capture address to claim it", c.path)
	}
	if expectedAddr != "" && lease.Applied.Server != expectedAddr {
		return nil
	}
	if lease.Owner != c.owner && (!recoverStale || c.alive(lease.PID)) {
		return nil
	}
	current, err := c.read()
	if err != nil {
		return err
	}
	// A user or another program changed proxy settings after us. Do not undo it.
	if current != lease.Applied {
		return c.save(nil)
	}
	if err := c.apply(lease.Original); err != nil {
		return err
	}
	return c.save(nil)
}

func enableSystemProxy(addr string) error { return proxyController().enable(addr) }
func restoreSystemProxy() error           { return proxyController().restore(true) }

// ReleaseSystemProxy is the shutdown path: only this exact process generation
// may restore its lease. Explicit UI restore may additionally recover a crash.
func ReleaseSystemProxy() error { return proxyController().restore(false) }

// In-process embedded backends share the OS process, but not proxy listeners.
// Closing an unrelated Component must not release its sibling's active lease.
func scopedProxyController(scope any) proxyLeaseController {
	c := proxyController()
	c.owner = fmt.Sprintf("%s/%p", c.owner, scope)
	return c
}
func EnableSystemProxyOwned(scope any, addr string) error {
	return scopedProxyController(scope).enable(addr)
}
func DisableSystemProxyOwned(scope any) error { return scopedProxyController(scope).restore(true) }
func ReleaseSystemProxyOwned(scope any) error { return scopedProxyController(scope).restore(false) }

func readBackup() (proxySnapshot, bool) {
	lease, err := proxyController().load()
	if err != nil || lease == nil {
		return proxySnapshot{}, false
	}
	return lease.Original, true
}
func hasProxyBackup() bool { _, err := os.Stat(backupPath()); return err == nil }
