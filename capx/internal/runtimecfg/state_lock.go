package runtimecfg

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type stateLockRecord struct {
	LockVersion int    `json:"lock_version,omitempty"`
	PID         int    `json:"pid"`
	Generation  string `json:"generation,omitempty"`
	Nonce       string `json:"nonce"`
	CreatedAt   string `json:"created_at"`
}

type stateLockHooks struct {
	beforeStaleRemove func()
}

var errStateLockClaimBusy = errors.New("state directory lock is already held")

func AcquireStateDirLock(stateDir, generation string) (func(), error) {
	return acquireStateDirLockWithHooks(stateDir, generation, stateLockHooks{})
}

func acquireStateDirLockWithHooks(stateDir, generation string, hooks stateLockHooks) (func(), error) {
	if strings.TrimSpace(stateDir) == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	releaseClaim, err := acquireStateLockClaim(filepath.Join(stateDir, ".capx-runtime.lock.claim"))
	if err != nil {
		if errors.Is(err, errStateLockClaimBusy) {
			return nil, errors.New("state directory is already owned by another Capx process")
		}
		return nil, fmt.Errorf("claim state directory: %w", err)
	}
	claimHeld := true
	releaseClaimOnError := func() {
		if claimHeld {
			releaseClaim()
			claimHeld = false
		}
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		releaseClaimOnError()
		return nil, err
	}
	record := stateLockRecord{
		LockVersion: 2, PID: os.Getpid(), Generation: generation,
		Nonce: hex.EncodeToString(nonceBytes), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(record)
	lockPath := filepath.Join(stateDir, ".capx-runtime.lock")

	for attempt := 0; attempt < 3; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, err := file.Write(data); err != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				releaseClaimOnError()
				return nil, err
			}
			if err := file.Sync(); err != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				releaseClaimOnError()
				return nil, err
			}
			if err := file.Close(); err != nil {
				_ = os.Remove(lockPath)
				releaseClaimOnError()
				return nil, err
			}
			var once sync.Once
			return func() {
				once.Do(func() {
					defer releaseClaimOnError()
					current, readErr := os.ReadFile(lockPath)
					if readErr != nil {
						return
					}
					var owner stateLockRecord
					if json.Unmarshal(current, &owner) == nil && owner.Nonce == record.Nonce {
						_ = os.Remove(lockPath)
					}
				})
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			releaseClaimOnError()
			return nil, err
		}
		current, readErr := os.ReadFile(lockPath)
		var owner stateLockRecord
		if readErr == nil && json.Unmarshal(current, &owner) == nil && owner.LockVersion < 2 && owner.PID > 0 && stateLockProcessAlive(owner.PID) {
			releaseClaimOnError()
			return nil, fmt.Errorf("already owned by live pid %d (generation %q)", owner.PID, owner.Generation)
		}
		if hooks.beforeStaleRemove != nil {
			hooks.beforeStaleRemove()
		}
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			releaseClaimOnError()
			return nil, fmt.Errorf("remove stale state lock: %w", err)
		}
	}
	releaseClaimOnError()
	return nil, errors.New("could not acquire state directory lock")
}
