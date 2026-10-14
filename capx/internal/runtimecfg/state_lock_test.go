package runtimecfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stateLockResult struct {
	release func()
	err     error
}

func TestStateDirLockRejectsLiveOwnerAndReleases(t *testing.T) {
	dir := t.TempDir()
	release, err := AcquireStateDirLock(dir, "generation-a")
	if err != nil {
		t.Fatal(err)
	}
	if second, secondErr := AcquireStateDirLock(dir, "generation-b"); secondErr == nil {
		second()
		t.Fatal("second process acquired a live state directory")
	}
	release()
	third, err := AcquireStateDirLock(dir, "generation-c")
	if err != nil {
		t.Fatalf("released state directory stayed locked: %v", err)
	}
	third()
}

func TestStateDirLockReleasePreservesReplacement(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".capx-runtime.lock")
	release, err := AcquireStateDirLock(dir, "generation-a")
	if err != nil {
		t.Fatal(err)
	}

	replacement := stateLockRecord{
		PID: os.Getpid(), Generation: "generation-b", Nonce: "replacement",
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	release()
	current, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("replacement lock was removed: %v", err)
	}
	var owner stateLockRecord
	if err := json.Unmarshal(current, &owner); err != nil {
		t.Fatal(err)
	}
	if owner.Nonce != replacement.Nonce {
		t.Fatalf("replacement lock changed: got nonce %q, want %q", owner.Nonce, replacement.Nonce)
	}
}

func TestStateDirLockRecoversStaleOwner(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".capx-runtime.lock")
	stale := stateLockRecord{
		PID: 1 << 30, Generation: "stale", Nonce: "stale",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(stale)
	if err := os.WriteFile(lockPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := AcquireStateDirLock(dir, "replacement")
	if err != nil {
		t.Fatalf("stale lock was not recovered: %v", err)
	}
	release()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file remained after release: %v", err)
	}
}

func TestStateDirLockRejectsConcurrentStaleRecovery(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".capx-runtime.lock")
	stale := stateLockRecord{
		PID: 1 << 30, Generation: "stale", Nonce: "stale",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	firstAtStale := make(chan struct{})
	allowFirst := make(chan struct{})
	firstResult := make(chan stateLockResult, 1)
	go func() {
		release, err := acquireStateDirLockWithHooks(dir, "generation-a", stateLockHooks{
			beforeStaleRemove: func() {
				close(firstAtStale)
				<-allowFirst
			},
		})
		firstResult <- stateLockResult{release: release, err: err}
	}()

	select {
	case <-firstAtStale:
	case result := <-firstResult:
		if result.release != nil {
			result.release()
		}
		t.Fatalf("first contender returned before stale recovery hook: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("first contender did not reach stale recovery hook")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan stateLockResult, 1)
	go func() {
		close(secondStarted)
		release, err := AcquireStateDirLock(dir, "generation-b")
		secondResult <- stateLockResult{release: release, err: err}
	}()
	<-secondStarted

	var second stateLockResult
	select {
	case second = <-secondResult:
	case <-time.After(5 * time.Second):
		close(allowFirst)
		t.Fatal("second contender did not fail the held OS claim")
	}
	close(allowFirst)

	first := <-firstResult
	if first.release != nil {
		defer first.release()
	}
	if second.release != nil {
		defer second.release()
	}
	if first.err != nil {
		t.Fatalf("first contender did not acquire recovered lock: %v", first.err)
	}
	if second.err == nil {
		t.Fatal("second contender acquired the same state directory")
	}
}

func TestStateDirLockRecoversVersionTwoRecordAfterOSClaimRelease(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".capx-runtime.lock")
	stale := stateLockRecord{
		LockVersion: 2,
		PID:         os.Getpid(),
		Generation:  "crashed-generation",
		Nonce:       "crashed-owner",
		CreatedAt:   time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := AcquireStateDirLock(dir, "replacement")
	if err != nil {
		t.Fatalf("released OS claim was mistaken for a live reused PID: %v", err)
	}
	release()
}

func TestEmptyStateDirNeedsNoLock(t *testing.T) {
	release, err := AcquireStateDirLock("", "")
	if err != nil {
		t.Fatal(err)
	}
	release()
}
