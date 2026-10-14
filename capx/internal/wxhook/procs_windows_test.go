//go:build windows

package wxhook

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessRoleCacheTTLSetChangesAndCopies(t *testing.T) {
	var cache processRoleCache
	current := time.Unix(100, 0)
	now := func() time.Time { return current }
	calls := 0
	source := map[uint32]string{1: "network", 2: "renderer"}
	load := func() (map[uint32]string, error) { calls++; return source, nil }
	first := cache.get([]Process{{PID: 2}, {PID: 1}}, load, now)
	first[1] = "mutated"
	source[1] = "changed-after-load"
	current = current.Add(9 * time.Second)
	second := cache.get([]Process{{PID: 1}, {PID: 2}, {PID: 1}}, load, now)
	if calls != 1 || second[1] != "network" {
		t.Fatalf("cache copied/normalized PID set incorrectly: calls=%d roles=%v", calls, second)
	}
	current = current.Add(time.Second)
	cache.get([]Process{{PID: 1}, {PID: 2}}, load, now)
	if calls != 2 {
		t.Fatal("ten-second cache did not expire")
	}
	cache.get([]Process{{PID: 1}, {PID: 2}, {PID: 3}}, load, now)
	if calls != 3 {
		t.Fatal("new NetworkService PID did not invalidate cache immediately")
	}
	cache.get(nil, load, now)
	if calls != 3 {
		t.Fatal("empty PID set launched unnecessary PowerShell query")
	}
	cache.get([]Process{{PID: 1}, {PID: 2}, {PID: 3}}, load, now)
	if calls != 4 {
		t.Fatal("empty PID transition failed to invalidate previous cache")
	}
}

func TestProcessRoleCacheDoesNotCacheErrors(t *testing.T) {
	var cache processRoleCache
	calls := 0
	load := func() (map[uint32]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("fixture WMI error")
		}
		return map[uint32]string{7: "network"}, nil
	}
	if got := cache.get([]Process{{PID: 7}}, load, time.Now); got != nil {
		t.Fatalf("failed lookup returned roles: %v", got)
	}
	if got := cache.get([]Process{{PID: 7}}, load, time.Now); calls != 2 || got[7] != "network" {
		t.Fatal("failed discovery was cached")
	}
}

func TestProcessRoleCacheSharesConcurrentSamePIDSetQuery(t *testing.T) {
	var cache processRoleCache
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	load := func() (map[uint32]string, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return map[uint32]string{9: "network"}, nil
	}
	var ready, done sync.WaitGroup
	ready.Add(8)
	done.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			result := cache.get([]Process{{PID: 9}}, load, time.Now)
			if result[9] != "network" {
				t.Errorf("unexpected role: %v", result)
			}
			result[9] = "private copy"
		}()
	}
	ready.Wait()
	<-started
	close(release)
	done.Wait()
	if calls.Load() != 1 {
		t.Fatalf("launched %d equivalent discovery queries", calls.Load())
	}
	if got := cache.get([]Process{{PID: 9}}, load, time.Now); got[9] != "network" {
		t.Fatal("concurrent caller mutated cached roles")
	}
}

func TestProcessRoleCacheNewPIDSetDoesNotWaitForOrLoseToOldQuery(t *testing.T) {
	var cache processRoleCache
	started, release, oldDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(oldDone)
		cache.get([]Process{{PID: 1}}, func() (map[uint32]string, error) {
			close(started)
			<-release
			return map[uint32]string{1: "renderer"}, nil
		}, time.Now)
	}()
	<-started
	newCalls := 0
	newLoader := func() (map[uint32]string, error) {
		newCalls++
		return map[uint32]string{1: "renderer", 2: "network"}, nil
	}
	if got := cache.get([]Process{{PID: 1}, {PID: 2}}, newLoader, time.Now); got[2] != "network" {
		t.Fatal("new network PID was not discovered")
	}
	close(release)
	<-oldDone
	if got := cache.get([]Process{{PID: 2}, {PID: 1}}, newLoader, time.Now); got[2] != "network" || newCalls != 1 {
		t.Fatal("old in-flight result overwrote new PID-set cache")
	}
}
