package api

import (
	"context"
	"fmt"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type deferredInterfaceFixture struct {
	calls   atomic.Int32
	release chan struct{}
	empty   bool
	err     error
}

func (fake *deferredInterfaceFixture) Run(context.Context, string, sniffer.Config, *store.Store) error {
	return nil
}
func (fake *deferredInterfaceFixture) Backend() string { return "fixture" }
func (fake *deferredInterfaceFixture) Interfaces() ([]sniffer.Device, error) {
	fake.calls.Add(1)
	if fake.err != nil {
		return nil, fake.err
	}
	<-fake.release
	if fake.empty {
		return nil, nil
	}
	return []sniffer.Device{{Name: "fixture-adapter"}}, nil
}

func TestRestrictedInterfaceInventoryReportsPermissionWithoutTimeout(t *testing.T) {
	fake := &deferredInterfaceFixture{err: fmt.Errorf("Npcap administrator-only fixture: %w", os.ErrPermission)}
	server := &Server{snif: fake}
	response := httptest.NewRecorder()
	started := time.Now()
	server.listIfaces(response, httptest.NewRequest(http.MethodGet, "/api/ifaces", nil))
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "Npcap") {
		t.Fatalf("permission response: %d / %s", response.Code, response.Body)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("permission rejection waited for the interface scan timeout")
	}
}

func TestInterfaceScanSurvivesCallerTimeoutAndCachesLateResults(t *testing.T) {
	fake := &deferredInterfaceFixture{release: make(chan struct{})}
	server := &Server{snif: fake}
	first := httptest.NewRecorder()
	server.listIfaces(first, httptest.NewRequest(http.MethodGet, "/api/ifaces", nil))
	if first.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected bounded initial wait: %d", first.Code)
	}
	close(fake.release)
	second := httptest.NewRecorder()
	server.listIfaces(second, httptest.NewRequest(http.MethodGet, "/api/ifaces", nil))
	if second.Code != http.StatusOK || fake.calls.Load() != 1 {
		t.Fatalf("late result lost or extra scan: %d / %d", second.Code, fake.calls.Load())
	}
}

func TestConcurrentInterfaceReadsShareOneScanAndCacheEmptyResults(t *testing.T) {
	fake := &deferredInterfaceFixture{release: make(chan struct{}), empty: true}
	server := &Server{snif: fake}
	var wait sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := httptest.NewRecorder()
			server.listIfaces(response, httptest.NewRequest(http.MethodGet, "/api/ifaces", nil))
			if response.Code != http.StatusOK {
				t.Errorf("status: %d", response.Code)
			}
		}()
	}
	close(start)
	deadline := time.Now().Add(time.Second)
	for fake.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(fake.release)
	wait.Wait()
	server.listIfaces(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/ifaces", nil))
	if fake.calls.Load() != 1 {
		t.Fatalf("duplicated scans: %d", fake.calls.Load())
	}
}
