package main

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAllocatePortSetAutoIsLoopbackHeldAndDistinct(t *testing.T) {
	ports, release, err := allocatePortSet(portRequest{})
	if err != nil {
		t.Fatalf("allocatePortSet: %v", err)
	}
	defer release()

	assertValidDistinctPortSet(t, ports)
	for _, port := range portSetValues(ports) {
		assertPortUnavailable(t, port)
	}

	release()
	for _, port := range portSetValues(ports) {
		listener, err := listenLoopbackPort(port)
		if err != nil {
			t.Fatalf("port %d was not released: %v", port, err)
		}
		_ = listener.Close()
	}
}

func TestAllocatePortSetHonorsIndependentExplicitPorts(t *testing.T) {
	explicit := threeFreePorts(t)
	request := portRequest{API: explicit[0], Proxy: explicit[1], CDP: explicit[2]}
	ports, release, err := allocatePortSet(request)
	if err != nil {
		t.Fatalf("allocatePortSet: %v", err)
	}
	defer release()

	if ports.API != request.API || ports.Proxy != request.Proxy || ports.CDP != request.CDP {
		t.Fatalf("explicit ports were remapped: request=%+v selected=%+v", request, ports)
	}
	assertValidDistinctPortSet(t, ports)
}

func TestAllocatePortSetRejectsOccupiedExplicitPortAndCleansUp(t *testing.T) {
	occupied, err := listenLoopbackPort(0)
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port
	apiPort := freePort(t)

	_, release, err := allocatePortSet(portRequest{API: apiPort, Proxy: occupiedPort})
	if err == nil {
		if release != nil {
			release()
		}
		t.Fatal("expected occupied explicit proxy port to fail")
	}
	if !strings.Contains(err.Error(), "proxy port") || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
	if release != nil {
		t.Fatal("failed allocation returned a release function")
	}

	listener, err := listenLoopbackPort(apiPort)
	if err != nil {
		t.Fatalf("API listener leaked after proxy collision: %v", err)
	}
	_ = listener.Close()
}

func TestAllocatePortSetRejectsDuplicateAndOutOfRangePorts(t *testing.T) {
	tests := []struct {
		name    string
		request portRequest
	}{
		{name: "duplicate API proxy", request: portRequest{API: 21001, Proxy: 21001}},
		{name: "negative API", request: portRequest{API: -1}},
		{name: "proxy above range", request: portRequest{Proxy: maximumTCPPort + 1}},
		{name: "CDP above range", request: portRequest{CDP: maximumTCPPort + 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, release, err := allocatePortSet(tt.request)
			if err == nil {
				if release != nil {
					release()
				}
				t.Fatal("expected validation error")
			}
			if release != nil {
				t.Fatal("failed allocation returned a release function")
			}
		})
	}
}

func TestAllocatePortSetConcurrentLeasesAreGloballyUnique(t *testing.T) {
	const workers = 12
	type result struct {
		ports   portSet
		release func()
		err     error
	}

	start := make(chan struct{})
	releaseAll := make(chan struct{})
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ports, release, err := allocatePortSet(portRequest{})
			results <- result{ports: ports, release: release, err: err}
			if err == nil {
				<-releaseAll
				release()
			}
		}()
	}
	close(start)

	seen := make(map[int]struct{}, workers*3)
	for i := 0; i < workers; i++ {
		result := <-results
		if result.err != nil {
			close(releaseAll)
			wg.Wait()
			t.Fatalf("concurrent allocation: %v", result.err)
		}
		assertValidDistinctPortSet(t, result.ports)
		for _, port := range portSetValues(result.ports) {
			if _, exists := seen[port]; exists {
				close(releaseAll)
				wg.Wait()
				t.Fatalf("port %d was assigned to more than one live lease", port)
			}
			seen[port] = struct{}{}
		}
	}
	close(releaseAll)
	wg.Wait()

	if len(seen) != workers*3 {
		t.Fatalf("got %d unique ports, want %d", len(seen), workers*3)
	}
}

func TestLockPortHandoffSerializesCallers(t *testing.T) {
	unlockFirst := lockPortHandoff()
	defer unlockFirst()

	acquired := make(chan func(), 1)
	go func() {
		acquired <- lockPortHandoff()
	}()

	select {
	case unlock := <-acquired:
		unlock()
		t.Fatal("second caller acquired handoff lock before the first released it")
	case <-time.After(50 * time.Millisecond):
	}

	unlockFirst()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("second caller did not acquire handoff lock after release")
	}
}

func assertValidDistinctPortSet(t *testing.T, ports portSet) {
	t.Helper()
	seen := make(map[int]struct{}, 3)
	for _, port := range portSetValues(ports) {
		if port < minimumTCPPort || port > maximumTCPPort {
			t.Fatalf("port %d is outside %d-%d", port, minimumTCPPort, maximumTCPPort)
		}
		if _, exists := seen[port]; exists {
			t.Fatalf("duplicate port in %+v", ports)
		}
		seen[port] = struct{}{}
	}
}

func assertPortUnavailable(t *testing.T, port int) {
	t.Helper()
	listener, err := listenLoopbackPort(port)
	if err == nil {
		_ = listener.Close()
		t.Fatalf("port %d was not held by the allocation lease", port)
	}
}

func portSetValues(ports portSet) []int {
	return []int{ports.API, ports.Proxy, ports.CDP}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := listenLoopbackPort(0)
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func threeFreePorts(t *testing.T) [3]int {
	t.Helper()
	listeners := make([]net.Listener, 0, 3)
	var ports [3]int
	for i := range ports {
		listener, err := listenLoopbackPort(0)
		if err != nil {
			for _, held := range listeners {
				_ = held.Close()
			}
			t.Fatalf("find explicit port %d: %v", i, err)
		}
		listeners = append(listeners, listener)
		ports[i] = listener.Addr().(*net.TCPAddr).Port
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	return ports
}
