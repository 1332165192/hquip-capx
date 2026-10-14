package main

import (
	"fmt"
	"net"
	"sync"
)

const (
	portAllocationHost = "127.0.0.1"
	minimumTCPPort     = 1
	maximumTCPPort     = 65535
)

// portRequest uses zero to request an operating-system-assigned loopback port.
// Explicit ports are never remapped.
type portRequest struct {
	API   int
	Proxy int
	CDP   int
}

type portSet struct {
	API   int
	Proxy int
	CDP   int
}

type portRole struct {
	name      string
	requested int
	set       func(int)
}

type portAllocator struct {
	allocationMu sync.Mutex
	handoffMu    sync.Mutex
	listen       func(int) (net.Listener, error)
}

var managerPortAllocator = newPortAllocator()

func newPortAllocator() *portAllocator {
	return &portAllocator{listen: listenLoopbackPort}
}

func listenLoopbackPort(port int) (net.Listener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{
		IP:   net.ParseIP(portAllocationHost),
		Port: port,
	})
}

// allocatePortSet reserves independent API, proxy, and CDP listeners. The
// returned release function is idempotent and must be called on every path.
//
// For a child-process handoff, acquire lockPortHandoff, call release
// immediately before cmd.Start, and keep the handoff lock until Start returns.
// The listeners cannot be inherited by the current child protocol, so a small
// cross-process bind window remains after release.
func allocatePortSet(request portRequest) (portSet, func(), error) {
	return managerPortAllocator.allocate(request)
}

// lockPortHandoff serializes the listener-release/process-start window. The
// returned unlock function is idempotent.
func lockPortHandoff() func() {
	managerPortAllocator.handoffMu.Lock()
	var once sync.Once
	return func() {
		once.Do(managerPortAllocator.handoffMu.Unlock)
	}
}

func (a *portAllocator) allocate(request portRequest) (portSet, func(), error) {
	a.allocationMu.Lock()
	defer a.allocationMu.Unlock()

	var selected portSet
	roles := []portRole{
		{name: "API", requested: request.API, set: func(port int) { selected.API = port }},
		{name: "proxy", requested: request.Proxy, set: func(port int) { selected.Proxy = port }},
		{name: "CDP", requested: request.CDP, set: func(port int) { selected.CDP = port }},
	}

	seenExplicit := make(map[int]string, len(roles))
	for _, role := range roles {
		if role.requested == 0 {
			continue
		}
		if role.requested < minimumTCPPort || role.requested > maximumTCPPort {
			return portSet{}, nil, fmt.Errorf("%s port %d is outside %d-%d", role.name, role.requested, minimumTCPPort, maximumTCPPort)
		}
		if previous, exists := seenExplicit[role.requested]; exists {
			return portSet{}, nil, fmt.Errorf("%s port %d duplicates %s port", role.name, role.requested, previous)
		}
		seenExplicit[role.requested] = role.name
	}

	listeners := make([]net.Listener, 0, len(roles))
	closeListeners := func() {
		for i := len(listeners) - 1; i >= 0; i-- {
			_ = listeners[i].Close()
		}
	}

	reserve := func(role portRole) error {
		listener, err := a.listen(role.requested)
		if err != nil {
			if role.requested != 0 {
				return fmt.Errorf("%s port %d is unavailable on %s: %w", role.name, role.requested, portAllocationHost, err)
			}
			return fmt.Errorf("allocate automatic %s port on %s: %w", role.name, portAllocationHost, err)
		}
		address, ok := listener.Addr().(*net.TCPAddr)
		if !ok || address.Port < minimumTCPPort || address.Port > maximumTCPPort {
			_ = listener.Close()
			return fmt.Errorf("allocator returned an invalid %s address: %s", role.name, listener.Addr())
		}
		listeners = append(listeners, listener)
		role.set(address.Port)
		return nil
	}

	// Bind explicit ports first so automatic allocation cannot consume a port
	// that the caller explicitly assigned to another role.
	for _, role := range roles {
		if role.requested != 0 {
			if err := reserve(role); err != nil {
				closeListeners()
				return portSet{}, nil, err
			}
		}
	}
	for _, role := range roles {
		if role.requested == 0 {
			if err := reserve(role); err != nil {
				closeListeners()
				return portSet{}, nil, err
			}
		}
	}

	if selected.API == selected.Proxy || selected.API == selected.CDP || selected.Proxy == selected.CDP {
		closeListeners()
		return portSet{}, nil, fmt.Errorf("allocator selected duplicate ports: API=%d proxy=%d CDP=%d", selected.API, selected.Proxy, selected.CDP)
	}

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(closeListeners)
	}
	return selected, release, nil
}
