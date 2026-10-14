// Package spoof implements LAN MITM positioning via ARP cache poisoning — the
// piece that lets capx intercept devices that don't honour a proxy: once a
// target's ARP cache points the gateway at us (and the gateway points the
// target at us), their traffic flows through this host, where the transparent
// interceptor / inline engine can act on it.
//
// This is an inherently active, disruptive, privileged operation (raw frame
// injection, needs Npcap/libpcap + admin/root) so it is gated behind the
// security policy and only built with the "pcap" tag; the default build ships a
// stub that reports it unavailable.
package spoof

import "sync"

// Manager owns the active ARP-poisoning session (at most one at a time).
type Manager struct {
	mu  sync.Mutex
	imp spoofer
}

// spoofer is the platform/back-end implementation (pcap or stub).
type spoofer interface {
	start(iface, targetIP, gatewayIP string) error
	stop() error
	status() (running bool, iface, target, gateway string)
	available() bool
}

// New returns a spoof manager using the compiled-in backend.
func New() *Manager { return &Manager{imp: newSpoofer()} }

// Available reports whether raw frame injection is built in.
func (m *Manager) Available() bool { return m.imp.available() }

// Start begins poisoning targetIP <-> gatewayIP on iface.
func (m *Manager) Start(iface, targetIP, gatewayIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imp.start(iface, targetIP, gatewayIP)
}

// Stop ends poisoning and (best-effort) restores the victims' ARP caches.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imp.stop()
}

// Status reports the current poisoning session.
func (m *Manager) Status() (running bool, iface, target, gateway string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imp.status()
}
