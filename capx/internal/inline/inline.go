package inline

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/hquip/capx/internal/store"
)

// ErrNoBackend is returned when no raw-packet diversion backend is compiled in
// (default builds) or the backend driver is unavailable at runtime.
var ErrNoBackend = errors.New("inline: no raw-packet backend (build with -tags windivert on Windows or -tags nfqueue on Linux, and run as admin/root)")

// backend is a platform packet-diversion driver (WinDivert / NFQUEUE).
type backend interface {
	name() string
	available() bool
	run(ctx context.Context, filter string, eng *Engine, st *store.Store) error
	send(pkt []byte, outbound bool) error
	runRedirect(ctx context.Context, filter string, redir *Redirector, st *store.Store) error
}

// Manager owns the packet-rule engine and the active diversion backend.
type Manager struct {
	st  *store.Store
	eng *Engine
	be  backend

	mu         sync.Mutex
	running    bool
	filter     string
	cancel     context.CancelFunc
	redirector *Redirector
	redirPort  int
}

func New(st *store.Store) *Manager {
	return &Manager{st: st, eng: NewEngine(), be: newBackend()}
}

func (m *Manager) Engine() *Engine { return m.eng }

func (m *Manager) Backend() string { return m.be.name() }

func (m *Manager) Available() bool { return m.be.available() }

func (m *Manager) Status() (running bool, filter string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running, m.filter
}

func (m *Manager) RedirectStatus() (running bool, port, flows int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.redirector == nil {
		return false, m.redirPort, 0
	}
	return true, m.redirPort, m.redirector.Flows()
}

func (m *Manager) UDPOnlyRedirect() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.redirector != nil && m.redirector.udpOnly
}

func (m *Manager) Start(filter string) error {
	if !m.be.available() {
		return ErrNoBackend
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("inline already running")
	}
	if m.redirector != nil {
		m.mu.Unlock()
		return errors.New("transparent redirect is running; stop it before starting inline rewrite")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.running, m.filter, m.cancel = true, filter, cancel
	m.mu.Unlock()

	go func() {
		_ = m.be.run(ctx, filter, m.eng, m.st)
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.cancel == nil {
		return errors.New("inline not running")
	}
	m.cancel()
	m.cancel = nil
	m.running = false
	return nil
}

func (m *Manager) StartRedirect(listenPort, skipDstPort int, ports ...int) error {
	if !m.be.available() {
		return ErrNoBackend
	}
	if listenPort <= 0 || listenPort > 65535 {
		return errors.New("invalid transparent listen port")
	}
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	m.mu.Lock()
	if m.redirector != nil {
		m.mu.Unlock()
		return errors.New("transparent redirect already running")
	}
	if m.running {
		m.mu.Unlock()
		return errors.New("inline rewrite is running; stop it before starting transparent redirect")
	}
	var tcpParts, udpParts []string
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			tcpParts = append(tcpParts, "tcp.DstPort == "+strconv.Itoa(p))
			udpParts = append(udpParts, "udp.DstPort == "+strconv.Itoa(p))
		}
	}
	if len(tcpParts) == 0 {
		m.mu.Unlock()
		return errors.New("no valid redirect ports")
	}
	lp := strconv.Itoa(listenPort)
	filter := "(ip or ipv6) and ((" +
		"tcp and ((" + strings.Join(tcpParts, " or ") + ") or tcp.SrcPort == " + lp + ")" +
		") or (" +
		"udp and ((" + strings.Join(udpParts, " or ") + ") or udp.SrcPort == " + lp + ")" +
		"))"
	return m.launchRedirectLocked(listenPort, skipDstPort, filter, ports, false)
}

// StartUDPRedirect DNATs only UDP (HTTP/3/QUIC) onto listenPort so an
// explicit MITM proxy can intercept QUIC without stealing TCP 80/443.
func (m *Manager) StartUDPRedirect(listenPort, skipDstPort int, ports ...int) error {
	if !m.be.available() {
		return ErrNoBackend
	}
	if listenPort <= 0 || listenPort > 65535 {
		return errors.New("invalid transparent listen port")
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	m.mu.Lock()
	if m.redirector != nil {
		m.mu.Unlock()
		return errors.New("transparent redirect already running")
	}
	if m.running {
		m.mu.Unlock()
		return errors.New("inline rewrite is running; stop it before starting transparent redirect")
	}
	var udpParts []string
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			udpParts = append(udpParts, "udp.DstPort == "+strconv.Itoa(p))
		}
	}
	if len(udpParts) == 0 {
		m.mu.Unlock()
		return errors.New("no valid redirect ports")
	}
	lp := strconv.Itoa(listenPort)
	filter := "(ip or ipv6) and udp and ((" + strings.Join(udpParts, " or ") + ") or udp.SrcPort == " + lp + ")"
	return m.launchRedirectLocked(listenPort, skipDstPort, filter, ports, true)
}

// launchRedirectLocked assumes m.mu is held and unlocks it.
func (m *Manager) launchRedirectLocked(listenPort, skipDstPort int, filter string, ports []int, udpOnly bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	redir := NewRedirector(listenPort, skipDstPort, ports...)
	redir.udpOnly = udpOnly
	m.redirector, m.redirPort, m.cancel = redir, listenPort, cancel
	m.mu.Unlock()

	go func() {
		_ = m.be.runRedirect(ctx, filter, redir, m.st)
		m.mu.Lock()
		if m.redirector == redir {
			m.redirector = nil
			m.redirPort = 0
			m.cancel = nil
		}
		m.mu.Unlock()
	}()
	return nil
}

func (m *Manager) StopRedirect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.redirector == nil {
		return errors.New("transparent redirect not running")
	}
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.redirector.Close()
	m.redirector = nil
	m.redirPort = 0
	return nil
}

func (m *Manager) Send(hexPkt string, outbound bool) error {
	if !m.be.available() {
		return ErrNoBackend
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(hexPkt), " ", ""))
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("empty packet")
	}
	return m.be.send(raw, outbound)
}

func (m *Manager) LookupOrigDst(srcIP net.IP, srcPort int) (string, bool) {
	m.mu.Lock()
	r := m.redirector
	m.mu.Unlock()
	if r == nil {
		return "", false
	}
	return r.Lookup(srcIP, srcPort)
}
