// Package wxhook manages independent capture sessions and an external CDP adapter.
package wxhook

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/hquip/capx/internal/hook"
	"github.com/hquip/capx/internal/wxcdp"
	"strconv"
	"sync"
	"time"
)

type hookEngine interface {
	Available() bool
	Backend() string
	Attach(uint32, string) (*hook.Session, error)
	Detach(string) error
	Sessions() []*hook.Session
}
type Process struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Version   int    `json:"version"`   // detected WMPF version (0 if unknown)
	Main      bool   `json:"main"`      // the main WMPF host (injection target)
	Supported bool   `json:"supported"` // offset table has this version
	Role      string `json:"role,omitempty"`
}

type Manager struct {
	hooks hookEngine
	cdp   *wxcdp.Bridge

	mu       sync.Mutex
	sessions map[uint32]string // pid -> DevTools hook session id

	captureAttachMu    sync.Mutex
	captureSessions    map[uint32]string // pid -> redirect hook session id
	captureRetry       map[uint32]time.Time
	captureFailures    map[uint32]int
	capturePort        int
	captureOptions     CaptureOptions
	captureErrors      map[uint32]string
	captureDiagnostics map[uint32]string
	captureCounts      map[string]uint64
	captureRetiring    map[string]uint32
	captureAgent       string
	captureWatch       bool
	captureCancel      context.CancelFunc
	closed             bool

	listProcesses func() ([]Process, error)
}

func New(h *hook.Manager) *Manager {
	return &Manager{
		hooks:           h,
		cdp:             wxcdp.New(nil),
		sessions:        map[uint32]string{},
		captureSessions: map[uint32]string{},
		captureRetry:    map[uint32]time.Time{},
		captureFailures: map[uint32]int{},
		listProcesses:   listWeChatAppEx,
	}
}

// CDPStart connects to the configured external CDP endpoint.
func (m *Manager) CDPStart() (map[string]any, error) { return m.cdp.Start() }

// CDPStop stops the DevTools CDP bridge.
func (m *Manager) CDPStop() error { return m.cdp.Stop() }

// CDPStatus reports the CDP bridge state including the DevTools URL.
func (m *Manager) CDPStatus() map[string]any { return m.cdp.Status() }

// CDPEval runs a JS expression in the connected mini-program (Runtime.evaluate)
// and returns the raw CDP response JSON. Powers cloud-function calls, route
// inspection, and mini-program jumps.
func (m *Manager) CDPEval(expr string) (string, error) { return m.cdp.Eval(expr, 0) }

// CDPCall forwards a generic Chrome DevTools Protocol command to the connected
// mini-program runtime.
func (m *Manager) CDPCall(method string, params any, timeout time.Duration) (json.RawMessage, error) {
	return m.cdp.Call(method, params, timeout)
}

// Available reports whether the underlying Frida hook engine is usable.
func (m *Manager) Available() bool {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	return !closed && m.hooks != nil && m.hooks.Available()
}

// Backend returns the underlying hook backend ("frida"/"stub"/"disabled").
func (m *Manager) Backend() string {
	if m.hooks == nil {
		return "disabled"
	}
	return m.hooks.Backend()
}

// Public builds ship no version-specific F12 hook or offset table.
func SupportedVersions() []int  { return []int{} }
func versionSupported(int) bool { return false }
func (m *Manager) Status() map[string]any {
	return map[string]any{"backend": "external-cdp", "available": false, "capture_available": m.Available(), "capture_backend": m.Backend(), "injected_pids": []uint32{}, "versions": SupportedVersions(), "capture": m.CaptureStatus(), "devtools_provider": "external-cdp", "bundled_f12": false}
}
func (m *Manager) Procs() ([]Process, error) {
	if m.listProcesses != nil {
		return m.listProcesses()
	}
	return listWeChatAppEx()
}
func (m *Manager) Enable(uint32) (map[string]any, error) {
	return nil, errors.New("public builds require an external debug provider: configure CAPX_CDP_WS and start the CDP connection; no F12 hook is bundled")
}
func (m *Manager) Disable() error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for _, id := range m.sessions {
		ids = append(ids, id)
	}
	m.sessions = map[uint32]string{}
	m.mu.Unlock()
	var firstErr error
	for _, id := range ids {
		if err := m.hooks.Detach(id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close only detaches this wx manager's sessions and stops its own watcher/CDP.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	err := m.CaptureStop()
	if e := m.Disable(); err == nil {
		err = e
	}
	if m.cdp != nil {
		if e := m.CDPStop(); err == nil {
			err = e
		}
	}
	return err
}

func lastNumber(s string) int {
	best := -1
	i := 0
	for i < len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if n, err := strconv.Atoi(s[i:j]); err == nil {
				best = n
			}
			i = j
		} else {
			i++
		}
	}
	if best < 0 {
		return 0
	}
	return best
}
