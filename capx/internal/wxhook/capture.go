package wxhook

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hquip/capx/internal/hook"
)

//go:embed redirect.js
var redirectAgentJS string

const (
	captureRetryBase      = 5 * time.Second
	captureRetryMax       = 5 * time.Minute
	captureStableSession  = 30 * time.Second
	capturePendingTimeout = 12 * time.Second
)

// CaptureOptions keeps direct TCP and explicit HTTP proxy transports separate.
// The caller verifies UpstreamProxy; this package also enforces a literal
// IPv4 loopback endpoint. Existing sockets and protocol bytes are untouched.
type CaptureOptions struct {
	Port          int    `json:"port"`
	ExplicitPort  int    `json:"explicit_port,omitempty"`
	UpstreamProxy string `json:"upstream_proxy,omitempty"`
}

type CaptureResult struct {
	Running       bool              `json:"running"`
	Enabled       bool              `json:"enabled"`
	Port          int               `json:"port"`
	ExplicitPort  int               `json:"explicit_port,omitempty"`
	UpstreamProxy string            `json:"upstream_proxy,omitempty"`
	Transport     string            `json:"transport"`
	Watch         bool              `json:"watch"`
	PIDs          []uint32          `json:"pids"`
	Attached      []uint32          `json:"attached,omitempty"`
	ReadyPIDs     []uint32          `json:"ready_pids"`
	PendingPIDs   []uint32          `json:"pending_pids"`
	Redirected    uint64            `json:"redirected"`
	Errors        map[uint32]string `json:"errors,omitempty"`
	Diagnostics   map[uint32]string `json:"diagnostics,omitempty"`
}

func normalizeCaptureOptions(opts CaptureOptions) (CaptureOptions, string, int, error) {
	if opts.Port < 1 || opts.Port > 65535 {
		return opts, "", 0, fmt.Errorf("invalid transparent proxy port %d", opts.Port)
	}
	opts.UpstreamProxy = strings.TrimSpace(opts.UpstreamProxy)
	if opts.UpstreamProxy == "" {
		if opts.ExplicitPort != 0 {
			return opts, "", 0, errors.New("explicit proxy port requires a verified upstream HTTP proxy")
		}
		return opts, "", 0, nil
	}
	if opts.ExplicitPort < 1 || opts.ExplicitPort > 65535 || opts.ExplicitPort == opts.Port {
		return opts, "", 0, errors.New("explicit and transparent proxy ports must be valid and distinct")
	}
	u, err := url.Parse(opts.UpstreamProxy)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return opts, "", 0, errors.New("upstream proxy must be an HTTP loopback endpoint without credentials, path, query or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || ip.To4() == nil || err != nil || port < 1 || port > 65535 {
		return opts, "", 0, errors.New("upstream proxy must use a literal IPv4 loopback address and explicit port (IPv6 sockets are left unchanged)")
	}
	if port == opts.ExplicitPort || port == opts.Port {
		return opts, "", 0, errors.New("upstream proxy must not be one of the Capx capture listeners")
	}
	host := ip.To4().String()
	opts.UpstreamProxy = "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	return opts, host, port, nil
}

func renderRedirectAgent(port int) ([]byte, error) {
	return renderRedirectAgentWithOptions(CaptureOptions{Port: port})
}
func renderRedirectAgentWithOptions(opts CaptureOptions) ([]byte, error) {
	opts, host, proxyPort, err := normalizeCaptureOptions(opts)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(redirectAgentJS, "@@PORT@@") || !strings.Contains(redirectAgentJS, "@@CONFIG@@") {
		return nil, errors.New("embedded redirect agent is missing configuration placeholders")
	}
	config, _ := json.Marshal(map[string]any{"explicit_port": opts.ExplicitPort, "upstream_host": host, "upstream_port": proxyPort})
	return []byte(strings.NewReplacer("@@PORT@@", strconv.Itoa(opts.Port), "@@CONFIG@@", string(config)).Replace(redirectAgentJS)), nil
}

func (m *Manager) CaptureStart(port int, pids []uint32, watch bool) (*CaptureResult, error) {
	return m.CaptureStartWithOptions(CaptureOptions{Port: port}, pids, watch)
}

func (m *Manager) CaptureStartWithOptions(opts CaptureOptions, pids []uint32, watch bool) (*CaptureResult, error) {
	if !m.Available() {
		return nil, hook.ErrNoFrida
	}
	opts, _, _, err := normalizeCaptureOptions(opts)
	if err != nil {
		return nil, err
	}
	script, err := renderRedirectAgentWithOptions(opts)
	if err != nil {
		return nil, err
	}
	m.captureAttachMu.Lock()
	defer m.captureAttachMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("wxhook manager is closed")
	}
	if m.capturePort != 0 && m.captureOptions != opts {
		m.mu.Unlock()
		return nil, errors.New("mini-program capture already uses another transport configuration; stop it before changing listeners")
	}
	if m.capturePort == 0 {
		m.capturePort = opts.Port
		m.captureOptions = opts
		m.captureAgent = fmt.Sprintf("wxredirect-%d-%p", opts.Port, m)
		m.captureSessions = map[uint32]string{}
		m.captureRetry = map[uint32]time.Time{}
		m.captureFailures = map[uint32]int{}
		m.captureErrors = map[uint32]string{}
		m.captureDiagnostics = map[uint32]string{}
		m.captureCounts = map[string]uint64{}
		m.captureRetiring = map[string]uint32{}
	}
	m.captureWatch = watch
	agentName := m.captureAgent
	var cancel context.CancelFunc
	if !watch {
		cancel = m.captureCancel
		m.captureCancel = nil
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	hook.RegisterAgent(agentName, script)
	result, attachErr := m.captureAttachLocked(append([]uint32(nil), pids...))
	if watch {
		m.mu.Lock()
		if m.captureCancel == nil {
			var ctx context.Context
			ctx, m.captureCancel = context.WithCancel(context.Background())
			go m.captureWatchLoop(ctx)
		}
		m.mu.Unlock()
	}
	// Never wait serially per PID: launched drivers remain explicitly pending.
	return result, attachErr
}

func (m *Manager) captureWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !m.Available() {
				return
			}
			m.captureAttachMu.Lock()
			select {
			case <-ctx.Done():
				m.captureAttachMu.Unlock()
				return
			default:
			}
			_, _ = m.captureAttachLocked(nil)
			m.captureAttachMu.Unlock()
		}
	}
}

func captureDefaultTargets(procs []Process) ([]uint32, string) {
	var network, main, all []uint32
	for _, p := range procs {
		all = append(all, p.PID)
		if p.Role == "network" {
			network = append(network, p.PID)
		}
		if p.Main {
			main = append(main, p.PID)
		}
	}
	if len(network) > 0 {
		return network, ""
	}
	if len(main) > 0 {
		return main, "NetworkService role was not identified; only the legacy main process is selected. Specify the verified network PID if required."
	}
	return all, "NetworkService/main role unavailable in this process list; using the legacy selection fallback."
}

func (m *Manager) captureAttachLocked(requested []uint32) (*CaptureResult, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return m.CaptureStatus(), errors.New("wxhook manager is closed")
	}
	status := m.CaptureStatus()
	if !status.Enabled {
		return status, nil
	}
	procs, err := m.Procs()
	if err != nil {
		m.mu.Lock()
		m.captureErrors[0] = err.Error()
		m.mu.Unlock()
		return m.CaptureStatus(), err
	}
	byPID := map[uint32]Process{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	var diagnostic string
	if len(requested) == 0 {
		requested, diagnostic = captureDefaultTargets(procs)
	}
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })
	m.mu.Lock()
	agentName := m.captureAgent
	delete(m.captureErrors, 0)
	if diagnostic != "" {
		m.captureDiagnostics[0] = diagnostic
	} else {
		delete(m.captureDiagnostics, 0)
	}
	for pid := range m.captureRetry {
		if _, ok := byPID[pid]; !ok {
			delete(m.captureRetry, pid)
			delete(m.captureFailures, pid)
		}
	}
	m.mu.Unlock()
	newIDs := map[uint32]bool{}
	seen := map[uint32]bool{}
	for _, pid := range requested {
		m.mu.Lock()
		closed = m.closed
		m.mu.Unlock()
		if closed {
			break
		}
		if seen[pid] {
			continue
		}
		seen[pid] = true
		if _, ok := byPID[pid]; !ok {
			m.mu.Lock()
			m.captureErrors[pid] = "pid is not a WeChatAppEx process"
			m.mu.Unlock()
			continue
		}
		m.mu.Lock()
		_, attached := m.captureSessions[pid]
		retryAt := m.captureRetry[pid]
		m.mu.Unlock()
		if attached || time.Now().Before(retryAt) {
			continue
		}
		session, attachErr := m.hooks.Attach(pid, agentName)
		m.mu.Lock()
		if attachErr != nil {
			m.captureFailures[pid]++
			m.captureErrors[pid] = attachErr.Error()
			m.captureRetry[pid] = time.Now().Add(captureRetryDelay(m.captureFailures[pid]))
		} else if session == nil || session.ID == "" {
			m.captureFailures[pid]++
			m.captureErrors[pid] = "hook engine returned no session"
			m.captureRetry[pid] = time.Now().Add(captureRetryDelay(m.captureFailures[pid]))
		} else {
			m.captureSessions[pid] = session.ID
			newIDs[pid] = true
		}
		m.mu.Unlock()
	}
	result := m.CaptureStatus()
	for _, pid := range result.ReadyPIDs {
		if newIDs[pid] {
			result.Attached = append(result.Attached, pid)
		}
	}
	if len(result.ReadyPIDs) == 0 && len(result.PendingPIDs) == 0 {
		if len(result.Errors) > 0 {
			return result, errors.New("all mini-program hook attachments failed; inspect capture.errors")
		}
		if len(procs) == 0 && !result.Watch {
			m.mu.Lock()
			m.captureErrors[0] = "WeChatAppEx.exe not found (open a mini-program first)"
			m.mu.Unlock()
			return m.CaptureStatus(), errors.New("WeChatAppEx.exe not found (open a mini-program first)")
		}
	}
	return result, nil
}

func (m *Manager) captureSession(id string, active map[string]*hook.Session) (*hook.Session, bool) {
	if reader, ok := m.hooks.(interface {
		Session(string) (*hook.Session, bool)
	}); ok {
		return reader.Session(id)
	}
	s, ok := active[id]
	return s, ok
}

// Async errors are reconciled on status polls even when watch is disabled.
func (m *Manager) pruneCaptureSessionsLocked() {
	if m.hooks == nil {
		return
	}
	active := map[string]*hook.Session{}
	for _, s := range m.hooks.Sessions() {
		active[s.ID] = s
	}
	m.mu.Lock()
	for id := range m.captureRetiring {
		if _, ok := active[id]; !ok {
			delete(m.captureRetiring, id)
		}
	}
	ids := map[uint32]string{}
	for pid, id := range m.captureSessions {
		ids[pid] = id
	}
	m.mu.Unlock()
	for pid, id := range ids {
		s, ok := m.captureSession(id, active)
		reason := ""
		timeout := false
		if !ok {
			reason = "hook driver ended before a ready session was observed"
		} else if s.Error != "" {
			reason = s.Error
		} else if !s.Ended.IsZero() || s.State == "stopped" || s.State == "stopping" {
			reason = "hook session ended"
		} else if !s.Ready && time.Since(s.Started) > capturePendingTimeout {
			reason = "timed out waiting for driver loaded / redirect agent ready"
			timeout = true
		}
		m.mu.Lock()
		if m.captureSessions[pid] != id {
			m.mu.Unlock()
			continue
		}
		if m.captureErrors == nil {
			m.captureErrors = map[uint32]string{}
		}
		if m.captureDiagnostics == nil {
			m.captureDiagnostics = map[uint32]string{}
		}
		if m.captureCounts == nil {
			m.captureCounts = map[string]uint64{}
		}
		if m.captureRetiring == nil {
			m.captureRetiring = map[string]uint32{}
		}
		if m.captureFailures == nil {
			m.captureFailures = map[uint32]int{}
		}
		if m.captureRetry == nil {
			m.captureRetry = map[uint32]time.Time{}
		}
		if ok {
			if s.Redirected > m.captureCounts[id] {
				m.captureCounts[id] = s.Redirected
			}
			if s.Diagnostic != "" {
				m.captureDiagnostics[pid] = s.Diagnostic
			}
		}
		if reason != "" {
			delete(m.captureSessions, pid)
			m.captureErrors[pid] = reason
			m.captureFailures[pid]++
			m.captureRetry[pid] = time.Now().Add(captureRetryDelay(m.captureFailures[pid]))
			if ok && s.Ended.IsZero() {
				m.captureRetiring[id] = pid
			}
		} else if s.Ready {
			delete(m.captureErrors, pid)
			if time.Since(s.Started) >= captureStableSession {
				m.captureFailures[pid] = 0
			}
		}
		m.mu.Unlock()
		if timeout || reason != "" && ok && s.Ended.IsZero() {
			if requester, ok := m.hooks.(interface{ RequestDetach(string) error }); ok {
				_ = requester.RequestDetach(id)
			} else {
				go func(id string) { _ = m.hooks.Detach(id) }(id)
			}
		}
	}
}

func (m *Manager) CaptureStatus() *CaptureResult {
	m.pruneCaptureSessionsLocked()
	active := map[string]*hook.Session{}
	if m.hooks != nil {
		for _, s := range m.hooks.Sessions() {
			active[s.ID] = s
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := &CaptureResult{Enabled: m.capturePort > 0, Port: m.capturePort, ExplicitPort: m.captureOptions.ExplicitPort, UpstreamProxy: m.captureOptions.UpstreamProxy, Watch: m.captureWatch, PIDs: []uint32{}, ReadyPIDs: []uint32{}, PendingPIDs: []uint32{}, Transport: "ipv4-direct-tcp", Errors: map[uint32]string{}, Diagnostics: map[uint32]string{}}
	if result.ExplicitPort > 0 {
		result.Transport = "ipv4-direct-tcp+explicit-http-proxy"
	}
	for pid, id := range m.captureSessions {
		result.PIDs = append(result.PIDs, pid)
		if s := active[id]; s != nil && s.Ready && s.Error == "" {
			result.ReadyPIDs = append(result.ReadyPIDs, pid)
		} else {
			result.PendingPIDs = append(result.PendingPIDs, pid)
		}
	}
	for _, pids := range [][]uint32{result.PIDs, result.ReadyPIDs, result.PendingPIDs} {
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	}
	for pid, err := range m.captureErrors {
		result.Errors[pid] = err
	}
	for pid, diag := range m.captureDiagnostics {
		result.Diagnostics[pid] = diag
	}
	for _, n := range m.captureCounts {
		result.Redirected += n
	}
	result.Running = len(result.ReadyPIDs) > 0
	return result
}

func (m *Manager) CaptureStop() error {
	m.captureAttachMu.Lock()
	defer m.captureAttachMu.Unlock()
	return m.resetCaptureLocked()
}
func (m *Manager) resetCaptureLocked() error {
	m.mu.Lock()
	ids := []string{}
	for _, id := range m.captureSessions {
		ids = append(ids, id)
	}
	for id := range m.captureRetiring {
		ids = append(ids, id)
	}
	cancel := m.captureCancel
	agentName := m.captureAgent
	m.captureSessions = map[uint32]string{}
	m.captureRetry = map[uint32]time.Time{}
	m.captureFailures = map[uint32]int{}
	m.captureRetiring = map[string]uint32{}
	m.capturePort = 0
	m.captureOptions = CaptureOptions{}
	m.captureAgent = ""
	m.captureWatch = false
	m.captureCancel = nil
	// Preserve last errors/counters through rollback; the next start clears them.
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if agentName != "" {
		hook.UnregisterAgent(agentName)
	}
	active := map[string]bool{}
	if m.hooks != nil {
		for _, s := range m.hooks.Sessions() {
			active[s.ID] = true
		}
	}
	var first error
	for _, id := range ids {
		if active[id] {
			if err := m.hooks.Detach(id); err != nil && !strings.Contains(err.Error(), "not found") && first == nil {
				first = err
			}
		}
	}
	return first
}
