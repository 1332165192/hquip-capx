// Security guard for the capx local API. The daemon exposes high-impact
// primitives (process injection, memory writes, raw-packet injection, Lua code
// loading), so the HTTP surface is hardened against the two realistic local
// threats:
//
//   - CSRF / DNS-rebinding from a malicious web page. The desktop console runs
//     in a browser, so a foreign site could try to drive 127.0.0.1. We reject
//     any request whose Host header is a DNS name (rebinding always needs one)
//     and any browser request whose Origin is not our own loopback origin.
//   - Unauthenticated local processes. Every /api/* call must present a bearer
//     token (Authorization: Bearer / X-Capx-Token / capx_token cookie). The
//     console gets the token via a Strict same-site cookie set when its page
//     loads; programmatic clients read it from CAPX_TOKEN or ~/.capx/token.
//
// On top of authn, mutating "active" primitives (inject / modify / attach /
// memory write / load code) are gated behind an explicit policy switch
// (default off, matching the documented "passive by default" model), every
// such attempt is audited, and all writes are rate-limited.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEntry is one recorded security-relevant decision.
type AuditEntry struct {
	TS      time.Time `json:"ts"`
	Remote  string    `json:"remote"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Action  string    `json:"action"` // "active" | "policy" | "denied"
	Allowed bool      `json:"allowed"`
	Reason  string    `json:"reason,omitempty"`
}

// guard holds the API's authn/authz state: the bearer token, the active-mode
// switch, a write rate limiter, and a ring buffer of audit entries.
type guard struct {
	token  string
	authOn bool
	active atomic.Bool

	mu       sync.Mutex
	audit    []AuditEntry
	auditCap int

	rlMu     sync.Mutex
	rlTokens float64
	rlLast   time.Time
	rlRate   float64 // tokens per second
	rlBurst  float64
}

// newGuard builds the guard, resolving the token (env CAPX_TOKEN, else
// ~/.capx/token, else freshly generated and persisted 0600) and the initial
// active-mode / auth settings from the environment.
func newGuard() *guard {
	g := &guard{
		authOn:   !envFalsey(os.Getenv("CAPX_AUTH")),
		auditCap: 500,
		rlRate:   20,
		rlBurst:  40,
	}
	g.rlTokens = g.rlBurst
	g.rlLast = time.Now()
	g.active.Store(envTruthy(os.Getenv("CAPX_ALLOW_ACTIVE")))
	g.token = resolveToken()
	return g
}

// resolveToken returns CAPX_TOKEN if set, else the token stored in
// ~/.capx/token, else a new random token that it persists there (best-effort).
func resolveToken() string {
	if t := strings.TrimSpace(os.Getenv("CAPX_TOKEN")); t != "" {
		return t
	}
	path := tokenPath()
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t
			}
		}
	}
	t := randomToken()
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = os.WriteFile(path, []byte(t), 0o600)
	}
	return t
}

func tokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".capx", "token")
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// rand.Read essentially never fails; fall back to a time seed.
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b)
}

func envTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envFalsey(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// Token returns the active bearer token (used by LogStartup to print it).
func (g *guard) Token() string { return g.token }

// AuthEnabled reports whether token auth is enforced.
func (g *guard) AuthEnabled() bool { return g.authOn }

// ActiveAllowed reports whether mutating "active" primitives are permitted.
func (g *guard) ActiveAllowed() bool { return g.active.Load() }

// SetActive toggles the active-mode switch and audits the change.
func (g *guard) SetActive(on bool, remote string) {
	g.active.Store(on)
	g.record(AuditEntry{TS: time.Now().UTC(), Remote: remote, Action: "policy",
		Allowed: true, Reason: activeReason(on)})
}

func activeReason(on bool) string {
	if on {
		return "active mode enabled"
	}
	return "active mode disabled"
}

// recentAudit returns a copy of the audit ring (oldest first).
func (g *guard) recentAudit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}

func (g *guard) record(e AuditEntry) {
	g.mu.Lock()
	g.audit = append(g.audit, e)
	if len(g.audit) > g.auditCap {
		g.audit = g.audit[len(g.audit)-g.auditCap:]
	}
	g.mu.Unlock()
}

// wrap returns middleware enforcing host/origin/token checks, active-mode
// gating, and write rate limiting on /api/* (and the SSE stream). Non-API
// paths (the console + assets) are passed straight through so the UI can load
// and set its auth cookie; /health is allowed unauthenticated for liveness.
func (g *guard) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		guarded := strings.HasPrefix(path, "/api/")
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}

		// Anti-DNS-rebinding: a rebinding attack must use a DNS name in Host;
		// reject anything that is not a loopback/IP literal host.
		if !hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "host not allowed (anti DNS-rebinding): use 127.0.0.1/localhost")
			return
		}
		// Anti-CSRF: a browser cross-site request carries a foreign Origin.
		if origin := r.Header.Get("Origin"); origin != "" && !originAllowed(origin, r.Host) {
			writeErr(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}

		if g.authOn && !g.tokenOK(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			if wantsFileDownload(r) {
				http.Error(w, "missing or invalid capx API token", http.StatusUnauthorized)
				return
			}
			writeErr(w, http.StatusUnauthorized, "missing or invalid capx API token")
			return
		}

		// Rate-limit all mutating verbs.
		if isWrite(r.Method) && !g.allowRate() {
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}

		// Gate mutating "active" primitives behind the policy switch.
		if isActiveOp(r.Method, path) {
			if !g.active.Load() {
				g.record(AuditEntry{TS: time.Now().UTC(), Remote: clientIP(r), Method: r.Method,
					Path: path, Action: "active", Allowed: false, Reason: "active mode disabled"})
				writeErr(w, http.StatusForbidden,
					"active mode disabled: enable via POST /api/policy {\"allow_active\":true} or start with -allow-active")
				return
			}
			g.record(AuditEntry{TS: time.Now().UTC(), Remote: clientIP(r), Method: r.Method,
				Path: path, Action: "active", Allowed: true})
		}

		next.ServeHTTP(w, r)
	})
}

// tokenOK reports whether the request carries the valid bearer token via the
// Authorization header, the X-Capx-Token header, or the capx_token cookie.
func (g *guard) tokenOK(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tokenEqual(strings.TrimPrefix(h, "Bearer "), g.token) {
			return true
		}
	}
	if h := r.Header.Get("X-Capx-Token"); h != "" && tokenEqual(h, g.token) {
		return true
	}
	if name := tokenCookieName(r.Host); name != "capx_token" {
		if c, err := r.Cookie(name); err == nil && tokenEqual(c.Value, g.token) {
			return true
		}
	}
	if c, err := r.Cookie("capx_token"); err == nil && tokenEqual(c.Value, g.token) {
		return true
	}
	if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" && tokenEqual(q, g.token) {
		return true
	}
	return false
}

func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(a)), []byte(b)) == 1
}

// allowRate implements a simple token-bucket limiter for write requests.
func (g *guard) allowRate() bool {
	g.rlMu.Lock()
	defer g.rlMu.Unlock()
	now := time.Now()
	g.rlTokens += now.Sub(g.rlLast).Seconds() * g.rlRate
	if g.rlTokens > g.rlBurst {
		g.rlTokens = g.rlBurst
	}
	g.rlLast = now
	if g.rlTokens < 1 {
		return false
	}
	g.rlTokens--
	return true
}

// setAuthCookie wraps an http.Handler (the console) to drop a same-site
// auth cookie so the in-browser UI authenticates to /api/* without any JS
// changes. SameSite=Lax covers top-level downloads from the console
// (CA / PCAP); Origin checks still block cross-site POSTs.
func (g *guard) setAuthCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.authOn {
			http.SetCookie(w, &http.Cookie{
				Name:     tokenCookieName(r.Host),
				Value:    g.token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

func tokenCookieName(host string) string {
	_, port, err := net.SplitHostPort(host)
	if err != nil || strings.TrimSpace(port) == "" {
		return "capx_token"
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return "capx_token"
		}
	}
	return "capx_token_" + port
}

// hostAllowed reports whether the Host header is a loopback/IP literal (i.e.
// not a DNS name). Rejecting DNS-name Hosts defeats DNS-rebinding regardless of
// the bind address.
func hostAllowed(host string) bool {
	if host == "" {
		return false
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	return net.ParseIP(h) != nil
}

// originAllowed reports whether a browser Origin matches our own loopback
// origin (same host family + same port as the request's Host).
func originAllowed(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if !hostAllowed(u.Host) {
		return false
	}
	_, oport, _ := net.SplitHostPort(u.Host)
	_, hport, _ := net.SplitHostPort(host)
	if hport == "" {
		// Host had no explicit port; accept any loopback origin port.
		return true
	}
	return oport == hport
}

func clientIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// wantsFileDownload is true for console "Save as" navigations (CA / PCAP /
// HAR). Those must not be answered with a JSON 401, or the browser shows
// "需要授权" instead of prompting for a file.
func wantsFileDownload(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/api/proxy/ca", "/api/export/pcap", "/api/http/export", "/api/keylog/export", "/api/project/export":
		return true
	}
	if strings.HasSuffix(r.URL.Path, "/curl") {
		return true
	}
	return false
}

func isWrite(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// isActiveOp classifies a request as a mutating "active" primitive that must be
// gated behind the policy switch: process injection, memory writes, raw-packet
// injection/rewrite, traffic match&replace, WebSocket frame injection, and Lua
// code loading. Read-only and plain "send" (repeater/intruder) verbs are not
// gated (they are rate-limited instead).
func isActiveOp(method, path string) bool {
	if method == http.MethodPost && strings.HasPrefix(path, "/api/wxdesk/") {
		return true
	}
	switch path {
	case "/api/mobile/capture/start", "/api/mobile/ca", "/api/mobile/tap", "/api/mobile/input", "/api/mobile/swipe", "/api/mobile/key", "/api/mobile/back", "/api/mobile/home", "/api/mobile/launch", "/api/mobile/ios/connect":
		return method == http.MethodPost
	case "/api/wxapkg/unpack", "/api/proxy/lan/start":
		return method == http.MethodPost
	case "/api/hook/attach", "/api/hook/agents", "/api/scripts", "/api/proxy/ws/replay", "/api/wxhook/enable", "/api/wxhook/cdp/start", "/api/wxhook/cdp/eval", "/api/wxhook/cdp/call":
		return method == http.MethodPost
	case "/api/wxhook/auto/click", "/api/wxhook/auto/input", "/api/wxhook/auto/scroll", "/api/wxhook/auto/back", "/api/wxhook/auto/start":
		return method == http.MethodPost
	case "/api/inline/start", "/api/inline/stop", "/api/inline/send":
		return method == http.MethodPost
	case "/api/spoof/arp/start", "/api/spoof/arp/stop":
		return method == http.MethodPost
	}
	// Proxy match&replace rules (mutate live traffic).
	if strings.HasPrefix(path, "/api/rules") && (method == http.MethodPost || method == http.MethodDelete) {
		return true
	}
	if strings.HasPrefix(path, "/api/wsrules") && (method == http.MethodPost || method == http.MethodDelete) {
		return true
	}
	// Raw-packet inline rules.
	if strings.HasPrefix(path, "/api/inline/rules") && (method == http.MethodPost || method == http.MethodDelete) {
		return true
	}
	// Memory mutation / code injection: /api/mem/{sid}/{write|patch|alloc|
	// freeze|unfreeze} and address-list freeze/unfreeze.
	if method == http.MethodPost && strings.HasPrefix(path, "/api/mem/") {
		switch {
		case strings.HasSuffix(path, "/write"),
			strings.HasSuffix(path, "/patch"),
			strings.HasSuffix(path, "/alloc"),
			strings.HasSuffix(path, "/assemble"),
			strings.HasSuffix(path, "/freeze"),
			strings.HasSuffix(path, "/unfreeze"):
			return true
		}
	}
	return false
}
