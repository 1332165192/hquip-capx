package proxy

import (
	"regexp"
	"strings"
	"time"
)

// WSMacroStep is one frame to inject as part of a WebSocket macro. Data may
// contain {{var}} placeholders resolved from the session store before sending;
// for binary frames Data must be base64. DelayMs pauses after the frame.
type WSMacroStep struct {
	Dir     string `json:"dir"`    // "send" (client->server, default) | "recv" (server->client)
	Opcode  string `json:"opcode"` // "text" (default) | "binary"
	Data    string `json:"data"`   // payload, supports {{var}}; base64 when opcode=="binary"
	DelayMs int64  `json:"delay_ms,omitempty"`
}

// WSMacro is a named, ordered sequence of frames injected onto a live
// WebSocket connection (e.g. an auth/subscribe handshake) on demand.
type WSMacro struct {
	Name  string        `json:"name"`
	Steps []WSMacroStep `json:"steps"`
}

// WSStepResult is the outcome of injecting one WS macro frame.
type WSStepResult struct {
	Dir    string `json:"dir"`
	Opcode string `json:"opcode"`
	Length int    `json:"length"`
	Error  string `json:"error,omitempty"`
}

// WSMacroRun is the transcript of a WS macro execution.
type WSMacroRun struct {
	Steps []WSStepResult    `json:"steps"`
	Vars  map[string]string `json:"vars"`
}

// WSRule auto-replays a frame onto a live WebSocket connection whenever an
// observed frame matches: e.g. answer a server heartbeat, or re-send an auth
// frame when the server asks for it. It is the WebSocket analogue of the
// HTTP SessionRule auto-relogin.
type WSRule struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	URL     string `json:"url"`      // substring match on the connection URL ("" = all)
	OnDir   string `json:"on_dir"`   // direction that triggers: "recv" (default) | "send" | "" = any
	When    string `json:"when"`     // regex on the observed frame text; "" = match any frame
	SendDir string `json:"send_dir"` // direction to inject the reply: "send" (default) | "recv"
	Opcode  string `json:"opcode"`   // reply opcode: "text" (default) | "binary"
	Data    string `json:"data"`     // reply payload, supports {{var}}; base64 when opcode=="binary"
	// Extract harvests values from the matched frame text into session vars
	// (regex; the first capture group, or whole match if none).
	Extract []Extractor `json:"extract,omitempty"`
	// MinIntervalMs throttles how often this rule may fire (per connection),
	// guarding against auto-reply loops. Default 500ms when 0.
	MinIntervalMs int64 `json:"min_interval_ms,omitempty"`
}

func (r WSRule) matchURL(url string) bool {
	if r.URL == "" {
		return true
	}
	return strings.Contains(strings.ToLower(url), strings.ToLower(r.URL))
}

func (r WSRule) matchDir(dir string) bool {
	want := strings.ToLower(strings.TrimSpace(r.OnDir))
	if want == "" {
		return true
	}
	return want == strings.ToLower(dir)
}

func (r WSRule) replyDir() string {
	if strings.EqualFold(strings.TrimSpace(r.SendDir), "recv") {
		return "recv"
	}
	return "send"
}

func (r WSRule) replyOpcode() string {
	if strings.EqualFold(strings.TrimSpace(r.Opcode), "binary") {
		return "binary"
	}
	return "text"
}

func (r WSRule) interval() time.Duration {
	if r.MinIntervalMs > 0 {
		return time.Duration(r.MinIntervalMs) * time.Millisecond
	}
	return 500 * time.Millisecond
}

// WSInject is a ready-to-send auto-reply produced by evalWSReply.
type WSInject struct {
	Name   string
	Dir    string // "send" | "recv"
	Opcode string // "text" | "binary"
	Data   string
}

// --- engine wiring (HTTP counterparts live in session.go) ---

func (e *sessionEngine) setWSMacros(ms []WSMacro) {
	e.mu.Lock()
	e.wsMacros = map[string]WSMacro{}
	for _, m := range ms {
		if m.Name != "" {
			e.wsMacros[m.Name] = m
		}
	}
	e.mu.Unlock()
	e.notify()
}

func (e *sessionEngine) listWSMacros() []WSMacro {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]WSMacro, 0, len(e.wsMacros))
	for _, m := range e.wsMacros {
		out = append(out, m)
	}
	return out
}

func (e *sessionEngine) setWSRules(rs []WSRule) {
	e.mu.Lock()
	e.wsRules = rs
	e.mu.Unlock()
	e.notify()
}

func (e *sessionEngine) snapshotWSRules() []WSRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]WSRule(nil), e.wsRules...)
}

func (e *sessionEngine) wsMacro(name string) (WSMacro, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.wsMacros[name]
	return m, ok
}

// WSMacros returns the configured WebSocket macros.
func (e *sessionEngine) WSMacros() []WSMacro { return e.listWSMacros() }

// WSRules returns the configured WebSocket auto-replay rules.
func (e *sessionEngine) WSRules() []WSRule { return e.snapshotWSRules() }

// SetWSMacros replaces the configured WebSocket macros.
func (e *sessionEngine) SetWSMacros(ms []WSMacro) { e.setWSMacros(ms) }

// SetWSRules replaces the configured WebSocket auto-replay rules.
func (e *sessionEngine) SetWSRules(rs []WSRule) { e.setWSRules(rs) }

// extractWSValues applies regex extractors to a frame's text, returning
// captured values. (Header/cookie sources do not apply to WS frames.)
func extractWSValues(frameText string, exs []Extractor) map[string]string {
	out := map[string]string{}
	for _, e := range exs {
		if e.Name == "" || e.Expr == "" {
			continue
		}
		re, err := regexp.Compile(e.Expr)
		if err != nil {
			continue
		}
		if g := re.FindStringSubmatch(frameText); g != nil {
			if len(g) > 1 {
				out[e.Name] = g[1]
			} else {
				out[e.Name] = g[0]
			}
		}
	}
	return out
}

// evalWSReply matches the observed frame (url + direction + text) against the
// configured WS rules, harvests any extractor values into the session store,
// and returns the frames to inject as auto-replies. A per-rule throttle guards
// against reply loops. dir is the direction of the observed frame.
func (e *sessionEngine) evalWSReply(url, dir, frameText string) []WSInject {
	rules := e.snapshotWSRules()
	if len(rules) == 0 {
		return nil
	}
	var out []WSInject
	now := time.Now()
	for _, r := range rules {
		if !r.Enabled || !r.matchURL(url) || !r.matchDir(dir) {
			continue
		}
		if r.When != "" {
			re, err := regexp.Compile(r.When)
			if err != nil || !re.MatchString(frameText) {
				continue
			}
		}
		if !e.throttleWS(r, url, now) {
			continue // fired too recently; skip to avoid a loop
		}
		if got := extractWSValues(frameText, r.Extract); len(got) > 0 {
			for k, v := range got {
				e.vars.Set(k, v)
			}
		}
		data := applyVars(r.Data, e.vars.Snapshot())
		out = append(out, WSInject{Name: r.Name, Dir: r.replyDir(), Opcode: r.replyOpcode(), Data: data})
	}
	return out
}

// throttleWS reports whether rule r may fire now for url, recording the time
// when it may. It returns false (and does not update) when the rule fired
// within its MinInterval.
func (e *sessionEngine) throttleWS(r WSRule, url string, now time.Time) bool {
	key := r.Name + "\x00" + r.When + "\x00" + url
	e.wsThrottleMu.Lock()
	defer e.wsThrottleMu.Unlock()
	if last, ok := e.wsThrottle[key]; ok && now.Sub(last) < r.interval() {
		return false
	}
	e.wsThrottle[key] = now
	return true
}
