package proxy

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SessionVars is a thread-safe store of named values extracted from macro
// responses (e.g. CSRF tokens, session ids) and re-injected into live requests.
type SessionVars struct {
	mu sync.RWMutex
	m  map[string]string
}

func newSessionVars() *SessionVars { return &SessionVars{m: map[string]string{}} }

func (s *SessionVars) Get(k string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *SessionVars) Set(k, v string) {
	s.mu.Lock()
	s.m[k] = v
	s.mu.Unlock()
}

// Snapshot returns a copy of all variables.
func (s *SessionVars) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// Extractor pulls a named value out of a response.
type Extractor struct {
	Name   string `json:"name"`
	Source string `json:"source"` // "body" (regex) | "header" | "setcookie"
	Expr   string `json:"expr"`   // regex (body) or header/cookie name
}

// MacroStep is one request in a macro. Raw may contain {{var}} placeholders
// resolved from the session store before sending; Extract harvests values from
// the response into the store.
type MacroStep struct {
	Scheme  string      `json:"scheme"`
	Host    string      `json:"host"`
	Raw     string      `json:"raw"`
	Follow  bool        `json:"follow"`
	Extract []Extractor `json:"extract"`
}

// Macro is a named, ordered sequence of requests used to (re-)establish a
// session and capture dynamic values.
type Macro struct {
	Name  string      `json:"name"`
	Steps []MacroStep `json:"steps"`
}

// StepResult is the outcome of running one macro step.
type StepResult struct {
	Status    int               `json:"status"`
	Length    int               `json:"length"`
	Millis    int64             `json:"millis"`
	Extracted map[string]string `json:"extracted,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// MacroRun is the full transcript of a macro execution.
type MacroRun struct {
	Steps []StepResult      `json:"steps"`
	Vars  map[string]string `json:"vars"`
}

var varRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_]+)\s*\}\}`)

// applyVars replaces {{name}} placeholders in s with values from vars (unknown
// names are left untouched).
func applyVars(s string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		name := varRe.FindStringSubmatch(m)[1]
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

// extractValues applies extractors to a raw response, returning captured values.
func extractValues(respRaw string, exs []Extractor) map[string]string {
	out := map[string]string{}
	header, body := splitHeadBody(respRaw)
	for _, e := range exs {
		if e.Name == "" {
			continue
		}
		switch strings.ToLower(e.Source) {
		case "header":
			if v := headerValue(header, e.Expr); v != "" {
				out[e.Name] = v
			}
		case "setcookie":
			if v := cookieValue(header, e.Expr); v != "" {
				out[e.Name] = v
			}
		default: // body regex
			if re, err := regexp.Compile(e.Expr); err == nil {
				if g := re.FindStringSubmatch(body); g != nil {
					if len(g) > 1 {
						out[e.Name] = g[1]
					} else {
						out[e.Name] = g[0]
					}
				}
			}
		}
	}
	return out
}

func splitHeadBody(raw string) (head, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	return raw, ""
}

// headerValue parses the raw header block and returns the first value for name.
func headerValue(head, name string) string {
	r := bufio.NewReader(strings.NewReader(head + "\r\n\r\n"))
	// Skip the status line.
	if _, err := r.ReadString('\n'); err != nil {
		return ""
	}
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			if strings.EqualFold(k, name) {
				return v
			}
		}
		if err != nil {
			break
		}
	}
	return ""
}

// cookieValue returns the value of cookie named want from Set-Cookie headers.
func cookieValue(head, want string) string {
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, ":")
		if idx < 0 || !strings.EqualFold(strings.TrimSpace(line[:idx]), "Set-Cookie") {
			continue
		}
		cookie := strings.TrimSpace(line[idx+1:])
		// first "k=v" pair
		if sc := strings.SplitN(cookie, ";", 2)[0]; sc != "" {
			kv := strings.SplitN(sc, "=", 2)
			if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), want) {
				return strings.TrimSpace(kv[1])
			}
		}
	}
	return ""
}

// RunMacro executes a macro against the live network, threading the session
// store through each step (placeholder substitution in, extraction out).
func RunMacro(m Macro, store *SessionVars) MacroRun {
	return runMacroWithSender(m, store, SendRawOpts)
}

func runMacroWithSender(m Macro, store *SessionVars, sender func(string, string, string, bool) RepeaterResult) MacroRun {
	run := MacroRun{}
	for _, step := range m.Steps {
		vars := store.Snapshot()
		raw := applyVars(step.Raw, vars)
		scheme := step.Scheme
		if scheme == "" {
			scheme = "https"
		}
		res := sender(scheme, step.Host, raw, step.Follow)
		sr := StepResult{Status: res.Status, Length: res.RespLen, Millis: res.Millis}
		if res.Error != "" {
			sr.Error = res.Error
			run.Steps = append(run.Steps, sr)
			break // abort the chain on a transport error
		}
		got := extractValues(res.RespRaw, step.Extract)
		for k, v := range got {
			store.Set(k, v)
		}
		sr.Extracted = got
		run.Steps = append(run.Steps, sr)
	}
	run.Vars = store.Snapshot()
	return run
}

// HeaderInject sets a request header from a session variable.
type HeaderInject struct {
	Name string `json:"name"`
	Var  string `json:"var"`
}

// SessionRule binds a macro and live-request rewriting to matching hosts.
type SessionRule struct {
	Enabled     bool           `json:"enabled"`
	Host        string         `json:"host"`         // substring, case-insensitive ("" = all)
	Macro       string         `json:"macro"`        // macro to run on relogin
	ReloginWhen string         `json:"relogin_when"` // regex on response; "" disables auto-relogin
	SetHeaders  []HeaderInject `json:"set_headers"`  // header <- session var
	SubstBody   bool           `json:"subst_body"`   // replace {{var}} in request body
}

func (r SessionRule) matchHost(host string) bool {
	if r.Host == "" {
		return true
	}
	return strings.Contains(strings.ToLower(host), strings.ToLower(r.Host))
}

// sessionEngine owns the macros, session rules and live variable store. It
// covers both HTTP (macros / SessionRule) and WebSocket (wsMacros / WSRule).
type sessionEngine struct {
	mu       sync.RWMutex
	macros   map[string]Macro
	rules    []SessionRule
	wsMacros map[string]WSMacro
	wsRules  []WSRule
	vars     *SessionVars

	wsThrottleMu sync.Mutex
	wsThrottle   map[string]time.Time // per-rule last-fired, guards auto-reply loops

	onChange func()       // invoked (unlocked) after any config mutates
	runGuard func() error // instance routing restrictions, not persisted
	sender   func(string, string, string, bool) RepeaterResult
}

func newSessionEngine() *sessionEngine {
	return &sessionEngine{
		macros:     map[string]Macro{},
		wsMacros:   map[string]WSMacro{},
		wsThrottle: map[string]time.Time{},
		vars:       newSessionVars(),
	}
}

func (e *sessionEngine) notify() {
	if e.onChange != nil {
		e.onChange()
	}
}

func (e *sessionEngine) setMacros(ms []Macro) {
	e.mu.Lock()
	e.macros = map[string]Macro{}
	for _, m := range ms {
		if m.Name != "" {
			e.macros[m.Name] = m
		}
	}
	e.mu.Unlock()
	e.notify()
}

func (e *sessionEngine) listMacros() []Macro {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Macro, 0, len(e.macros))
	for _, m := range e.macros {
		out = append(out, m)
	}
	return out
}

func (e *sessionEngine) setRules(rs []SessionRule) {
	e.mu.Lock()
	e.rules = rs
	e.mu.Unlock()
	e.notify()
}

func (e *sessionEngine) snapshotRules() []SessionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]SessionRule(nil), e.rules...)
}

func (e *sessionEngine) macro(name string) (Macro, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.macros[name]
	return m, ok
}

// Macros returns the configured macros.
func (e *sessionEngine) Macros() []Macro { return e.listMacros() }

// Rules returns the configured session rules.
func (e *sessionEngine) Rules() []SessionRule { return e.snapshotRules() }

// Vars returns a snapshot of the live session variables.
func (e *sessionEngine) Vars() map[string]string { return e.vars.Snapshot() }

// SetMacros replaces the configured macros.
func (e *sessionEngine) SetMacros(ms []Macro) { e.setMacros(ms) }

// SetRules replaces the configured session rules.
func (e *sessionEngine) SetRules(rs []SessionRule) { e.setRules(rs) }

// RunMacroByName executes a stored macro against the shared session store.
func (e *sessionEngine) RunMacroByName(name string) (MacroRun, error) {
	return e.runMacroByName(name)
}

// runMacroByName executes a stored macro against the shared session store.
func (e *sessionEngine) runMacroByName(name string) (MacroRun, error) {
	if e.runGuard != nil {
		if err := e.runGuard(); err != nil {
			return MacroRun{}, err
		}
	}
	m, ok := e.macro(name)
	if !ok {
		return MacroRun{}, fmt.Errorf("macro %q not found", name)
	}
	if e.sender != nil {
		return runMacroWithSender(m, e.vars, e.sender), nil
	}
	return RunMacro(m, e.vars), nil
}

// applyToRequest rewrites an in-flight request per matching session rules:
// injecting headers from session vars and substituting {{var}} in the body.
// It returns the (possibly new) request and whether anything changed.
func (e *sessionEngine) applyToRequest(r *http.Request) (bool, error) {
	rules := e.snapshotRules()
	vars := e.vars.Snapshot()
	changed := false
	for _, rule := range rules {
		if !rule.Enabled || !rule.matchHost(r.Host) {
			continue
		}
		for _, h := range rule.SetHeaders {
			if v, ok := vars[h.Var]; ok && h.Name != "" {
				r.Header.Set(h.Name, v)
				changed = true
			}
		}
		if rule.SubstBody && r.Body != nil {
			full, restored, err := bufferEditableBody(r.Body, r.ContentLength)
			r.Body = restored
			if err != nil {
				return changed, err
			}
			nb := applyVars(string(full), vars)
			setRequestBody(r, []byte(nb))
			if nb != string(full) {
				changed = true
			}
		}
	}
	return changed, nil
}

// maybeRelogin runs the configured macro when a response for host matches a
// rule's ReloginWhen pattern, refreshing session vars for subsequent requests.
// Returns the name of the macro run (if any).
func (e *sessionEngine) maybeRelogin(host, respRaw string) string {
	for _, rule := range e.snapshotRules() {
		if !rule.Enabled || rule.ReloginWhen == "" || rule.Macro == "" || !rule.matchHost(host) {
			continue
		}
		re, err := regexp.Compile(rule.ReloginWhen)
		if err != nil || !re.MatchString(respRaw) {
			continue
		}
		if _, err := e.runMacroByName(rule.Macro); err == nil {
			return rule.Macro
		}
	}
	return ""
}
