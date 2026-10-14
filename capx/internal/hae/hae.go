// Package hae implements a HaE-compatible (github.com/gh0stkey/HaE) rule engine:
// it loads HaE's Rules.yml verbatim and applies the regex rules to captured
// HTTP messages to highlight + extract sensitive information (API keys, tokens,
// fingerprints, endpoints, PII, ...). This lets capx reuse HaE's large
// community ruleset instead of hand-coding detectors.
//
// HaE rule fields (per group): name, f_regex (primary, capture groups in
// parens), s_regex (optional secondary extraction over f_regex matches),
// format ({0}/{1}.. group templating), color, scope (request/response line/
// header/body or "any"[/header/body]), engine (nfa/dfa), sensitive (case
// sensitivity), loaded (enabled).
//
// Go's regexp (RE2) does not support backreferences/lookaround, so a small
// fraction of HaE NFA rules that use those features will fail to compile; those
// are skipped and reported rather than aborting the whole load.
package hae

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// defaultRulesYML is capx's built-in HaE ruleset, embedded so HaE extraction
// works out of the box without uploading a Rules.yml. It can still be replaced
// at runtime via Load (the /api/hae/rules endpoint).
//
//go:embed default_rules.yml
var defaultRulesYML []byte

// Rule is one HaE rule (YAML field names match HaE's Rules.yml exactly).
type Rule struct {
	Name      string `yaml:"name" json:"name"`
	Loaded    bool   `yaml:"loaded" json:"loaded"`
	FRegex    string `yaml:"f_regex" json:"f_regex"`
	SRegex    string `yaml:"s_regex" json:"s_regex"`
	Format    string `yaml:"format" json:"format"`
	Color     string `yaml:"color" json:"color"`
	Scope     string `yaml:"scope" json:"scope"`
	Engine    string `yaml:"engine" json:"engine"`
	Sensitive bool   `yaml:"sensitive" json:"sensitive"`

	group string
	fre   *regexp.Regexp
	sre   *regexp.Regexp
}

// Group is a named set of rules.
type Group struct {
	Group string `yaml:"group" json:"group"`
	Rule  []Rule `yaml:"rule" json:"rule"`
}

// config is the top-level Rules.yml document.
type config struct {
	Rules []Group `yaml:"rules"`
}

// Message is the captured HTTP message a ruleset is applied to. Each part is
// optional; empty parts simply never match.
type Message struct {
	ReqLine    string
	ReqHeader  string
	ReqBody    string
	RespLine   string
	RespHeader string
	RespBody   string
}

// Match is one rule hit on a message.
type Match struct {
	Group   string   `json:"group"`
	Name    string   `json:"name"`
	Color   string   `json:"color"`
	Extract []string `json:"extract"`
}

// Engine holds the compiled, enabled rules.
type Engine struct {
	mu      sync.RWMutex
	rules   []*Rule
	skipped []string // "group/name: reason" for rules that failed to compile
	groups  int
}

// New returns an engine preloaded with capx's built-in HaE ruleset. If the
// embedded rules fail to parse the engine simply starts empty.
func New() *Engine {
	e := &Engine{}
	if len(defaultRulesYML) > 0 {
		_, _, _ = e.Load(defaultRulesYML)
	}
	return e
}

// Load parses a HaE Rules.yml document and replaces the engine's ruleset.
// It returns the number of loaded rules and the names of skipped (uncompilable)
// rules. A parse error replaces nothing.
func (e *Engine) Load(yml []byte) (loaded int, skipped []string, err error) {
	var cfg config
	if err := yaml.Unmarshal(yml, &cfg); err != nil {
		return 0, nil, fmt.Errorf("parse Rules.yml: %w", err)
	}
	var rules []*Rule
	var skip []string
	for _, g := range cfg.Rules {
		for i := range g.Rule {
			r := g.Rule[i]
			r.group = g.Group
			if !r.Loaded || r.FRegex == "" {
				continue
			}
			fre, ferr := compile(r.FRegex, r.Sensitive)
			if ferr != nil {
				skip = append(skip, fmt.Sprintf("%s/%s: %v", g.Group, r.Name, ferr))
				continue
			}
			r.fre = fre
			if strings.TrimSpace(r.SRegex) != "" {
				if sre, serr := compile(r.SRegex, r.Sensitive); serr == nil {
					r.sre = sre
				}
			}
			rc := r
			rules = append(rules, &rc)
		}
	}
	e.mu.Lock()
	e.rules = rules
	e.skipped = skip
	e.groups = len(cfg.Rules)
	e.mu.Unlock()
	return len(rules), skip, nil
}

// compile builds a RE2 regexp, applying case-insensitivity when not sensitive.
func compile(pat string, sensitive bool) (*regexp.Regexp, error) {
	if !sensitive && !strings.HasPrefix(pat, "(?i)") {
		pat = "(?i)" + pat
	}
	return regexp.Compile(pat)
}

// Stats reports loaded/skipped counts.
func (e *Engine) Stats() (loaded, skipped, groups int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules), len(e.skipped), e.groups
}

// Skipped returns the rules that failed to compile (RE2 limitations).
func (e *Engine) Skipped() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, len(e.skipped))
	copy(out, e.skipped)
	return out
}

// Rules returns a snapshot of the loaded rules (metadata only).
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, Rule{Name: r.Name, Loaded: r.Loaded, FRegex: r.FRegex, SRegex: r.SRegex,
			Format: r.Format, Color: r.Color, Scope: r.Scope, Engine: r.Engine, Sensitive: r.Sensitive})
	}
	return out
}

// Apply runs every loaded rule against a message, returning the matches.
func (e *Engine) Apply(m Message) []Match {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	var out []Match
	for _, r := range rules {
		text := scopeText(r.Scope, m)
		if text == "" {
			continue
		}
		extracts := r.extract(text)
		if len(extracts) == 0 {
			continue
		}
		out = append(out, Match{Group: r.group, Name: r.Name, Color: r.Color, Extract: dedupCap(extracts, 50)})
	}
	return out
}

// extract returns the formatted extractions for a rule over the given text.
func (r *Rule) extract(text string) []string {
	matches := r.fre.FindAllStringSubmatch(text, -1)
	if matches == nil {
		return nil
	}
	var out []string
	for _, m := range matches {
		val := formatGroups(r.Format, m)
		if r.sre != nil {
			// Secondary regex extracts further from the primary match value.
			for _, sm := range r.sre.FindAllStringSubmatch(val, -1) {
				if len(sm) > 1 {
					out = append(out, sm[1])
				} else {
					out = append(out, sm[0])
				}
			}
			continue
		}
		out = append(out, val)
	}
	return out
}

// formatGroups renders HaE's {0}/{1}.. templating against a regex submatch.
func formatGroups(format string, groups []string) string {
	if format == "" {
		format = "{0}"
	}
	out := format
	for i, g := range groups {
		out = strings.ReplaceAll(out, "{"+strconv.Itoa(i)+"}", g)
	}
	return out
}

// scopeText selects the part(s) of the message a rule's scope targets.
func scopeText(scope string, m Message) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "any":
		return join(m.ReqLine, m.ReqHeader, m.ReqBody, m.RespLine, m.RespHeader, m.RespBody)
	case "any header":
		return join(m.ReqHeader, m.RespHeader)
	case "any body":
		return join(m.ReqBody, m.RespBody)
	case "request", "request line":
		return m.ReqLine
	case "request header":
		return m.ReqHeader
	case "request body":
		return m.ReqBody
	case "response", "response line":
		return m.RespLine
	case "response header":
		return m.RespHeader
	case "response body":
		return m.RespBody
	}
	// Unknown scope: be permissive and scan everything.
	return join(m.ReqLine, m.ReqHeader, m.ReqBody, m.RespLine, m.RespHeader, m.RespBody)
}

func join(parts ...string) string {
	nonEmpty := parts[:0]
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n")
}

func dedupCap(in []string, max int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}
