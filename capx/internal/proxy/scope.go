package proxy

import (
	"strings"
	"sync"
)

// ScopeRule is one include/exclude entry (Burp "Target scope").
type ScopeRule struct {
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix"`    // URL prefix, e.g. "https://example.com"
	Host    string `json:"host"`      // optional host match
	Subtree bool   `json:"subdomain"` // include subdomains of Host
}

// Scope holds include/exclude rules. When no include rule is enabled, all
// traffic is in scope (Burp default), minus any matching exclude rule.
type Scope struct {
	mu      sync.RWMutex
	include []ScopeRule
	exclude []ScopeRule

	onChange func() // invoked (unlocked) after the rule lists mutate
}

func newScope() *Scope { return &Scope{} }

func (s *Scope) notify() {
	if s.onChange != nil {
		s.onChange()
	}
}

// Snapshot returns copies of the include/exclude rule lists.
func (s *Scope) Snapshot() (include, exclude []ScopeRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	include = append(include, s.include...)
	exclude = append(exclude, s.exclude...)
	return
}

// SetRules replaces both rule lists atomically.
func (s *Scope) SetRules(include, exclude []ScopeRule) {
	s.mu.Lock()
	s.include = append(s.include[:0:0], include...)
	s.exclude = append(s.exclude[:0:0], exclude...)
	s.mu.Unlock()
	s.notify()
}

// AddInclude / AddExclude append a single rule.
func (s *Scope) AddInclude(r ScopeRule) {
	s.mu.Lock()
	s.include = append(s.include, r)
	s.mu.Unlock()
	s.notify()
}
func (s *Scope) AddExclude(r ScopeRule) {
	s.mu.Lock()
	s.exclude = append(s.exclude, r)
	s.mu.Unlock()
	s.notify()
}

// InScope reports whether scheme://host/path is in scope.
func (s *Scope) InScope(scheme, host, path string) bool {
	url := scheme + "://" + host + path
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, r := range s.exclude {
		if r.Enabled && r.match(scheme, host, url) {
			return false
		}
	}
	anyInclude := false
	for _, r := range s.include {
		if r.Enabled {
			anyInclude = true
			if r.match(scheme, host, url) {
				return true
			}
		}
	}
	return !anyInclude // empty include set => everything in scope
}

func (r ScopeRule) match(_, host, url string) bool {
	if r.Host != "" {
		h := stripPort(host)
		if r.Subtree {
			if h != r.Host && !strings.HasSuffix(h, "."+r.Host) {
				return false
			}
		} else if h != r.Host {
			return false
		}
	}
	if r.Prefix != "" && !strings.HasPrefix(url, r.Prefix) {
		return false
	}
	return r.Host != "" || r.Prefix != ""
}
