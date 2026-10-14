package proxy

import (
	"path"
	"strings"
	"sync"
)

// InterceptCond is one ordered interception condition (Burp "intercept client
// requests" rules). The first enabled rule that matches a request decides
// whether it is paused ("intercept") or passed straight through ("forward").
// If no rule matches, the request is intercepted by default — so an empty rule
// set preserves the original "pause everything in scope" behavior.
//
// A predicate left empty is ignored; a rule with every predicate empty matches
// any request and acts as an explicit catch-all (commonly a trailing "forward"
// to auto-pass anything the earlier rules did not single out).
type InterceptCond struct {
	Enabled   bool   `json:"enabled"`
	Action    string `json:"action"`     // "intercept" (default) | "forward"
	Host      string `json:"host"`       // host substring, case-insensitive
	Method    string `json:"method"`     // exact method, case-insensitive
	FileExt   string `json:"file_ext"`   // comma list, e.g. "js,css,png,woff2"
	HasParams string `json:"has_params"` // "" any | "yes" | "no" (query string)
}

// condSet is the ordered, concurrency-safe list of interception conditions.
type condSet struct {
	mu    sync.RWMutex
	rules []InterceptCond

	onChange func() // invoked (unlocked) after the rule list mutates
}

func newCondSet() *condSet { return &condSet{} }

func (c *condSet) snapshot() []InterceptCond {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]InterceptCond(nil), c.rules...)
}

func (c *condSet) set(rules []InterceptCond) {
	c.mu.Lock()
	c.rules = append(c.rules[:0:0], rules...)
	c.mu.Unlock()
	if c.onChange != nil {
		c.onChange()
	}
}

// shouldIntercept evaluates the ordered rules for a request and reports whether
// it should be paused for manual interception.
func (c *condSet) shouldIntercept(method, host, urlPath, rawQuery string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.rules {
		if !r.Enabled {
			continue
		}
		if r.matches(method, host, urlPath, rawQuery) {
			return !strings.EqualFold(r.Action, "forward")
		}
	}
	return true // no rule matched: intercept by default
}

func (r InterceptCond) matches(method, host, urlPath, rawQuery string) bool {
	if r.Host != "" && !strings.Contains(strings.ToLower(stripPort(host)), strings.ToLower(r.Host)) {
		return false
	}
	if r.Method != "" && !strings.EqualFold(strings.TrimSpace(r.Method), method) {
		return false
	}
	if r.FileExt != "" {
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(urlPath)), ".")
		if !extInList(ext, r.FileExt) {
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(r.HasParams)) {
	case "yes", "true":
		if rawQuery == "" {
			return false
		}
	case "no", "false":
		if rawQuery != "" {
			return false
		}
	}
	return true
}

// extInList reports whether ext (without leading dot) is one of the
// comma-separated extensions in list.
func extInList(ext, list string) bool {
	if ext == "" {
		return false
	}
	for _, e := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(e), "."), ext) {
			return true
		}
	}
	return false
}
