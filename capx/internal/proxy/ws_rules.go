package proxy

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hquip/capx/internal/model"
)

// WSMatchRule rewrites or drops proxied WebSocket data frames before they are
// forwarded. Text frames match on text; binary frames match on base64 text.
type WSMatchRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`     // substring match on connection URL; empty = all
	Dir     string `json:"dir"`     // send | recv | empty = any
	Opcode  string `json:"opcode"`  // text | binary | empty = any
	Match   string `json:"match"`   // regexp on text or base64
	Replace string `json:"replace"` // replacement, ignored for drop
	Action  string `json:"action"`  // replace | drop
	Hits    uint64 `json:"hits"`

	re *regexp.Regexp
}

type WSRuleSet struct {
	mu    sync.RWMutex
	rules []*WSMatchRule
	seq   int

	onChange func()
}

func newWSRuleSet() *WSRuleSet { return &WSRuleSet{} }

func (rs *WSRuleSet) notify() {
	if rs.onChange != nil {
		rs.onChange()
	}
}

func (rs *WSRuleSet) List() []*WSMatchRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*WSMatchRule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

func (rs *WSRuleSet) Add(r *WSMatchRule) (*WSMatchRule, error) {
	if err := normalizeWSMatchRule(r); err != nil {
		return nil, err
	}
	rs.mu.Lock()
	rs.seq++
	r.ID = fmt.Sprintf("wsrule-%d", rs.seq)
	r.Hits = 0
	rs.rules = append(rs.rules, r)
	rs.mu.Unlock()
	rs.notify()
	return r, nil
}

func (rs *WSRuleSet) Delete(id string) bool {
	rs.mu.Lock()
	found := false
	for i, r := range rs.rules {
		if r.ID == id {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			found = true
			break
		}
	}
	rs.mu.Unlock()
	if found {
		rs.notify()
	}
	return found
}

func (rs *WSRuleSet) restore(rules []*WSMatchRule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = rs.rules[:0]
	for _, r := range rules {
		if r == nil {
			continue
		}
		if err := normalizeWSMatchRule(r); err != nil {
			continue
		}
		if n := parseWSRuleSeq(r.ID); n > rs.seq {
			rs.seq = n
		}
		rs.rules = append(rs.rules, r)
	}
}

func parseWSRuleSeq(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "wsrule-"))
	if err != nil {
		return 0
	}
	return n
}

func normalizeWSMatchRule(r *WSMatchRule) error {
	if r == nil {
		return fmt.Errorf("rule is nil")
	}
	r.Dir = strings.ToLower(strings.TrimSpace(r.Dir))
	if r.Dir != "" && r.Dir != string(model.WSSend) && r.Dir != string(model.WSRecv) {
		return fmt.Errorf("dir must be send|recv|empty")
	}
	r.Opcode = strings.ToLower(strings.TrimSpace(r.Opcode))
	if r.Opcode != "" && r.Opcode != "text" && r.Opcode != "binary" {
		return fmt.Errorf("opcode must be text|binary|empty")
	}
	if r.Action == "" {
		r.Action = "replace"
	}
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	if r.Action != "replace" && r.Action != "drop" {
		return fmt.Errorf("action must be replace|drop")
	}
	re, err := regexp.Compile(r.Match)
	if err != nil {
		return fmt.Errorf("bad match regexp: %w", err)
	}
	r.re = re
	return nil
}

func (r *WSMatchRule) matches(wc *wsConn, dir model.WSDir, opcode byte, text string) bool {
	if !r.Enabled || r.re == nil {
		return false
	}
	if r.URL != "" && (wc == nil || !strings.Contains(strings.ToLower(wc.url), strings.ToLower(r.URL))) {
		return false
	}
	if r.Dir != "" && r.Dir != string(dir) {
		return false
	}
	op := "text"
	if opcode == 0x2 {
		op = "binary"
	}
	if r.Opcode != "" && r.Opcode != op {
		return false
	}
	return r.re.MatchString(text)
}

func (rs *WSRuleSet) hasEnabled() bool {
	if rs == nil {
		return false
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	for _, r := range rs.rules {
		if r != nil && r.Enabled {
			return true
		}
	}
	return false
}

// apply mutates payload per enabled rules and returns drop=true when forwarding
// should be suppressed. Binary frames are matched and replaced as base64.
func (rs *WSRuleSet) apply(wc *wsConn, dir model.WSDir, opcode byte, payload []byte) ([]byte, bool, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if len(rs.rules) == 0 {
		return payload, false, false
	}
	text := string(payload)
	if opcode == 0x2 {
		text = base64.StdEncoding.EncodeToString(payload)
	}
	changed := false
	for _, rule := range rs.rules {
		if !rule.matches(wc, dir, opcode, text) {
			continue
		}
		atomic.AddUint64(&rule.Hits, 1)
		if rule.Action == "drop" {
			return payload, true, changed
		}
		text = rule.re.ReplaceAllString(text, rule.Replace)
		changed = true
	}
	if !changed {
		return payload, false, false
	}
	if opcode == 0x2 {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return payload, false, false
		}
		return dec, false, true
	}
	return []byte(text), false, true
}
