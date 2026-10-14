package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Rule is a single Match&Replace / block rule applied inline to proxied
// traffic (M6). Match is always treated as a regular expression; escape it for
// literal matches. A request rule with Action "block" short-circuits the
// request with a 403 instead of forwarding it upstream.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Target  string `json:"target"`           // "request" | "response"
	Where   string `json:"where"`            // "body" | "header" | "url" | "status"
	Header  string `json:"header,omitempty"` // header name when Where=="header"
	Match   string `json:"match"`            // regular expression
	Replace string `json:"replace"`          // replacement (supports $1 groups)
	Action  string `json:"action"`           // "replace" | "block"
	Hits    uint64 `json:"hits"`

	// MaR-style conditional gating (github.com/gh0stkey/MaR): when CondMatch is
	// set, the rule only fires if the condition holds on CondWhere
	// ("url"|"header"|"body"|"status"|"any"). CondNegate inverts it ("does not
	// match"); CondRegex treats CondMatch as a regex (else literal substring).
	CondWhere  string `json:"cond_where,omitempty"`
	CondHeader string `json:"cond_header,omitempty"`
	CondMatch  string `json:"cond_match,omitempty"`
	CondRegex  bool   `json:"cond_regex,omitempty"`
	CondNegate bool   `json:"cond_negate,omitempty"`

	re     *regexp.Regexp
	condRe *regexp.Regexp
}

// HTTPMutator is an optional programmatic transform over proxied messages (the
// Lua script layer implements it). It returns the possibly-modified headers and
// body plus whether anything changed. Defined here to avoid a proxy->script
// import cycle; the api layer wires the concrete implementation in.
type HTTPMutator interface {
	// WantsRequest/WantsResponse report whether any script registered a
	// request/response hook, so the proxy can skip reading+rebuilding the body
	// on the common no-hook path. Whole-body hooks have an explicit edit limit.
	WantsRequest() bool
	WantsResponse() bool
	MutateRequest(method, url, host string, headers map[string]string, body []byte) (map[string]string, []byte, bool)
	MutateResponse(status int, headers map[string]string, body []byte) (map[string]string, []byte, bool)
}

// SetMutator installs the programmatic HTTP mutator (script engine).
func (p *Proxy) SetMutator(m HTTPMutator) { p.mutator = m }

// headerLines renders headers as "Name: value" lines for condition matching.
func headerLines(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// applyRequestMutator runs the script mutator over a request, rebuilding its
// body + headers (and Content-Length) when a script changed them.
func (p *Proxy) applyRequestMutator(r *http.Request) error {
	if p.mutator == nil || !p.mutator.WantsRequest() {
		return nil
	}
	body, restored, err := bufferEditableBody(r.Body, r.ContentLength)
	r.Body = restored
	if err != nil {
		return err
	}
	nh, nb, changed := p.mutator.MutateRequest(r.Method, r.URL.String(), r.Host, flattenHeader(r.Header), body)
	if changed {
		applyHeaderMap(r.Header, nh)
		setRequestBody(r, nb)
	}
	return nil
}

// applyResponseMutator only buffers when a script actually registered a hook.
func (p *Proxy) applyResponseMutator(resp *http.Response) error {
	if p.mutator == nil || !p.mutator.WantsResponse() {
		return nil
	}
	if err := rejectStreamingEdit(resp.Header); err != nil {
		return err
	}
	body, restored, err := bufferEditableBody(resp.Body, resp.ContentLength)
	resp.Body = restored
	if err != nil {
		return err
	}
	nh, nb, changed := p.mutator.MutateResponse(resp.StatusCode, flattenHeader(resp.Header), body)
	if changed {
		applyHeaderMap(resp.Header, nh)
		setResponseBody(resp, nb)
	}
	return nil
}

// applyHeaderMap overwrites h with the flat name->value map (comma-joined
// values are kept as-is); existing headers not present in m are removed.
func applyHeaderMap(h http.Header, m map[string]string) {
	for k := range h {
		if _, ok := m[k]; !ok {
			h.Del(k)
		}
	}
	for k, v := range m {
		h.Set(k, v)
	}
}

// RuleSet is a concurrency-safe ordered list of rules.
type RuleSet struct {
	mu    sync.RWMutex
	rules []*Rule
	seq   int

	onChange func() // invoked (unlocked) after the rule list mutates
}

func newRuleSet() *RuleSet { return &RuleSet{} }

func (rs *RuleSet) notify() {
	if rs.onChange != nil {
		rs.onChange()
	}
}

// List returns a snapshot copy of the rules.
func (rs *RuleSet) List() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Add validates and appends a rule, returning the stored rule (with ID set).
func (rs *RuleSet) Add(r *Rule) (*Rule, error) {
	if err := normalizeRule(r); err != nil {
		return nil, err
	}
	rs.mu.Lock()
	rs.seq++
	r.ID = fmt.Sprintf("rule-%d", rs.seq)
	r.Hits = 0
	rs.rules = append(rs.rules, r)
	rs.mu.Unlock()
	rs.notify()
	return r, nil
}

// Delete removes a rule by ID. Returns false if not found.
func (rs *RuleSet) Delete(id string) bool {
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

// restore replaces the rule list with persisted rules, recompiling each
// regexp and advancing the id sequence past the highest restored id so future
// Add calls don't collide. Rules that fail validation are skipped. It does not
// trigger onChange (used only at load time).
func (rs *RuleSet) restore(rules []*Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = rs.rules[:0]
	for _, r := range rules {
		if r == nil {
			continue
		}
		if err := normalizeRule(r); err != nil {
			continue
		}
		if n := parseRuleSeq(r.ID); n > rs.seq {
			rs.seq = n
		}
		rs.rules = append(rs.rules, r)
	}
}

// parseRuleSeq extracts the numeric suffix of a "rule-N" id, returning 0 when
// the id has no recognizable sequence number.
func parseRuleSeq(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "rule-"))
	if err != nil {
		return 0
	}
	return n
}

// normalizeRule validates fields and compiles the regexp.
func normalizeRule(r *Rule) error {
	if r.Target != "request" && r.Target != "response" {
		return fmt.Errorf("target must be request|response")
	}
	switch r.Where {
	case "body", "url", "status":
	case "header":
		if r.Header == "" {
			return fmt.Errorf("header name required when where=header")
		}
	default:
		return fmt.Errorf("where must be body|header|url|status")
	}
	if r.Action == "" {
		r.Action = "replace"
	}
	if r.Action != "replace" && r.Action != "block" {
		return fmt.Errorf("action must be replace|block")
	}
	if r.Action == "block" && r.Target != "request" {
		return fmt.Errorf("block action only valid for request rules")
	}
	if r.Where == "url" && r.Target != "request" {
		return fmt.Errorf("where=url only valid for request rules")
	}
	if r.Where == "status" && r.Target != "response" {
		return fmt.Errorf("where=status only valid for response rules")
	}
	re, err := regexp.Compile(r.Match)
	if err != nil {
		return fmt.Errorf("bad match regexp: %w", err)
	}
	r.re = re
	// MaR-style condition: compile the optional gate (literal unless CondRegex).
	if strings.TrimSpace(r.CondMatch) != "" {
		pat := r.CondMatch
		if !r.CondRegex {
			pat = regexp.QuoteMeta(pat)
		}
		cre, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("bad condition regexp: %w", err)
		}
		r.condRe = cre
	}
	return nil
}

// applyRequest mutates r per enabled request rules. Returns blocked=true when a
// "block" rule matches (caller should refuse the request). Bodies sent with a
// supported Content-Encoding (gzip/deflate/br) are transparently decompressed
// before body rules match/replace and recompressed before forwarding.
func (rs *RuleSet) applyRequest(r *http.Request) (blocked bool, err error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var origRaw, body []byte // origRaw: on-wire bytes; body: decoded working copy
	bodyRead := false
	bodyEnc := ""
	bodyModified := false
	var bodyErr error

	readBody := func() {
		if bodyRead {
			return
		}
		bodyRead = true
		if r.Body == nil {
			return
		}
		origRaw, r.Body, bodyErr = bufferEditableBody(r.Body, r.ContentLength)
		if bodyErr != nil {
			return
		}
		if enc := decodableEncoding(r.Header); enc != "" {
			if dec, ok := decompress(enc, origRaw); ok {
				body, bodyEnc = dec, enc
				return
			}
		}
		body = origRaw
	}
	restoreBody := func() {
		if !bodyRead || bodyErr != nil {
			return
		}
		out := origRaw
		if bodyModified {
			out = body
			if bodyEnc != "" {
				if enc, ok := compress(bodyEnc, body); ok {
					out = enc
				} else {
					r.Header.Del("Content-Encoding")
				}
			}
			setRequestBody(r, out)
		} else {
			r.Body = io.NopCloser(bytes.NewReader(out))
		}
	}

	condOK := func(rule *Rule) bool {
		if rule.condRe == nil {
			return true
		}
		var text string
		switch rule.CondWhere {
		case "url":
			text = r.URL.RequestURI()
		case "header":
			text = r.Header.Get(rule.CondHeader)
		case "body":
			readBody()
			text = string(body)
		default: // "any" / ""
			readBody()
			text = r.Method + " " + r.URL.RequestURI() + "\n" + headerLines(r.Header) + "\n" + string(body)
		}
		m := rule.condRe.MatchString(text)
		if rule.CondNegate {
			return !m
		}
		return m
	}

	for _, rule := range rs.rules {
		if !rule.Enabled || rule.Target != "request" || rule.re == nil {
			continue
		}
		matches := condOK(rule)
		if bodyErr != nil {
			return false, bodyErr
		}
		if !matches {
			continue
		}
		switch rule.Where {
		case "url":
			cur := r.URL.RequestURI()
			if !rule.re.MatchString(cur) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			if rule.Action == "block" {
				restoreBody()
				return true, nil
			}
			nu := rule.re.ReplaceAllString(cur, rule.Replace)
			if parsed, err := url.ParseRequestURI(nu); err == nil {
				r.URL.Path = parsed.Path
				r.URL.RawQuery = parsed.RawQuery
			}
		case "header":
			cur := r.Header.Get(rule.Header)
			if !rule.re.MatchString(cur) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			if rule.Action == "block" {
				restoreBody()
				return true, nil
			}
			r.Header.Set(rule.Header, rule.re.ReplaceAllString(cur, rule.Replace))
		case "body":
			readBody()
			if bodyErr != nil {
				return false, bodyErr
			}
			if !rule.re.Match(body) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			if rule.Action == "block" {
				restoreBody()
				return true, nil
			}
			body = rule.re.ReplaceAll(body, []byte(rule.Replace))
			bodyModified = true
		}
	}
	restoreBody()
	return false, nil
}

// applyResponse mutates resp per enabled response rules, reading and rewriting
// the body when needed. It rewrites Content-Length so the client sees a
// consistent message. Bodies carrying a supported Content-Encoding
// (gzip/deflate/br) are transparently decompressed before body rules
// match/replace and recompressed with the same encoding before being sent.
func (rs *RuleSet) applyResponse(resp *http.Response) error {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	var origRaw, body []byte // origRaw: on-wire bytes; body: decoded working copy
	bodyRead := false
	bodyEnc := ""
	bodyModified := false
	var bodyErr error
	readBody := func() {
		if bodyRead {
			return
		}
		bodyRead = true
		bodyErr = rejectStreamingEdit(resp.Header)
		if bodyErr != nil {
			return
		}
		origRaw, resp.Body, bodyErr = bufferEditableBody(resp.Body, resp.ContentLength)
		if bodyErr != nil {
			return
		}
		if enc := decodableEncoding(resp.Header); enc != "" {
			if dec, ok := decompress(enc, origRaw); ok {
				body, bodyEnc = dec, enc
				return
			}
		}
		body = origRaw
	}
	condOK := func(rule *Rule) bool {
		if rule.condRe == nil {
			return true
		}
		var text string
		switch rule.CondWhere {
		case "status":
			text = strconv.Itoa(resp.StatusCode)
		case "header":
			text = resp.Header.Get(rule.CondHeader)
		case "body":
			readBody()
			text = string(body)
		default: // "any" / ""
			readBody()
			text = resp.Status + "\n" + headerLines(resp.Header) + "\n" + string(body)
		}
		m := rule.condRe.MatchString(text)
		if rule.CondNegate {
			return !m
		}
		return m
	}
	for _, rule := range rs.rules {
		if !rule.Enabled || rule.Target != "response" || rule.re == nil {
			continue
		}
		matches := condOK(rule)
		if bodyErr != nil {
			return bodyErr
		}
		if !matches {
			continue
		}
		switch rule.Where {
		case "status":
			cur := strconv.Itoa(resp.StatusCode)
			if !rule.re.MatchString(cur) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			ns := rule.re.ReplaceAllString(cur, rule.Replace)
			if code, err := strconv.Atoi(strings.TrimSpace(ns)); err == nil && code >= 100 && code <= 599 {
				resp.StatusCode = code
				resp.Status = strconv.Itoa(code) + " " + http.StatusText(code)
			}
		case "header":
			cur := resp.Header.Get(rule.Header)
			if !rule.re.MatchString(cur) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			resp.Header.Set(rule.Header, rule.re.ReplaceAllString(cur, rule.Replace))
		case "body":
			readBody()
			if bodyErr != nil {
				return bodyErr
			}
			if !rule.re.Match(body) {
				continue
			}
			atomic.AddUint64(&rule.Hits, 1)
			body = rule.re.ReplaceAll(body, []byte(rule.Replace))
			bodyModified = true
		}
	}
	if bodyRead {
		out := origRaw
		if bodyModified {
			out = body
			if bodyEnc != "" {
				if enc, ok := compress(bodyEnc, body); ok {
					out = enc
				} else {
					resp.Header.Del("Content-Encoding")
				}
			}
		}
		if bodyModified {
			setResponseBody(resp, out)
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(out))
		}
	}
	return nil
}
