// Package inline implements raw-packet inline modification (M6): match&replace
// or drop on live packets at the network layer. The pure-Go rule engine here
// is platform-independent and fully unit-tested; the actual packet diversion
// backend (WinDivert on Windows, NFQUEUE on Linux) is pluggable and gated
// behind build tags, with a stub default so capx always builds and runs.
package inline

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// PacketRule matches raw packet bytes and either rewrites them in place
// (equal-length, so IP/transport length fields stay valid and only checksums
// need recomputing) or drops the packet. Match is an AOB-style hex pattern that
// may contain "??" wildcards; Replace is a plain hex string whose byte length
// must equal Match's when Action is "replace".
type PacketRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Proto   string `json:"proto"`             // "tcp" | "udp" | "any"
	Port    int    `json:"port,omitempty"`    // match src or dst port; 0 = any
	Match   string `json:"match"`             // AOB hex, e.g. "48 8B ?? C0"
	Replace string `json:"replace,omitempty"` // hex; equal-length unless AllowResize
	Action  string `json:"action"`            // "replace" | "drop"
	// AllowResize permits a Replace of a different byte length than Match. The
	// engine then splices the packet and fixes the IP (and UDP) length fields.
	// Safe for UDP; for TCP a length change desyncs the stream (seq/ack of later
	// packets shift), so use with care.
	AllowResize bool   `json:"allow_resize,omitempty"`
	Hits        uint64 `json:"hits"`

	pat  []byte // pattern bytes (wildcards are 0)
	mask []byte // 1 where pat byte is significant, 0 for wildcard
	repl []byte // replacement bytes (Action=="replace")
}

// Engine is a concurrency-safe ordered set of packet rules.
type Engine struct {
	mu    sync.RWMutex
	rules []*PacketRule
	seq   int
	fixer *TCPFixer
}

// NewEngine returns an empty engine.
func NewEngine() *Engine { return &Engine{fixer: NewTCPFixer()} }

// List returns a snapshot copy of the rules.
func (e *Engine) List() []*PacketRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*PacketRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Add validates, compiles, and appends a rule.
func (e *Engine) Add(r *PacketRule) (*PacketRule, error) {
	if err := compileRule(r); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	r.ID = fmt.Sprintf("prule-%d", e.seq)
	r.Hits = 0
	e.rules = append(e.rules, r)
	return r, nil
}

// Delete removes a rule by ID.
func (e *Engine) Delete(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Apply runs the rules against a single packet's bytes. proto is "tcp"/"udp",
// srcPort/dstPort identify the flow (0 if unknown). It returns the possibly
// rewritten packet, whether to drop it, whether any rule matched (hit), and
// whether the packet bytes were changed at all (modified — true for a rule hit
// and also for steady-state TCP sequence/ACK fix-ups on connections whose length
// has shifted). The input slice may be modified in place for replacements.
func (e *Engine) Apply(pkt []byte, proto string, srcPort, dstPort int) (out []byte, drop bool, hit bool, modified bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	inLen := len(pkt)
	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		if r.Proto != "" && r.Proto != "any" && r.Proto != proto {
			continue
		}
		if r.Port != 0 && r.Port != srcPort && r.Port != dstPort {
			continue
		}
		idx := indexPattern(pkt, r.pat, r.mask)
		if idx < 0 {
			continue
		}
		atomic.AddUint64(&r.Hits, 1)
		hit = true
		if r.Action == "drop" {
			return pkt, true, true, true
		}
		if len(r.repl) == len(r.pat) {
			// equal-length: rewrite in place, headers untouched.
			copy(pkt[idx:idx+len(r.repl)], r.repl)
			continue
		}
		// variable-length: splice and fix IP/UDP length fields. Re-parse each
		// time because a prior resize shifted offsets.
		matchLen := len(r.pat)
		info := parseIP(pkt)
		delta := len(r.repl) - matchLen
		spliced := make([]byte, 0, len(pkt)+delta)
		spliced = append(spliced, pkt[:idx]...)
		spliced = append(spliced, r.repl...)
		spliced = append(spliced, pkt[idx+matchLen:]...)
		fixLengthsAfterResize(spliced, info, delta)
		pkt = spliced
	}
	modified = hit

	// Keep TCP streams in sync after any variable-length rewrite. The fixer runs
	// for every TCP packet of a connection once a resize rule is configured, so
	// SEQ/ACK stay consistent even on packets this call did not itself rewrite.
	if proto == "tcp" && e.fixer != nil && e.hasResizeRuleLocked() {
		info := parseIP(pkt)
		if info.OK && info.Proto == "tcp" {
			thisDelta := len(pkt) - inLen
			if e.fixer.fixTCP(pkt, info, thisDelta) {
				modified = true
			}
		}
	}
	return pkt, false, hit, modified
}

// hasResizeRuleLocked reports whether any enabled rule may change TCP payload
// length (so the fixer should track this connection). Caller holds e.mu.
func (e *Engine) hasResizeRuleLocked() bool {
	for _, r := range e.rules {
		if r.Enabled && r.AllowResize && r.Action == "replace" &&
			(r.Proto == "tcp" || r.Proto == "any" || r.Proto == "") {
			return true
		}
	}
	return false
}

func compileRule(r *PacketRule) error {
	switch r.Proto {
	case "", "any", "tcp", "udp":
	default:
		return fmt.Errorf("proto must be tcp|udp|any")
	}
	if r.Action == "" {
		r.Action = "replace"
	}
	if r.Action != "replace" && r.Action != "drop" {
		return fmt.Errorf("action must be replace|drop")
	}
	pat, mask, err := parseAOB(r.Match)
	if err != nil {
		return fmt.Errorf("bad match pattern: %w", err)
	}
	if len(pat) == 0 {
		return fmt.Errorf("empty match pattern")
	}
	r.pat, r.mask = pat, mask
	if r.Action == "replace" {
		repl, err := hex.DecodeString(stripSpaces(r.Replace))
		if err != nil {
			return fmt.Errorf("bad replace hex: %w", err)
		}
		if len(repl) != len(pat) && !r.AllowResize {
			return fmt.Errorf("replace length %d != match length %d (set allow_resize for variable-length rewrite)", len(repl), len(pat))
		}
		r.repl = repl
	}
	return nil
}

// parseAOB parses an AOB-style hex pattern with optional "??" wildcards into
// (pattern, mask). Bytes may be space-separated or contiguous.
func parseAOB(s string) (pat, mask []byte, err error) {
	fields := strings.Fields(s)
	if len(fields) == 1 && len(fields[0])%2 == 0 && !strings.Contains(fields[0], "?") {
		// contiguous hex like "deadbeef"
		b, e := hex.DecodeString(fields[0])
		if e != nil {
			return nil, nil, e
		}
		m := make([]byte, len(b))
		for i := range m {
			m[i] = 1
		}
		return b, m, nil
	}
	for _, f := range fields {
		if f == "??" || f == "?" {
			pat = append(pat, 0)
			mask = append(mask, 0)
			continue
		}
		if len(f) != 2 {
			return nil, nil, fmt.Errorf("token %q not a byte", f)
		}
		v, e := hex.DecodeString(f)
		if e != nil {
			return nil, nil, e
		}
		pat = append(pat, v[0])
		mask = append(mask, 1)
	}
	return pat, mask, nil
}

// indexPattern returns the first index where pat (with mask) occurs in b, or -1.
func indexPattern(b, pat, mask []byte) int {
	if len(pat) == 0 || len(b) < len(pat) {
		return -1
	}
	for i := 0; i+len(pat) <= len(b); i++ {
		ok := true
		for j := range pat {
			if mask[j] == 1 && b[i+j] != pat[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func stripSpaces(s string) string { return strings.ReplaceAll(s, " ", "") }
