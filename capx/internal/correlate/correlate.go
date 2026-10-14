// Package correlate implements the M7 cross-layer correlation engine: it lines
// up the same logical session across capture layers (L3/L4 flow <-> L7 HTTP/WS
// <-> in-process TLS hook) by unioning shared correlation keys (flow id, host,
// pid, ip:port endpoint) with a union-find, then emitting per-session timelines.
//
// The Build function is a pure, deterministic transform over snapshots taken
// from the store, which keeps it trivially unit-testable; the Engine wrapper
// just feeds it live store data on demand.
package correlate

import (
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hquip/capx/internal/model"
)

// Entry is one event placed on a correlated timeline.
type Entry struct {
	TS      time.Time    `json:"ts"`
	Source  model.Source `json:"source"`
	Kind    string       `json:"kind"`
	Summary string       `json:"summary"`
	keys    []string     // correlation keys this entry exposes (internal)
}

// Group is a set of entries the engine believes belong to one logical session.
type Group struct {
	CorrID  string    `json:"corr_id"`
	Keys    []string  `json:"keys"`
	Started time.Time `json:"started"`
	Updated time.Time `json:"updated"`
	Entries []Entry   `json:"entries"`
}

// Input is a snapshot of the layers to correlate.
type Input struct {
	Flows   []*model.Flow
	HTTP    []*model.HTTPTx
	WS      []*model.WSMessage
	Hooks   []*model.HookEvent
	MemHits []*model.MemHit
}

// Build correlates a snapshot into timeline groups, ordered by first activity.
func Build(in Input) []*Group {
	uf := newUnionFind()
	var entries []*Entry

	add := func(e *Entry) {
		if len(e.keys) == 0 {
			return
		}
		for _, k := range e.keys[1:] {
			uf.union(e.keys[0], k)
		}
		uf.add(e.keys[0])
		entries = append(entries, e)
	}

	for _, f := range in.Flows {
		add(&Entry{
			TS:      f.Started,
			Source:  model.SourceSniffer,
			Kind:    "flow",
			Summary: string(f.L4) + " " + ep(f.SrcIP, f.SrcPort) + " -> " + ep(f.DstIP, f.DstPort),
			keys:    []string{"flow:" + f.ID, "ep:" + ep(f.DstIP, f.DstPort)},
		})
	}
	for _, tx := range in.HTTP {
		keys := []string{"host:" + hostOnly(tx.Host), "http:" + utoa(tx.ID)}
		if tx.FlowID != "" {
			keys = append(keys, "flow:"+tx.FlowID)
		}
		// The resolved upstream endpoint bridges this HTTP tx to the L3/L4
		// flow and to in-process TLS hook events that share the same peer.
		if tx.ServerAddr != "" {
			keys = append(keys, "ep:"+tx.ServerAddr)
		}
		add(&Entry{
			TS:      tx.TS,
			Source:  model.SourceProxy,
			Kind:    "http_tx",
			Summary: tx.Method + " " + tx.URL + " -> " + itoa(tx.Status),
			keys:    keys,
		})
	}
	for _, m := range in.WS {
		keys := []string{"host:" + hostOnly(hostFromURL(m.URL))}
		if m.FlowID != "" {
			keys = append(keys, "flow:"+m.FlowID)
		}
		add(&Entry{
			TS:      m.TS,
			Source:  model.SourceProxy,
			Kind:    "ws_msg",
			Summary: "ws " + string(m.Dir) + " " + m.Opcode + " (" + itoa(m.Length) + "B)",
			keys:    keys,
		})
	}
	for _, h := range in.Hooks {
		keys := []string{"pid:" + utoa(uint64(h.PID))}
		if host := hostOnly(h.Peer); host != "" {
			keys = append(keys, "host:"+host)
		}
		if h.Peer != "" && strings.Contains(h.Peer, ":") {
			keys = append(keys, "ep:"+h.Peer)
		}
		add(&Entry{
			TS:      h.TS,
			Source:  model.SourceHook,
			Kind:    "hook_tls",
			Summary: h.Func + " " + h.Dir + " (" + itoa(h.Len) + "B plaintext)",
			keys:    keys,
		})
	}
	for _, m := range in.MemHits {
		keys := []string{"pid:" + utoa(uint64(m.PID))}
		if m.HTTPID != 0 {
			keys = append(keys, "http:"+utoa(m.HTTPID))
		}
		if host := hostOnly(m.Host); host != "" {
			keys = append(keys, "host:"+host)
		}
		add(&Entry{
			TS:      m.TS,
			Source:  model.SourceMem,
			Kind:    "mem_hit",
			Summary: m.Type + " @ 0x" + fmt.Sprintf("%x", m.Addr) + " = " + m.Value,
			keys:    keys,
		})
	}

	// Bucket entries by their union-find root.
	byRoot := map[string]*Group{}
	for _, e := range entries {
		root := uf.find(e.keys[0])
		g := byRoot[root]
		if g == nil {
			g = &Group{Started: e.TS, Updated: e.TS}
			byRoot[root] = g
		}
		g.Entries = append(g.Entries, *e)
		if e.TS.Before(g.Started) {
			g.Started = e.TS
		}
		if e.TS.After(g.Updated) {
			g.Updated = e.TS
		}
		for _, k := range e.keys {
			if !contains(g.Keys, k) {
				g.Keys = append(g.Keys, k)
			}
		}
	}

	groups := make([]*Group, 0, len(byRoot))
	for _, g := range byRoot {
		sort.Slice(g.Entries, func(i, j int) bool { return g.Entries[i].TS.Before(g.Entries[j].TS) })
		sort.Strings(g.Keys)
		// A content-derived id keeps the same logical session stable across
		// repeated correlations (instead of a positional "corr-1" that shifts
		// as new sessions appear).
		g.CorrID = "corr-" + corrHash(g.Keys)
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Started.Equal(groups[j].Started) {
			return groups[i].CorrID < groups[j].CorrID
		}
		return groups[i].Started.Before(groups[j].Started)
	})
	return groups
}

// corrHash returns a short stable hex id derived from a group's sorted keys.
func corrHash(keys []string) string {
	h := fnv.New64a()
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
	}
	return strconv.FormatUint(h.Sum64()&0xffffffff, 16)
}

// --- helpers ---

func ep(ip string, port uint16) string {
	return net.JoinHostPort(ip, strconv.FormatUint(uint64(port), 10))
}

func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func hostFromURL(u string) string {
	u = strings.TrimPrefix(u, "ws://")
	u = strings.TrimPrefix(u, "wss://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(i int) string { return strconv.Itoa(i) }

func utoa(u uint64) string { return strconv.FormatUint(u, 10) }

// --- union-find over string keys ---

type unionFind struct{ parent map[string]string }

func newUnionFind() *unionFind { return &unionFind{parent: map[string]string{}} }

func (u *unionFind) add(k string) {
	if _, ok := u.parent[k]; !ok {
		u.parent[k] = k
	}
}

func (u *unionFind) find(k string) string {
	u.add(k)
	for u.parent[k] != k {
		u.parent[k] = u.parent[u.parent[k]]
		k = u.parent[k]
	}
	return k
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}
