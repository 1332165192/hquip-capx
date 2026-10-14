// Package store holds capx runtime state (captures, flows, recent events) and
// a small pub/sub hub used to fan out events to SSE subscribers. The current
// working set is bounded in memory, with optional snapshots and SQLite history.
package store

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hquip/capx/internal/model"
)

// Store is the in-memory state container. Safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	captures  map[string]*model.Capture
	flows     map[string]*model.Flow
	maxFlows  int             // cap on tracked flows (0 = unbounded)
	httpTxs   []*model.HTTPTx // L7 HTTP/HTTPS history (Burp-style)
	httpDisk  *HTTPDisk
	wsMsgs    []*model.WSMessage // WebSocket frames
	hookEvts  []*model.HookEvent // in-process hook observations (Frida)
	memHits   []*model.MemHit    // memory scan results (CE-style)
	packets   []model.Packet     // ring buffer of raw packets (for PCAP export)
	maxPkts   int                // cap on retained packets (0 = none retained)
	keylog    []string           // NSS key-log lines (TLS secrets) for decryption
	keylogSet map[string]struct{}
	recent    []model.Event // ring buffer of recent events
	recentCap int

	seq   atomic.Uint64
	txSeq atomic.Uint64
	wsSeq atomic.Uint64
	// Lock order for durable history operations: persistMu -> historyMu -> mu.
	// A history writer keeps its read lock through disk commit and publication.
	historyMu         sync.RWMutex
	persistMu         sync.Mutex
	persist           *persister
	historyGeneration uint64
	subsMu            sync.RWMutex
	subs              map[chan model.Event]struct{}
}

// New returns an empty store keeping up to recentCap recent events.
func New(recentCap int) *Store {
	if recentCap <= 0 {
		recentCap = 1000
	}
	return &Store{
		captures:  make(map[string]*model.Capture),
		flows:     make(map[string]*model.Flow),
		subs:      make(map[chan model.Event]struct{}),
		maxFlows:  recentCap * 4,
		maxPkts:   50000,
		keylogSet: make(map[string]struct{}),
		recentCap: recentCap,
	}
}

func advanceCounter(counter *atomic.Uint64, value uint64) {
	for old := counter.Load(); value > old; old = counter.Load() {
		if counter.CompareAndSwap(old, value) {
			return
		}
	}
}

// AddKeylogLine records one NSS Key Log line (e.g. "CLIENT_RANDOM <hex> <hex>"
// or a TLS 1.3 traffic-secret line). Duplicates are ignored. These secrets let
// captured TLS flows be decrypted (here or in Wireshark) without a MITM proxy.
func (s *Store) AddKeylogLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keylogSet[line]; ok {
		return false
	}
	s.keylogSet[line] = struct{}{}
	s.keylog = append(s.keylog, line)
	return true
}

// Keylog returns all recorded NSS key-log lines (an SSLKEYLOGFILE body).
func (s *Store) Keylog() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.keylog))
	copy(out, s.keylog)
	return out
}

// SetMaxPackets overrides how many raw packets are retained for PCAP export
// (0 disables retention).
func (s *Store) SetMaxPackets(n int) {
	s.mu.Lock()
	s.maxPkts = n
	s.mu.Unlock()
}

// AddPacket retains a captured packet (with raw bytes) in a bounded ring for
// later PCAP/PCAPNG export. The packet's Raw slice is copied so the caller may
// reuse its buffer.
func (s *Store) AddPacket(p model.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxPkts <= 0 {
		return
	}
	if len(p.Raw) > 0 {
		p.Raw = append([]byte(nil), p.Raw...)
	}
	s.packets = append(s.packets, p)
	if len(s.packets) > s.maxPkts {
		s.packets = s.packets[len(s.packets)-s.maxPkts:]
	}
}

// ListPackets returns retained packets, optionally filtered to a capture id
// (empty = all), as copies safe to hand to a PCAP writer.
func (s *Store) ListPackets(captureID string) []model.Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Packet, 0, len(s.packets))
	for _, p := range s.packets {
		if captureID != "" && p.CaptureID != captureID {
			continue
		}
		out = append(out, p)
	}
	return out
}

// SetCaptureLinkType records the libpcap link type observed for a capture so
// exported PCAP files declare the correct DLT.
func (s *Store) SetCaptureLinkType(id string, lt int) {
	s.mu.Lock()
	if c, ok := s.captures[id]; ok {
		c.LinkType = lt
	}
	s.mu.Unlock()
}

// SetMaxFlows overrides the cap on the number of tracked flows (0 = unbounded).
// When exceeded, the least-recently-updated flows are evicted.
func (s *Store) SetMaxFlows(n int) {
	s.mu.Lock()
	s.maxFlows = n
	s.mu.Unlock()
}

// Publish stamps an event with a monotonic id + timestamp, records it, and
// fans it out to all subscribers. Returns the stamped event.
func (s *Store) Publish(ev model.Event) model.Event {
	ev.ID = s.seq.Add(1)
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}

	s.mu.Lock()
	ev.HistoryGeneration = s.historyGeneration
	s.recent = append(s.recent, ev)
	if len(s.recent) > s.recentCap {
		s.recent = s.recent[len(s.recent)-s.recentCap:]
	}
	s.mu.Unlock()

	// Closing a subscriber must wait until all non-blocking sends finish.
	s.subsMu.RLock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // drop for slow consumers; never block the producer
		}
	}
	s.subsMu.RUnlock()
	return ev
}

// Subscribe returns a channel of future events plus an unsubscribe func.
func (s *Store) Subscribe(buf int) (<-chan model.Event, func()) {
	if buf <= 0 {
		buf = 256
	}
	ch := make(chan model.Event, buf)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch, func() {
		s.subsMu.Lock()
		defer s.subsMu.Unlock()
		if _, ok := s.subs[ch]; !ok {
			return
		}
		delete(s.subs, ch)
		close(ch)
	}
}

// Recent returns a copy of the recent-events ring buffer.
func (s *Store) Recent() []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Event, len(s.recent))
	copy(out, s.recent)
	return out
}

// HistoryCounts is a compact summary of retained capture history.
type HistoryCounts struct {
	Generation uint64 `json:"generation"`
	HTTP       int    `json:"http"`
	WS         int    `json:"ws"`
	Flows      int    `json:"flows"`
	Packets    int    `json:"packets"`
	Events     int    `json:"events"`
}

// ClearHistory drops captured traffic history while keeping runtime
// configuration such as proxy state, scope, CA, sessions, rules, and key logs.
func (s *Store) ClearHistory() HistoryCounts {
	counts, err := s.clearHistory(false)
	if err != nil {
		log.Printf("capx: clear history failed: %v", err)
	}
	return counts
}

// ClearHistoryAndNotify atomically clears disk and memory history, then emits
// its event before new HTTP/WS transactions can be published. API callers get
// an error rather than acknowledging a failed disk deletion or snapshot flush.
func (s *Store) ClearHistoryAndNotify() (HistoryCounts, error) {
	return s.clearHistory(true)
}

func (s *Store) clearHistory(notify bool) (HistoryCounts, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	s.mu.Lock()
	counts := HistoryCounts{
		HTTP:    len(s.httpTxs),
		WS:      len(s.wsMsgs),
		Flows:   len(s.flows),
		Packets: len(s.packets),
		Events:  len(s.recent),
	}
	generation := s.historyGeneration + 1
	counts.Generation = generation
	if s.httpDisk != nil {
		eventHighwater := s.seq.Load()
		if notify {
			eventHighwater++
		} // reserve the history_cleared event too
		count, err := s.httpDisk.Clear(s.txSeq.Load(), s.wsSeq.Load(), eventHighwater, generation)
		if err != nil {
			s.mu.Unlock()
			return HistoryCounts{}, err
		}
		counts.HTTP = count
	}
	s.clearTrafficLocked()
	s.historyGeneration = generation
	p := s.persist
	s.mu.Unlock()
	if notify {
		s.Publish(model.Event{Source: model.SourceProxy, Kind: "history_cleared", Data: counts})
	}
	if p != nil {
		if err := p.flushLocked(); err != nil {
			return counts, err
		}
	}
	return counts, nil
}

func (s *Store) clearTrafficLocked() {
	s.httpTxs = nil
	s.wsMsgs = nil
	s.flows = make(map[string]*model.Flow)
	s.packets = nil
	s.recent = nil
	// IDs are never reused: details, events and stored references may outlive a clear.
}

// PutCapture stores/updates a capture descriptor.
func (s *Store) PutCapture(c *model.Capture) {
	if c == nil {
		return
	}
	cc := *c
	s.mu.Lock()
	s.captures[c.ID] = &cc
	s.mu.Unlock()
}

// MarkCaptureStopped flags a capture as finished without dropping other
// fields (notably LinkType, which the sniffer writes after OpenLive).
func (s *Store) MarkCaptureStopped(id string, stopped time.Time) {
	s.mu.Lock()
	if c, ok := s.captures[id]; ok && c != nil {
		c.Running = false
		t := stopped
		c.Stopped = &t
	}
	s.mu.Unlock()
}

// GetCapture returns a capture by id.
func (s *Store) GetCapture(id string) (*model.Capture, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.captures[id]
	if !ok || c == nil {
		return nil, false
	}
	cc := *c
	return &cc, true
}

// ListCaptures returns all capture descriptors.
func (s *Store) ListCaptures() []*model.Capture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Capture, 0, len(s.captures))
	for _, c := range s.captures {
		if c == nil {
			continue
		}
		cc := *c
		out = append(out, &cc)
	}
	return out
}

// CaptureLinkTypeForExport picks a single libpcap DLT for a packet dump.
// When captureID is set, that session's type is used. When dumping mixed
// sessions, only a unanimous non-zero DLT is trusted; otherwise Ethernet is
// the conservative default so Wireshark does not mis-parse frames.
func (s *Store) CaptureLinkTypeForExport(captureID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if captureID != "" {
		if c, ok := s.captures[captureID]; ok && c != nil && c.LinkType != 0 {
			return c.LinkType
		}
		return 0
	}
	seen := 0
	for _, c := range s.captures {
		if c == nil || c.LinkType == 0 {
			continue
		}
		if seen == 0 {
			seen = c.LinkType
			continue
		}
		if c.LinkType != seen {
			return 0
		}
	}
	return seen
}

// UpsertFlow inserts or replaces a flow. It stores a copy so the caller cannot
// later mutate the stored value (which would race with concurrent readers).
func (s *Store) UpsertFlow(f *model.Flow) {
	s.mu.Lock()
	s.flows[f.ID] = copyFlow(f)
	s.evictFlowsLocked()
	s.mu.Unlock()
}

// EnsureFlow inserts a copy of f if no flow with its id exists yet, evicting the
// least-recently-updated flows if the cap is exceeded. It reports whether the
// flow was newly created.
func (s *Store) EnsureFlow(f *model.Flow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.flows[f.ID]; ok {
		return false
	}
	s.flows[f.ID] = copyFlow(f)
	s.evictFlowsLocked()
	return true
}

// AddFlowPacket records one packet against a flow's counters under the store
// lock (so it never races with API readers). No-op if the flow is unknown.
func (s *Store) AddFlowPacket(id string, byteLen int, ts time.Time) {
	s.mu.Lock()
	if f, ok := s.flows[id]; ok {
		f.Packets++
		f.Bytes += uint64(byteLen)
		f.Updated = ts
	}
	s.mu.Unlock()
}

// AppendFlowPayload appends reassembled application-layer bytes to a flow's
// client or server buffer (dir "client"|"server"), capped at capN bytes. It
// reports whether the flow existed. Runs under the store lock so it never
// races with API readers that snapshot the flow.
func (s *Store) AppendFlowPayload(id, dir string, data []byte, capN int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flows[id]
	if !ok {
		return false
	}
	if dir == "server" {
		f.ServerPayload = appendCappedBytes(f.ServerPayload, data, capN)
	} else {
		f.ClientPayload = appendCappedBytes(f.ClientPayload, data, capN)
	}
	f.Updated = time.Now().UTC()
	return true
}

// MarkFlowClosed flags a flow as closed (e.g. on TCP teardown).
func (s *Store) MarkFlowClosed(id string) {
	s.mu.Lock()
	if f, ok := s.flows[id]; ok {
		f.Closed = true
		f.Updated = time.Now().UTC()
	}
	s.mu.Unlock()
}

// GetFlowByID returns a copy of a flow by its id.
func (s *Store) GetFlowByID(id string) (*model.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.flows[id]
	if !ok {
		return nil, false
	}
	return copyFlow(f), true
}

// ListFlows returns copies of all known flows.
func (s *Store) ListFlows() []*model.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	merged := make(map[string]*model.Flow, len(s.flows))
	for _, f := range s.flows {
		addCanonicalFlow(merged, f)
	}
	out := make([]*model.Flow, 0, len(merged))
	for _, f := range merged {
		out = append(out, f)
	}
	return out
}

// evictFlowsLocked drops the least-recently-updated flows when the map exceeds
// maxFlows, trimming down to ~90% so eviction is amortized. Caller holds s.mu.
func (s *Store) evictFlowsLocked() {
	if s.maxFlows <= 0 || len(s.flows) <= s.maxFlows {
		return
	}
	target := s.maxFlows - s.maxFlows/10
	if target < 1 {
		target = 1
	}
	type fa struct {
		id string
		ts time.Time
	}
	ages := make([]fa, 0, len(s.flows))
	for id, f := range s.flows {
		ts := f.Updated
		if ts.IsZero() {
			ts = f.Started
		}
		ages = append(ages, fa{id, ts})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].ts.Before(ages[j].ts) })
	for i := 0; i < len(ages) && len(s.flows) > target; i++ {
		delete(s.flows, ages[i].id)
	}
}

// copyFlow returns a deep-ish copy of f: the struct plus its payload slices, so
// a returned snapshot is immune to later in-place appends.
func copyFlow(f *model.Flow) *model.Flow {
	fc := *f
	if len(f.ClientPayload) > 0 {
		fc.ClientPayload = append([]byte(nil), f.ClientPayload...)
	}
	if len(f.ServerPayload) > 0 {
		fc.ServerPayload = append([]byte(nil), f.ServerPayload...)
	}
	return &fc
}

func canCanonicalizeFlow(f *model.Flow) bool {
	return f != nil && (f.SrcIP != "" || f.SrcPort != 0) && (f.DstIP != "" || f.DstPort != 0)
}

func canonicalizeFlowCopy(f *model.Flow) *model.Flow {
	if f == nil {
		return nil
	}
	fc := copyFlow(f)
	if !canCanonicalizeFlow(fc) {
		return fc
	}
	id, reversed := model.CanonicalFlowIDStringPorts(fc.L4, fc.SrcIP, strconv.FormatUint(uint64(fc.SrcPort), 10), fc.DstIP, strconv.FormatUint(uint64(fc.DstPort), 10))
	fc.ID = id
	if reversed {
		fc.SrcIP, fc.DstIP = fc.DstIP, fc.SrcIP
		fc.SrcPort, fc.DstPort = fc.DstPort, fc.SrcPort
		fc.ClientPayload, fc.ServerPayload = fc.ServerPayload, fc.ClientPayload
	}
	return fc
}

func mergeFlowCopies(dst, src *model.Flow) *model.Flow {
	if dst == nil {
		return src
	}
	if src == nil {
		return dst
	}
	dst.Bytes += src.Bytes
	dst.Packets += src.Packets
	if dst.Started.IsZero() || (!src.Started.IsZero() && src.Started.Before(dst.Started)) {
		dst.Started = src.Started
	}
	if src.Updated.After(dst.Updated) {
		dst.Updated = src.Updated
	}
	dst.Closed = dst.Closed || src.Closed
	if len(src.ClientPayload) > 0 {
		dst.ClientPayload = append(dst.ClientPayload, src.ClientPayload...)
	}
	if len(src.ServerPayload) > 0 {
		dst.ServerPayload = append(dst.ServerPayload, src.ServerPayload...)
	}
	return dst
}

func addCanonicalFlow(dst map[string]*model.Flow, f *model.Flow) {
	if f == nil {
		return
	}
	cf := canonicalizeFlowCopy(f)
	if cf == nil {
		return
	}
	if cur, ok := dst[cf.ID]; ok {
		dst[cf.ID] = mergeFlowCopies(cur, cf)
		return
	}
	dst[cf.ID] = cf
}

func appendCappedBytes(dst, src []byte, capN int) []byte {
	if capN > 0 {
		remaining := capN - len(dst)
		if remaining <= 0 {
			return dst
		}
		if len(src) > remaining {
			src = src[:remaining]
		}
	}
	return append(dst, src...)
}

// AddHTTPTx records an L7 HTTP/HTTPS transaction (assigning it an id) and
// publishes an "http_tx" event. Used by the MITM proxy (M4).
func (s *Store) AddHTTPTx(tx *model.HTTPTx) *model.HTTPTx {
	if tx == nil {
		return nil
	}
	s.historyMu.RLock()
	defer s.historyMu.RUnlock()
	tx = cloneHTTPTx(tx)
	if tx.TS.IsZero() {
		tx.TS = time.Now().UTC()
	}
	if tx.LastSeen.IsZero() {
		tx.LastSeen = tx.TS
	}
	// Every exchange is evidence, even if its URL and body repeat. Grouping is
	// presentation-only; Cookie/Authorization/Set-Cookie must never be discarded.
	tx.RepeatCnt = 1
	tx.InScope = !tx.OutOfScope
	tx.ReqRawLen, tx.RespRawLen = len(tx.ReqRaw), len(tx.RespRaw)
	tx.ID = s.txSeq.Add(1)
	s.mu.Lock()
	s.httpTxs = append(s.httpTxs, tx)
	if len(s.httpTxs) > s.recentCap {
		s.httpTxs = s.httpTxs[len(s.httpTxs)-s.recentCap:]
	}
	d := s.httpDisk
	s.mu.Unlock()
	if d != nil {
		if err := d.Upsert(tx); err != nil {
			log.Printf("capx: HTTP history write failed: %v", err)
		}
	}
	evTx := cloneHTTPTx(tx)
	evTx.ReqRaw, evTx.RespRaw = "", ""
	s.Publish(model.Event{Source: model.SourceProxy, Kind: "http_tx", CorrID: tx.FlowID, Data: evTx})
	return cloneHTTPTx(tx)
}

func cloneHTTPTx(tx *model.HTTPTx) *model.HTTPTx {
	if tx == nil {
		return nil
	}
	cp := *tx
	cp.ReqHdr = cloneHeaders(tx.ReqHdr)
	cp.RespHdr = cloneHeaders(tx.RespHdr)
	return &cp
}

func cloneHeaders(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// HTTPFilter narrows the HTTP history returned by FilterHTTPTx. Every field is
// optional; a zero value matches everything. All string matching is
// case-insensitive.
type HTTPFilter struct {
	Scheme string // exact "http" | "https"
	Host   string // substring of Host
	Method string // comma-separated list, e.g. "GET,POST" (membership)
	MIME   string // substring of MIME
	Status string // "200" | "2xx" | "200-299" (see statusMatches)
	Query  string // substring matched against URL + raw request/response
	Scope  string // "" or "all" = everything; "in" = in-scope only; "out" = out-of-scope only
}

// ListHTTPTx returns HTTP transactions, optionally filtered by scheme
// ("http" or "https"); an empty scheme returns all.
func (s *Store) ListHTTPTx(scheme string) []*model.HTTPTx {
	return s.FilterHTTPTx(HTTPFilter{Scheme: scheme})
}

// SnapshotHTTPTx returns value copies of the in-memory HTTP history. It is
// intended for background automation that compares repeat counters and
// LastSeen timestamps while the proxy continues recording traffic.
func (s *Store) SnapshotHTTPTx() []*model.HTTPTx {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.HTTPTx, 0, len(s.httpTxs))
	for _, tx := range s.httpTxs {
		if tx == nil {
			continue
		}
		copy := *tx
		copy.ReqHdr = nil
		copy.RespHdr = nil
		copy.ReqRaw = ""
		copy.RespRaw = ""
		out = append(out, &copy)
	}
	return out
}

// FilterHTTPTx returns the captured HTTP transactions matching f, in capture
// order.
func (s *Store) FilterHTTPTx(f HTTPFilter) []*model.HTTPTx {
	host := strings.ToLower(f.Host)
	mime := strings.ToLower(f.MIME)
	query := strings.ToLower(f.Query)
	methods := splitCSVLower(f.Method)

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.HTTPTx, 0, len(s.httpTxs))
	for _, tx := range s.httpTxs {
		if f.Scheme != "" && !strings.EqualFold(tx.Scheme, f.Scheme) {
			continue
		}
		if host != "" && !strings.Contains(strings.ToLower(tx.Host), host) {
			continue
		}
		if len(methods) > 0 && !methods[strings.ToLower(tx.Method)] {
			continue
		}
		if mime != "" && !strings.Contains(strings.ToLower(tx.MIME), mime) {
			continue
		}
		if !statusMatches(tx.Status, f.Status) {
			continue
		}
		if query != "" && !httpTxContains(tx, query) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(f.Scope)) {
		case "in":
			if tx.OutOfScope {
				continue
			}
		case "out":
			if !tx.OutOfScope {
				continue
			}
		}
		out = append(out, cloneHTTPTx(tx))
	}
	return out
}

// httpTxContains reports whether the lowercased needle appears in the tx URL or
// its raw request/response text (i.e. headers + body).
func httpTxContains(tx *model.HTTPTx, needle string) bool {
	return strings.Contains(strings.ToLower(tx.URL), needle) ||
		strings.Contains(strings.ToLower(tx.Host), needle) ||
		strings.Contains(strings.ToLower(tx.Path), needle) ||
		strings.Contains(strings.ToLower(tx.Method), needle) ||
		strings.Contains(strings.ToLower(tx.MIME), needle) ||
		strings.Contains(strconv.Itoa(tx.Status), needle) ||
		strings.Contains(strings.ToLower(tx.ReqRaw), needle) ||
		strings.Contains(strings.ToLower(tx.RespRaw), needle)
}

// statusMatches reports whether code satisfies spec. spec may be empty (any),
// an exact code ("404"), a class ("4xx" / "4XX"), or an inclusive range
// ("400-499"). An unparseable spec matches nothing.
func statusMatches(code int, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		return err1 == nil && err2 == nil && code >= l && code <= h
	}
	if len(spec) == 3 && (spec[1] == 'x' || spec[1] == 'X') && (spec[2] == 'x' || spec[2] == 'X') {
		if d := int(spec[0] - '0'); d >= 1 && d <= 9 {
			return code >= d*100 && code < (d+1)*100
		}
		return false
	}
	n, err := strconv.Atoi(spec)
	return err == nil && code == n
}

func splitCSVLower(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out[p] = true
		}
	}
	return out
}

// GetHTTPTx returns a captured HTTP transaction by its id.
func (s *Store) GetHTTPTx(id uint64) (*model.HTTPTx, bool) {
	s.mu.RLock()
	for _, tx := range s.httpTxs {
		if tx.ID == id {
			s.mu.RUnlock()
			return cloneHTTPTx(tx), true
		}
	}
	d := s.httpDisk
	s.mu.RUnlock()
	if d != nil {
		tx, err := d.Get(id)
		return tx, err == nil && tx != nil
	}
	return nil, false
}

// AddWSMessage records a WebSocket frame (assigning it an id) and publishes a
// "ws_msg" event. Used by the MITM proxy (M4).
func (s *Store) AddWSMessage(m *model.WSMessage) *model.WSMessage {
	s.historyMu.RLock()
	defer s.historyMu.RUnlock()
	m.ID = s.wsSeq.Add(1)
	if m.TS.IsZero() {
		m.TS = time.Now().UTC()
	}
	s.mu.Lock()
	s.wsMsgs = append(s.wsMsgs, m)
	if len(s.wsMsgs) > s.recentCap {
		s.wsMsgs = s.wsMsgs[len(s.wsMsgs)-s.recentCap:]
	}
	s.mu.Unlock()
	s.Publish(model.Event{Source: model.SourceProxy, Kind: "ws_msg", CorrID: m.FlowID, Data: m})
	return m
}

// WSFilter narrows WebSocket frames returned by FilterWS. Optional fields; a
// zero value matches everything. String matching is case-insensitive.
type WSFilter struct {
	URL    string // substring of the ws/wss endpoint
	Dir    string // exact "send" | "recv"
	Opcode string // exact "text" | "binary"
	Query  string // substring of the frame payload
}

// ListWS returns all captured WebSocket frames.
func (s *Store) ListWS() []*model.WSMessage {
	return s.FilterWS(WSFilter{})
}

// FilterWS returns the captured WebSocket frames matching f, in capture order.
func (s *Store) FilterWS(f WSFilter) []*model.WSMessage {
	url := strings.ToLower(f.URL)
	query := strings.ToLower(f.Query)
	dir := strings.ToLower(f.Dir)
	opcode := strings.ToLower(f.Opcode)

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.WSMessage, 0, len(s.wsMsgs))
	for _, m := range s.wsMsgs {
		if url != "" && !strings.Contains(strings.ToLower(m.URL), url) {
			continue
		}
		if dir != "" && strings.ToLower(string(m.Dir)) != dir {
			continue
		}
		if opcode != "" && strings.ToLower(m.Opcode) != opcode {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(m.Data), query) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// AddHookEvent records an in-process hook observation (Frida) and publishes a
// "hook_tls" event. Used by the hook engine (M5).
func (s *Store) AddHookEvent(h *model.HookEvent) *model.HookEvent {
	if h.TS.IsZero() {
		h.TS = time.Now().UTC()
	}
	s.mu.Lock()
	s.hookEvts = append(s.hookEvts, h)
	if len(s.hookEvts) > s.recentCap {
		s.hookEvts = s.hookEvts[len(s.hookEvts)-s.recentCap:]
	}
	s.mu.Unlock()
	s.Publish(model.Event{Source: model.SourceHook, Kind: "hook_tls", Data: h})
	return h
}

// ListHookEvents returns all recorded hook observations.
func (s *Store) ListHookEvents() []*model.HookEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.HookEvent, 0, len(s.hookEvts))
	out = append(out, s.hookEvts...)
	return out
}

// AddMemHit records a memory scan result and publishes a "mem_hit" event.
func (s *Store) AddMemHit(h *model.MemHit) *model.MemHit {
	s.mu.Lock()
	s.memHits = append(s.memHits, h)
	if len(s.memHits) > s.recentCap {
		s.memHits = s.memHits[len(s.memHits)-s.recentCap:]
	}
	s.mu.Unlock()
	corr := fmt.Sprintf("pid:%d", h.PID)
	if h.HTTPID != 0 {
		corr = fmt.Sprintf("http:%d", h.HTTPID)
	}
	s.Publish(model.Event{
		Source: model.SourceMem,
		Kind:   "mem_hit",
		CorrID: corr,
		Data:   h,
	})
	return h
}

// ListMemHits returns all recorded memory scan results.
func (s *Store) ListMemHits() []*model.MemHit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.MemHit, 0, len(s.memHits))
	out = append(out, s.memHits...)
	return out
}
