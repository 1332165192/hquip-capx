package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
)

// PersistConfig controls how the store persists its state to disk.
type PersistConfig struct {
	Dir      string        // directory for state files; empty = no persistence
	Interval time.Duration // flush interval; 0 = default 10s
}

// snapshot is the on-disk representation of the store state.
type snapshot struct {
	Version           int                `json:"version,omitempty"`
	HistoryGeneration uint64             `json:"history_generation,omitempty"`
	EventSequence     uint64             `json:"event_sequence,omitempty"`
	HTTPSequence      uint64             `json:"http_sequence,omitempty"`
	WSSequence        uint64             `json:"ws_sequence,omitempty"`
	Captures          []*model.Capture   `json:"captures,omitempty"`
	Packets           []model.Packet     `json:"packets,omitempty"`
	Keylog            []string           `json:"keylog,omitempty"`
	Flows             []*model.Flow      `json:"flows,omitempty"`
	HTTPTxs           []*model.HTTPTx    `json:"http_txs,omitempty"`
	WSMsgs            []*model.WSMessage `json:"ws_msgs,omitempty"`
	HookEvts          []*model.HookEvent `json:"hook_evts,omitempty"`
	MemHits           []*model.MemHit    `json:"mem_hits,omitempty"`
	Events            []model.Event      `json:"events,omitempty"`
}

// persister handles periodic flushing of store state to disk.
type persister struct {
	st  *Store
	dir string

	mu      sync.Mutex
	stop    chan struct{}
	done    chan struct{}
	stopped bool
}

// EnablePersistence starts a background goroutine that periodically writes
// the store state to dir. Call the returned function to stop and flush.
func (s *Store) EnablePersistence(cfg PersistConfig) (stop func(), err error) {
	if cfg.Dir == "" {
		return func() {}, nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	alreadyEnabled := s.persist != nil
	s.mu.RUnlock()
	if alreadyEnabled {
		return nil, fmt.Errorf("persist: already enabled")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("persist: mkdir %s: %w", cfg.Dir, err)
	}
	interval := cfg.Interval
	if interval == 0 {
		interval = 10 * time.Second
	}

	p := &persister{st: s, dir: cfg.Dir, stop: make(chan struct{}), done: make(chan struct{})}

	// Load existing state on startup.
	if err := p.load(); err != nil {
		// Never overwrite unreadable evidence with a fresh empty snapshot.
		return nil, err
	}
	s.mu.Lock()
	s.persist = p
	s.mu.Unlock()
	go p.run(interval)
	return p.shutdown, nil
}

func (p *persister) run(interval time.Duration) {
	defer close(p.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			if err := p.flush(); err != nil {
				log.Printf("capx: final state save failed: %v", err)
			}
			return
		case <-ticker.C:
			if err := p.flush(); err != nil {
				log.Printf("capx: state save failed: %v", err)
			}
		}
	}
}

func (p *persister) shutdown() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		<-p.done
		return
	}
	p.stopped = true
	close(p.stop)
	p.mu.Unlock()
	<-p.done // wait for final flush
	p.st.persistMu.Lock()
	p.st.mu.Lock()
	if p.st.persist == p {
		p.st.persist = nil
	}
	p.st.mu.Unlock()
	p.st.persistMu.Unlock()
}

func (p *persister) stateFile() string { return filepath.Join(p.dir, "capx_state.json") }

func (p *persister) flush() error {
	p.st.persistMu.Lock()
	defer p.st.persistMu.Unlock()
	return p.flushLocked()
}

// flushLocked is also used by ClearHistory while it holds persistMu, so a
// periodic write of an older snapshot can never resurrect cleared history.
func (p *persister) flushLocked() error {
	snap := p.st.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("persist: marshal: %w", err)
	}
	tmp := p.stateFile() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("persist: open tmp: %w", err)
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("persist: write tmp: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("persist: close tmp: %w", closeErr)
	}
	if err := os.Rename(tmp, p.stateFile()); err != nil {
		return fmt.Errorf("persist: rename: %w", err)
	}
	return nil
}

func (p *persister) load() error {
	data, err := os.ReadFile(p.stateFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no prior state
		}
		return fmt.Errorf("persist: read: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("persist: unmarshal: %w", err)
	}
	p.st.Restore(snap)
	return nil
}

// Snapshot returns a serializable copy of the store's current state.
func (s *Store) Snapshot() snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	merged := make(map[string]*model.Flow, len(s.flows))
	for _, f := range s.flows {
		addCanonicalFlow(merged, f)
	}
	flows := make([]*model.Flow, 0, len(merged))
	for _, f := range merged {
		flows = append(flows, f)
	}
	txs := make([]*model.HTTPTx, len(s.httpTxs))
	for i, tx := range s.httpTxs {
		txs[i] = cloneHTTPTx(tx)
	}
	wss := make([]*model.WSMessage, len(s.wsMsgs))
	copy(wss, s.wsMsgs)
	hooks := make([]*model.HookEvent, len(s.hookEvts))
	copy(hooks, s.hookEvts)
	mems := make([]*model.MemHit, len(s.memHits))
	copy(mems, s.memHits)
	evts := make([]model.Event, len(s.recent))
	copy(evts, s.recent)
	captures := make([]*model.Capture, 0, len(s.captures))
	for _, c := range s.captures {
		if c != nil {
			cp := *c
			captures = append(captures, &cp)
		}
	}
	packets := make([]model.Packet, len(s.packets))
	for i, p := range s.packets {
		packets[i] = p
		packets[i].Raw = append([]byte(nil), p.Raw...)
	}

	return snapshot{
		Version:           2,
		HistoryGeneration: s.historyGeneration,
		EventSequence:     s.seq.Load(), HTTPSequence: s.txSeq.Load(), WSSequence: s.wsSeq.Load(),
		Captures: captures, Packets: packets, Keylog: append([]string(nil), s.keylog...),
		Flows:    flows,
		HTTPTxs:  txs,
		WSMsgs:   wss,
		HookEvts: hooks,
		MemHits:  mems,
		Events:   evts,
	}
}

// Restore loads a snapshot into the store, merging with any existing state.
func (s *Store) Restore(snap snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Clearing traffic does not clear TLS secrets or capture descriptors. Restore
	// these even if SQLite proves the traffic part of this snapshot is stale.
	for _, line := range snap.Keylog {
		if _, exists := s.keylogSet[line]; !exists {
			s.keylogSet[line] = struct{}{}
			s.keylog = append(s.keylog, line)
		}
	}
	advanceCounter(&s.seq, snap.EventSequence)
	advanceCounter(&s.txSeq, snap.HTTPSequence)
	advanceCounter(&s.wsSeq, snap.WSSequence)
	for _, c := range snap.Captures {
		if c == nil {
			continue
		}
		cp := *c
		// A saved descriptor is history, not a resurrected live sniffer.
		if cp.Running {
			cp.Running = false
			stopped := time.Now().UTC()
			cp.Stopped = &stopped
		}
		if _, exists := s.captures[cp.ID]; !exists {
			s.captures[cp.ID] = &cp
		}
	}
	if snap.HistoryGeneration < s.historyGeneration {
		return
	}
	s.historyGeneration = snap.HistoryGeneration
	for _, p := range snap.Packets {
		p.Raw = append([]byte(nil), p.Raw...)
		s.packets = append(s.packets, p)
	}
	if s.maxPkts <= 0 {
		s.packets = nil
	} else if len(s.packets) > s.maxPkts {
		s.packets = s.packets[len(s.packets)-s.maxPkts:]
	}

	merged := make(map[string]*model.Flow, len(s.flows)+len(snap.Flows))
	for _, f := range s.flows {
		addCanonicalFlow(merged, f)
	}
	for _, f := range snap.Flows {
		addCanonicalFlow(merged, f)
	}
	s.flows = merged
	httpIDs := make(map[uint64]bool, len(s.httpTxs))
	for _, tx := range s.httpTxs {
		if tx != nil {
			httpIDs[tx.ID] = true
		}
	}
	for _, tx := range snap.HTTPTxs {
		if tx == nil || httpIDs[tx.ID] {
			continue
		}
		s.httpTxs = append(s.httpTxs, cloneHTTPTx(tx))
		httpIDs[tx.ID] = true
	}
	if len(s.httpTxs) > s.recentCap {
		s.httpTxs = s.httpTxs[len(s.httpTxs)-s.recentCap:]
	}
	wsIDs := make(map[uint64]bool, len(s.wsMsgs))
	for _, ws := range s.wsMsgs {
		if ws != nil {
			wsIDs[ws.ID] = true
		}
	}
	for _, ws := range snap.WSMsgs {
		if ws == nil || wsIDs[ws.ID] {
			continue
		}
		cp := *ws
		s.wsMsgs = append(s.wsMsgs, &cp)
		wsIDs[ws.ID] = true
	}
	if len(s.wsMsgs) > s.recentCap {
		s.wsMsgs = s.wsMsgs[len(s.wsMsgs)-s.recentCap:]
	}
	s.hookEvts = append(s.hookEvts, snap.HookEvts...)
	if len(s.hookEvts) > s.recentCap {
		s.hookEvts = s.hookEvts[len(s.hookEvts)-s.recentCap:]
	}
	s.memHits = append(s.memHits, snap.MemHits...)
	if len(s.memHits) > s.recentCap {
		s.memHits = s.memHits[len(s.memHits)-s.recentCap:]
	}
	s.recent = append(s.recent, snap.Events...)
	if len(s.recent) > s.recentCap {
		s.recent = s.recent[len(s.recent)-s.recentCap:]
	}
	for _, ev := range snap.Events {
		advanceCounter(&s.seq, ev.ID)
	}
	advanceCounter(&s.seq, snap.EventSequence)
	advanceCounter(&s.txSeq, snap.HTTPSequence)
	advanceCounter(&s.wsSeq, snap.WSSequence)

	// Restore the txSeq/wsSeq counters so new IDs don't collide.
	for _, tx := range s.httpTxs {
		if tx != nil {
			advanceCounter(&s.txSeq, tx.ID)
		}
	}
	for _, ws := range s.wsMsgs {
		if ws != nil {
			advanceCounter(&s.wsSeq, ws.ID)
		}
	}
}
