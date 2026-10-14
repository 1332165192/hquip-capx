package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

// HeldRequest is a message (request, response or WebSocket frame) paused by the
// interceptor awaiting a user decision. Kind is "request", "response" or "ws";
// for responses the Raw holds the full status line + headers + body, and for
// WebSocket frames it holds the (text or base64 binary) payload to edit.
type HeldRequest struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"` // "request" | "response" | "ws"
	TS     time.Time `json:"ts"`
	Scheme string    `json:"scheme"`
	Host   string    `json:"host"`
	Raw    string    `json:"raw"`

	// WebSocket-only fields (set when Kind == "ws").
	ConnID string `json:"conn_id,omitempty"`
	Dir    string `json:"dir,omitempty"`    // "send" (client->server) | "recv"
	Opcode string `json:"opcode,omitempty"` // "text" | "binary"
	URL    string `json:"url,omitempty"`

	decided chan decision
}

type decision struct {
	edited string
	drop   bool
}

// intercept is the in-memory hold queue for request interception.
type intercept struct {
	st  *store.Store
	mu  sync.Mutex
	seq int
	q   map[string]*HeldRequest
	ord []string
}

func newIntercept() *intercept {
	return &intercept{q: map[string]*HeldRequest{}}
}

func (ic *intercept) bind(st *store.Store) { ic.st = st }

// hold registers a paused request/response and blocks until a decision is
// posted (or a safety timeout auto-forwards it). Returns the possibly-edited
// raw and a drop flag.
func (ic *intercept) hold(kind, scheme, host, raw string) (string, bool) {
	return ic.holdContext(context.Background(), kind, scheme, host, raw)
}

func (ic *intercept) holdContext(ctx context.Context, kind, scheme, host, raw string) (string, bool) {
	return ic.holdMsgContext(ctx, &HeldRequest{Kind: kind, Scheme: scheme, Host: host, Raw: raw})
}

// holdMsg registers an arbitrary held message (the caller fills in Kind and any
// kind-specific fields) and blocks until decided or the safety timeout fires.
func (ic *intercept) holdMsg(h *HeldRequest) (string, bool) {
	return ic.holdMsgContext(context.Background(), h)
}

func (ic *intercept) holdMsgContext(ctx context.Context, h *HeldRequest) (string, bool) {
	ic.mu.Lock()
	ic.seq++
	h.ID = fmt.Sprintf("icpt-%d", ic.seq)
	h.TS = time.Now().UTC()
	h.decided = make(chan decision, 1)
	ic.q[h.ID] = h
	ic.ord = append(ic.ord, h.ID)
	ic.mu.Unlock()

	if ic.st != nil {
		ic.st.Publish(model.Event{Source: model.SourceProxy, Kind: "intercept_hold", Data: h})
	}

	select {
	case <-ctx.Done():
		ic.remove(h.ID)
		return "", true
	case d := <-h.decided:
		return d.edited, d.drop
	case <-time.After(5 * time.Minute):
		ic.remove(h.ID)
		return "", false
	}
}

// Decide resolves a held request by id (forward with optional edited raw, or drop).
func (ic *intercept) Decide(id, edited string, drop bool) bool {
	ic.mu.Lock()
	h, ok := ic.q[id]
	ic.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case h.decided <- decision{edited: edited, drop: drop}:
	default:
	}
	ic.remove(id)
	return true
}

func (ic *intercept) remove(id string) {
	ic.mu.Lock()
	delete(ic.q, id)
	for i, x := range ic.ord {
		if x == id {
			ic.ord = append(ic.ord[:i], ic.ord[i+1:]...)
			break
		}
	}
	ic.mu.Unlock()
}

// Queue returns the currently held requests in arrival order.
func (ic *intercept) Queue() []*HeldRequest {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	out := make([]*HeldRequest, 0, len(ic.ord))
	for _, id := range ic.ord {
		if h, ok := ic.q[id]; ok {
			out = append(out, h)
		}
	}
	return out
}
