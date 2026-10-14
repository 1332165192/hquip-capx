package correlate

import (
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

func ts(sec int) time.Time { return time.Unix(int64(sec), 0).UTC() }

// A flow, an HTTP tx on that flow, and a hook event for the same host should
// all collapse into a single correlated session.
func TestCrossLayerJoin(t *testing.T) {
	in := Input{
		Flows: []*model.Flow{
			{ID: "f1", L4: model.TCP, SrcIP: "10.0.0.2", SrcPort: 51000, DstIP: "93.184.216.34", DstPort: 443, Started: ts(1)},
		},
		HTTP: []*model.HTTPTx{
			{ID: 1, FlowID: "f1", TS: ts(2), Scheme: "https", Method: "GET", Host: "example.com:443", URL: "https://example.com/", Status: 200},
		},
		Hooks: []*model.HookEvent{
			{PID: 4242, TS: ts(3), Func: "SSL_write", Dir: "send", Len: 80, Peer: "example.com:443"},
		},
	}
	groups := Build(in)
	if len(groups) != 1 {
		t.Fatalf("expected 1 correlated group, got %d: %+v", len(groups), groups)
	}
	g := groups[0]
	if len(g.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(g.Entries))
	}
	// entries must be time-ordered
	if !(g.Entries[0].TS.Before(g.Entries[1].TS) && g.Entries[1].TS.Before(g.Entries[2].TS)) {
		t.Fatal("entries not time-ordered")
	}
	if g.Started != ts(1) || g.Updated != ts(3) {
		t.Fatalf("span = %v..%v", g.Started, g.Updated)
	}
	if g.CorrID == "" {
		t.Fatal("missing corr id")
	}
}

// Unrelated activity (different host, different pid) stays in separate groups.
func TestSeparateGroups(t *testing.T) {
	in := Input{
		HTTP: []*model.HTTPTx{
			{ID: 1, TS: ts(1), Host: "a.com", URL: "http://a.com/", Status: 200},
			{ID: 2, TS: ts(2), Host: "b.com", URL: "http://b.com/", Status: 404},
		},
		Hooks: []*model.HookEvent{
			{PID: 1, TS: ts(3), Func: "SSL_read", Peer: "c.com:443", Len: 10},
		},
	}
	groups := Build(in)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
}

// Multiple requests on the same proxy connection (same FlowID) group together.
func TestSameFlowGrouped(t *testing.T) {
	in := Input{
		HTTP: []*model.HTTPTx{
			{ID: 1, FlowID: "c7", TS: ts(1), Host: "x.com", URL: "http://x.com/a", Status: 200},
			{ID: 2, FlowID: "c7", TS: ts(2), Host: "x.com", URL: "http://x.com/b", Status: 200},
		},
		WS: []*model.WSMessage{
			{ID: 1, FlowID: "c7", TS: ts(3), URL: "ws://x.com/sock", Dir: model.WSSend, Opcode: "text", Length: 5},
		},
	}
	groups := Build(in)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if len(groups[0].Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(groups[0].Entries))
	}
}

func TestEmpty(t *testing.T) {
	if g := Build(Input{}); len(g) != 0 {
		t.Fatalf("expected no groups, got %d", len(g))
	}
}

// MemHit for the same PID as a hook event should correlate into the same group.
func TestMemHitCorrelation(t *testing.T) {
	in := Input{
		Hooks: []*model.HookEvent{
			{PID: 1234, TS: ts(1), Func: "SSL_write", Dir: "send", Len: 100, Peer: "target.com:443"},
		},
		MemHits: []*model.MemHit{
			{PID: 1234, Addr: 0x7fff0010, Type: "i32", Value: "42"},
		},
	}
	groups := Build(in)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (pid-correlated), got %d", len(groups))
	}
	if len(groups[0].Entries) != 2 {
		t.Fatalf("expected 2 entries (hook + memhit), got %d", len(groups[0].Entries))
	}
}

// The full kill-chain: a memory hit (pid) -> TLS hook (pid + peer endpoint) ->
// L3/L4 flow (endpoint) -> HTTP tx (host + resolved server endpoint) should all
// collapse into ONE session, bridged purely by the shared endpoint ip:port.
func TestEndpointBridgeFullChain(t *testing.T) {
	ep := "93.184.216.34:443"
	in := Input{
		Flows: []*model.Flow{
			{ID: "f1", L4: model.TCP, SrcIP: "10.0.0.2", SrcPort: 51000, DstIP: "93.184.216.34", DstPort: 443, Started: ts(1)},
		},
		HTTP: []*model.HTTPTx{
			// Different host string + no shared FlowID; only ServerAddr bridges it.
			{ID: 1, TS: ts(2), Host: "example.com", URL: "https://example.com/", Status: 200, ServerAddr: ep},
		},
		Hooks: []*model.HookEvent{
			{PID: 4242, TS: ts(3), Func: "SSL_write", Dir: "send", Len: 80, Peer: ep},
		},
		MemHits: []*model.MemHit{
			{PID: 4242, Addr: 0x140000, Type: "i32", Value: "7"},
		},
	}
	groups := Build(in)
	if len(groups) != 1 {
		t.Fatalf("expected 1 fully-bridged group, got %d: %+v", len(groups), groups)
	}
	if len(groups[0].Entries) != 4 {
		t.Fatalf("expected 4 entries (flow+http+hook+mem), got %d", len(groups[0].Entries))
	}
}

func TestMemHitHTTPIDJoinsHTTP(t *testing.T) {
	in := Input{
		HTTP: []*model.HTTPTx{
			{ID: 9, TS: ts(1), Host: "api.example.com", URL: "https://api.example.com/login", Status: 200},
		},
		MemHits: []*model.MemHit{
			{PID: 7, Addr: 0xabc, Type: "http_link", Value: "https://api.example.com/login", TS: ts(2), HTTPID: 9, Host: "api.example.com"},
		},
	}
	groups := Build(in)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group joined by http id, got %d: %+v", len(groups), groups)
	}
	if len(groups[0].Entries) != 2 {
		t.Fatalf("expected http+mem entries, got %d", len(groups[0].Entries))
	}
}

// The stable corr id must be derived from the session's keys (stable across
// rebuilds), not its position.
func TestStableCorrID(t *testing.T) {
	in := Input{HTTP: []*model.HTTPTx{{ID: 1, TS: ts(1), Host: "a.com", URL: "http://a.com/", Status: 200}}}
	g1 := Build(in)
	g2 := Build(in)
	if g1[0].CorrID != g2[0].CorrID {
		t.Fatalf("corr id not stable: %s vs %s", g1[0].CorrID, g2[0].CorrID)
	}
}

func TestHelpers(t *testing.T) {
	if hostOnly("example.com:443") != "example.com" {
		t.Fatal("hostOnly port strip")
	}
	if hostOnly("example.com") != "example.com" {
		t.Fatal("hostOnly bare")
	}
	if hostFromURL("wss://x.com/sock?q=1") != "x.com" {
		t.Fatal("hostFromURL")
	}
}
