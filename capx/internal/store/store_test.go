package store

import (
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

// TestFlowConcurrency exercises the race-safe flow mutators against concurrent
// readers; run with -race it would flag the old read-modify-write-on-shared-
// pointer pattern.
func TestFlowConcurrency(t *testing.T) {
	s := New(100)
	s.EnsureFlow(&model.Flow{ID: "f1", L4: model.TCP, Started: time.Now()})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				s.AddFlowPacket("f1", 100, time.Now())
				s.AppendFlowPayload("f1", "client", []byte("abc"), 1024)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				for _, f := range s.ListFlows() {
					_ = f.Packets
					_ = len(f.ClientPayload)
				}
			}
		}()
	}
	wg.Wait()

	f, ok := s.GetFlowByID("f1")
	if !ok || f.Packets != 2000 {
		t.Fatalf("packets = %d (ok=%v), want 2000", f.Packets, ok)
	}
	if len(f.ClientPayload) != 1024 {
		t.Fatalf("payload capped len = %d, want 1024", len(f.ClientPayload))
	}
}

// TestKeylogDedup verifies key-log lines are de-duplicated and comments/blank
// lines ignored.
func TestKeylogDedup(t *testing.T) {
	s := New(100)
	if !s.AddKeylogLine("CLIENT_RANDOM abc def") {
		t.Fatal("first line should be added")
	}
	if s.AddKeylogLine("CLIENT_RANDOM abc def") {
		t.Fatal("duplicate should be rejected")
	}
	if s.AddKeylogLine("  # a comment") {
		t.Fatal("comment should be ignored")
	}
	if s.AddKeylogLine("   ") {
		t.Fatal("blank should be ignored")
	}
	if !s.AddKeylogLine("SERVER_TRAFFIC_SECRET_0 11 22") {
		t.Fatal("second distinct line should be added")
	}
	if got := s.Keylog(); len(got) != 2 {
		t.Fatalf("keylog len = %d, want 2", len(got))
	}
}

// TestFlowEviction verifies the LRU-ish cap keeps the flow map bounded.
func TestFlowEviction(t *testing.T) {
	s := New(10)
	s.SetMaxFlows(20)
	base := time.Now()
	for i := 0; i < 100; i++ {
		id := "flow-" + time.Duration(i).String()
		s.EnsureFlow(&model.Flow{ID: id, Started: base.Add(time.Duration(i) * time.Millisecond),
			Updated: base.Add(time.Duration(i) * time.Millisecond)})
	}
	if n := len(s.ListFlows()); n > 20 {
		t.Fatalf("flow count = %d, want <= 20 after eviction", n)
	}
}

func ids(txs []*model.HTTPTx) []uint64 {
	out := make([]uint64, len(txs))
	for i, tx := range txs {
		out[i] = tx.ID
	}
	return out
}

func seedHTTP(s *Store) {
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", URL: "https://api.example.com/users", Status: 200, MIME: "application/json", RespRaw: "HTTP/1.1 200 OK\r\n\r\n{\"name\":\"alice\"}"})
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "POST", Host: "api.example.com", URL: "https://api.example.com/login", Status: 401, MIME: "application/json", ReqRaw: "POST /login HTTP/1.1\r\n\r\nsecret-token"})
	s.AddHTTPTx(&model.HTTPTx{Scheme: "http", Method: "GET", Host: "cdn.other.net", URL: "http://cdn.other.net/app.js", Status: 200, MIME: "application/javascript"})
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", URL: "https://api.example.com/missing", Status: 404, MIME: "text/html"})
}

func TestFilterHTTPTx(t *testing.T) {
	s := New(100)
	seedHTTP(s)

	cases := []struct {
		name string
		f    HTTPFilter
		want []uint64
	}{
		{"empty matches all", HTTPFilter{}, []uint64{1, 2, 3, 4}},
		{"scheme http", HTTPFilter{Scheme: "http"}, []uint64{3}},
		{"host substring ci", HTTPFilter{Host: "EXAMPLE"}, []uint64{1, 2, 4}},
		{"method list", HTTPFilter{Method: "post, GET"}, []uint64{1, 2, 3, 4}},
		{"method single", HTTPFilter{Method: "POST"}, []uint64{2}},
		{"mime substring", HTTPFilter{MIME: "json"}, []uint64{1, 2}},
		{"status exact", HTTPFilter{Status: "404"}, []uint64{4}},
		{"status class 2xx", HTTPFilter{Status: "2xx"}, []uint64{1, 3}},
		{"status range", HTTPFilter{Status: "400-499"}, []uint64{2, 4}},
		{"status bad spec matches none", HTTPFilter{Status: "abc"}, []uint64{}},
		{"query hits url", HTTPFilter{Query: "USERS"}, []uint64{1}},
		{"query hits req body", HTTPFilter{Query: "secret-token"}, []uint64{2}},
		{"query hits resp body", HTTPFilter{Query: "alice"}, []uint64{1}},
		{"combined", HTTPFilter{Scheme: "https", Method: "GET", Status: "2xx"}, []uint64{1}},
		{"no match", HTTPFilter{Host: "nope"}, []uint64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(s.FilterHTTPTx(tc.f))
			if len(got) != len(tc.want) {
				t.Fatalf("got ids %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got ids %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestListHTTPTxStillFiltersByScheme(t *testing.T) {
	s := New(100)
	seedHTTP(s)
	if got := ids(s.ListHTTPTx("http")); len(got) != 1 || got[0] != 3 {
		t.Fatalf("ListHTTPTx(http) = %v, want [3]", got)
	}
	if got := s.ListHTTPTx(""); len(got) != 4 {
		t.Fatalf("ListHTTPTx(\"\") returned %d, want 4", len(got))
	}
}

func TestAddHTTPTxPreservesEveryPollingExchange(t *testing.T) {
	s := New(100)
	first := s.AddHTTPTx(&model.HTTPTx{
		Scheme:  "https",
		Method:  "POST",
		Host:    "console.volcengine.com",
		Path:    "/api/passport/account/currentIdentity",
		Status:  200,
		MIME:    "application/json",
		RespLen: 257,
		ReqRaw:  "POST /api/passport/account/currentIdentity HTTP/1.1\r\nHost: console.volcengine.com\r\n\r\n{}",
	})
	second := s.AddHTTPTx(&model.HTTPTx{
		Scheme:  "https",
		Method:  "POST",
		Host:    "console.volcengine.com",
		Path:    "/api/passport/account/currentIdentity",
		Status:  200,
		MIME:    "application/json",
		RespLen: 257,
		ReqRaw:  "POST /api/passport/account/currentIdentity HTTP/1.1\r\nHost: console.volcengine.com\r\nDate: later\r\n\r\n{}",
	})

	if first.ID == second.ID {
		t.Fatalf("original exchanges must have distinct ids: %d vs %d", first.ID, second.ID)
	}
	got := s.ListHTTPTx("")
	if len(got) != 2 {
		t.Fatalf("history len = %d, want 2", len(got))
	}
	if got[0].RepeatCnt != 1 || got[1].RepeatCnt != 1 {
		t.Fatal("original exchanges must not be collapsed in storage")
	}
}

func TestAddHTTPTxKeepsDifferentBodies(t *testing.T) {
	s := New(100)
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "POST", Host: "api.example.com", Path: "/save", Status: 200, MIME: "application/json", RespLen: 2, ReqRaw: "POST /save HTTP/1.1\r\n\r\n{\"id\":1}"})
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "POST", Host: "api.example.com", Path: "/save", Status: 200, MIME: "application/json", RespLen: 2, ReqRaw: "POST /save HTTP/1.1\r\n\r\n{\"id\":2}"})
	if got := s.ListHTTPTx(""); len(got) != 2 {
		t.Fatalf("different bodies collapsed; len = %d, want 2", len(got))
	}
}

func TestAddHTTPTxKeepsDifferentResponseBodies(t *testing.T) {
	s := New(100)
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/poll", Status: 200, MIME: "application/json", RespLen: 7, ReqRaw: "GET /poll HTTP/1.1\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nDate: one\r\n\r\n{\"a\":1}"})
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/poll", Status: 200, MIME: "application/json", RespLen: 7, ReqRaw: "GET /poll HTTP/1.1\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nDate: two\r\n\r\n{\"a\":2}"})
	if got := s.ListHTTPTx(""); len(got) != 2 {
		t.Fatalf("different response bodies collapsed; len = %d, want 2", len(got))
	}
}

func TestAddHTTPTxPreservesResponseHeaderChanges(t *testing.T) {
	s := New(100)
	first := s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/poll", Status: 200, MIME: "application/json", RespLen: 7, ReqRaw: "GET /poll HTTP/1.1\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nDate: one\r\nX-Trace-Id: a\r\n\r\n{\"a\":1}"})
	second := s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/poll", Status: 200, MIME: "application/json", RespLen: 7, ReqRaw: "GET /poll HTTP/1.1\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nDate: two\r\nX-Trace-Id: b\r\nSet-Cookie: sid=2\r\n\r\n{\"a\":1}"})
	if first.ID == second.ID {
		t.Fatalf("header changes collapsed into id %d", first.ID)
	}
	if got := s.ListHTTPTx(""); len(got) != 2 || got[1].RespRaw != second.RespRaw {
		t.Fatalf("response header evidence lost: %+v", got)
	}
}

func TestCaptureLinkTypeForExportUnanimousOnly(t *testing.T) {
	s := New(10)
	s.PutCapture(&model.Capture{ID: "cap-1", LinkType: 1})
	s.PutCapture(&model.Capture{ID: "cap-2", LinkType: 101})
	if got := s.CaptureLinkTypeForExport(""); got != 0 {
		t.Fatalf("mixed link types = %d, want 0 so export can fall back to Ethernet", got)
	}
	if got := s.CaptureLinkTypeForExport("cap-2"); got != 101 {
		t.Fatalf("cap-2 link type = %d, want 101", got)
	}
}

func TestSubscribeUnsubIsIdempotent(t *testing.T) {
	s := New(8)
	_, unsub := s.Subscribe(4)
	unsub()
	unsub() // must not panic on a second close
}

func TestGetCaptureReturnsCopy(t *testing.T) {
	s := New(8)
	s.PutCapture(&model.Capture{ID: "cap-1", Running: true, LinkType: 1})
	got, ok := s.GetCapture("cap-1")
	if !ok {
		t.Fatal("missing capture")
	}
	got.Running = false
	again, _ := s.GetCapture("cap-1")
	if !again.Running {
		t.Fatal("GetCapture leaked a mutable pointer into the store")
	}
	s.MarkCaptureStopped("cap-1", time.Now())
	stopped, _ := s.GetCapture("cap-1")
	if stopped.Running || stopped.Stopped == nil || stopped.LinkType != 1 {
		t.Fatalf("MarkCaptureStopped dropped fields: %+v", stopped)
	}
}

func TestClearHistory(t *testing.T) {
	s := New(100)
	seedHTTP(s)
	s.AddWSMessage(&model.WSMessage{URL: "wss://api.example.com/socket", Dir: model.WSSend, Opcode: "text", Data: "ping"})
	s.EnsureFlow(&model.Flow{ID: "f1", L4: model.TCP, Started: time.Now()})
	s.AddPacket(model.Packet{CaptureID: "cap-1", Raw: []byte{1, 2, 3}})
	s.Publish(model.Event{Source: model.SourceProxy, Kind: "http_tx"})

	counts := s.ClearHistory()
	if counts.HTTP != 4 || counts.WS != 1 || counts.Flows != 1 || counts.Packets != 1 || counts.Events != 6 {
		t.Fatalf("unexpected clear counts: %+v", counts)
	}
	if got := s.ListHTTPTx(""); len(got) != 0 {
		t.Fatalf("http history len = %d, want 0", len(got))
	}
	if got := s.ListWS(); len(got) != 0 {
		t.Fatalf("ws history len = %d, want 0", len(got))
	}
	if got := s.ListFlows(); len(got) != 0 {
		t.Fatalf("flows len = %d, want 0", len(got))
	}
	if got := s.ListPackets(""); len(got) != 0 {
		t.Fatalf("packets len = %d, want 0", len(got))
	}
	if got := s.Recent(); len(got) != 0 {
		t.Fatalf("recent events len = %d, want 0", len(got))
	}
}

func TestStatusMatches(t *testing.T) {
	cases := []struct {
		code int
		spec string
		want bool
	}{
		{200, "", true},
		{200, "200", true},
		{200, "201", false},
		{204, "2xx", true},
		{204, "2XX", true},
		{301, "2xx", false},
		{404, "400-499", true},
		{500, "400-499", false},
		{200, "abc", false},
		{200, "0xx", false},
	}
	for _, tc := range cases {
		if got := statusMatches(tc.code, tc.spec); got != tc.want {
			t.Errorf("statusMatches(%d, %q) = %v, want %v", tc.code, tc.spec, got, tc.want)
		}
	}
}

func TestFilterWS(t *testing.T) {
	s := New(100)
	s.AddWSMessage(&model.WSMessage{URL: "wss://api.example.com/socket", Dir: model.WSSend, Opcode: "text", Data: "ping hello"})
	s.AddWSMessage(&model.WSMessage{URL: "wss://api.example.com/socket", Dir: model.WSRecv, Opcode: "text", Data: "pong world"})
	s.AddWSMessage(&model.WSMessage{URL: "wss://other.net/feed", Dir: model.WSRecv, Opcode: "binary", Data: "deadbeef"})

	if got := s.FilterWS(WSFilter{}); len(got) != 3 {
		t.Fatalf("empty filter returned %d, want 3", len(got))
	}
	if got := s.FilterWS(WSFilter{Dir: "recv"}); len(got) != 2 {
		t.Fatalf("dir=recv returned %d, want 2", len(got))
	}
	if got := s.FilterWS(WSFilter{Opcode: "binary"}); len(got) != 1 || got[0].URL != "wss://other.net/feed" {
		t.Fatalf("opcode=binary wrong: %+v", got)
	}
	if got := s.FilterWS(WSFilter{URL: "EXAMPLE"}); len(got) != 2 {
		t.Fatalf("url substring returned %d, want 2", len(got))
	}
	if got := s.FilterWS(WSFilter{Query: "world"}); len(got) != 1 || got[0].Data != "pong world" {
		t.Fatalf("query=world wrong: %+v", got)
	}
}
