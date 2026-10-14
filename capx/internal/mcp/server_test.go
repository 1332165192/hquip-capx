package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToolsListJSONRPC(t *testing.T) {
	s := &Server{api: &apiClient{}}
	var out bytes.Buffer
	req := rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list"}
	if err := s.handle(&out, req); err != nil {
		t.Fatal(err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !bytes.Contains(raw, []byte("capx_list_http")) {
		t.Fatalf("missing capx_list_http in %s", raw)
	}
	if !bytes.Contains(raw, []byte("capx_repeater_send")) {
		t.Fatalf("missing repeater tool in %s", raw)
	}
	if !bytes.Contains(raw, []byte("capx_mem_write")) {
		t.Fatalf("missing mem write in %s", raw)
	}
	if !bytes.Contains(raw, []byte("capx_api")) {
		t.Fatalf("missing generic capx_api in %s", raw)
	}
}

func TestAllRoutesUnique(t *testing.T) {
	seen := map[string]string{}
	for _, r := range allRoutes() {
		key := r.Method + " " + r.Path
		if prev, ok := seen[r.Name]; ok {
			t.Fatalf("duplicate tool name %s (%s vs %s)", r.Name, prev, key)
		}
		seen[r.Name] = key
	}
	if len(seen) < 150 {
		t.Fatalf("too few routes: %d", len(seen))
	}
}

func TestMemWriteRequiresActive(t *testing.T) {
	s := &Server{api: &apiClient{active: false}}
	text, isErr := s.call("capx_mem_write", json.RawMessage(`{"sid":"s1","addr":1}`))
	if !isErr || !strings.Contains(text, "CAPX_MCP_ACTIVE") {
		t.Fatalf("got err=%v text=%q", isErr, text)
	}
}

func TestGenericAPIGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/policy", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"active_allowed": false})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &Server{api: &apiClient{base: srv.URL, http: srv.Client()}}
	text, isErr := s.call("capx_api", json.RawMessage(`{"method":"GET","path":"/api/policy"}`))
	if isErr {
		t.Fatal(text)
	}
	if !strings.Contains(text, "active_allowed") {
		t.Fatalf("got %s", text)
	}
}

func TestRepeaterAllowsPOSTByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/repeater/send", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 200})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &Server{api: &apiClient{base: srv.URL, http: srv.Client(), active: false}}
	text, isErr := s.call("capx_repeater_send", json.RawMessage(`{"raw":"POST /x HTTP/1.1\r\nHost: a\r\n\r\n"}`))
	if isErr {
		t.Fatal(text)
	}
	if !strings.Contains(text, "200") {
		t.Fatalf("got %q", text)
	}
}

func TestRepeaterBlocksDELETEByDefault(t *testing.T) {
	s := &Server{api: &apiClient{active: false}}
	text, isErr := s.call("capx_repeater_send", json.RawMessage(`{"raw":"DELETE /x HTTP/1.1\r\nHost: a\r\n\r\n"}`))
	if !isErr {
		t.Fatal("expected error")
	}
	if !strings.Contains(text, "CAPX_MCP_ACTIVE") {
		t.Fatalf("got %q", text)
	}
}

func TestListHTTPHitsAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/http", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("host") != "example.com" {
			t.Errorf("host=%q", r.URL.Query().Get("host"))
		}
		if got := r.Header.Get("X-Capx-Token"); got != "tok" {
			t.Errorf("token=%q", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "host": "example.com", "method": "GET"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &Server{api: &apiClient{base: srv.URL, token: "tok", http: srv.Client()}}
	text, isErr := s.call("capx_list_http", json.RawMessage(`{"host":"example.com","limit":10}`))
	if isErr {
		t.Fatal(text)
	}
	if !strings.Contains(text, "example.com") {
		t.Fatalf("got %s", text)
	}
}

func TestInitialize(t *testing.T) {
	s := New()
	var out bytes.Buffer
	req := rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize", Params: json.RawMessage(`{}`)}
	if err := s.handle(&out, req); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"name":"capx"`)) {
		t.Fatalf("%s", out.Bytes())
	}
}

func TestFirstMethod(t *testing.T) {
	if got := firstMethod("POST /x HTTP/1.1\r\nHost: a\r\n\r\n"); got != "POST" {
		t.Fatal(got)
	}
	if !safeMethod("GET") || !safeMethod("POST") || safeMethod("DELETE") {
		t.Fatal("safeMethod")
	}
}
