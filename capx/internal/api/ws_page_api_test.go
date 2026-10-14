package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func wsReadTestMux(st *store.Store) http.Handler {
	s := &Server{st: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ws/page", s.wsPage)
	mux.HandleFunc("GET /api/ws/detail/{id}", s.wsDetail)
	mux.HandleFunc("GET /api/ws", s.listWS)
	return mux
}

func TestWSPageAPIWireContractAndBackwardCompatibility(t *testing.T) {
	st := store.New(500)
	for i := 0; i < 350; i++ {
		st.AddWSMessage(&model.WSMessage{ConnID: "same", URL: "wss://example.test/ws", Dir: model.WSSend, Opcode: "text", Data: "retained payload", Length: 16})
	}
	mux := wsReadTestMux(st)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws/page?limit=100", nil))
	var page store.WSPage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 100 || page.Total != 350 || page.NextCursor != "251" || !page.HasMore {
		t.Fatalf("wrong response: %d %s", w.Code, w.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw["items"], &rows); err != nil {
		t.Fatal(err)
	}
	if string(rows[0]["id"]) != `"350"` || string(raw["next_cursor"]) != `"251"` {
		t.Fatal("IDs are not decimal strings")
	}
	for _, row := range rows {
		if _, found := row["data"]; found {
			t.Fatal("list leaked frame body")
		}
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws?dir=send", nil))
	var old []map[string]json.RawMessage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &old) != nil || len(old) != 350 || string(old[0]["id"]) != "1" || string(old[0]["data"]) != `"retained payload"` {
		t.Fatal("old endpoint behavior changed")
	}
}

func TestWSPageAPIRejectsInvalidParameters(t *testing.T) {
	mux := wsReadTestMux(store.New(10))
	for _, query := range []string{
		"limit=", "limit=0", "limit=-1", "limit=101", "limit=abc", "limit=1.5", "limit=1&limit=2",
		"before_id=", "before_id=0", "before_id=-1", "before_id=%2B1", "before_id=18446744073709551616",
		"after_id=x", "after_id=5&before_id=5", "after_id=6&before_id=5", "after_id=2&after_id=3",
		"dir=client", "dir=SEND", "opcode=ping", "opcode=TEXT", "conn_id=one&conn_id=two", "unknown=true", "q=%xx",
	} {
		t.Run(query, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws/page?"+query, nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid parameter accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws/page", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"items":[],"total":0,"next_cursor":"","has_more":false}` {
		t.Fatalf("empty array contract: %s", w.Body.String())
	}
}

func TestWSDetailAPIExactBinaryAndNotFound(t *testing.T) {
	st := store.New(10)
	bytes := []byte{0, 255, 10, 13, 128}
	data := base64.StdEncoding.EncodeToString(bytes)
	st.AddWSMessage(&model.WSMessage{ConnID: "socket", Opcode: "binary", Data: data, Length: len(bytes)})
	mux := wsReadTestMux(st)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws/detail/1", nil))
	var detail store.WSDetail
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.ID != "1" || detail.Data != data || !detail.IsBase64 || detail.Length != len(bytes) {
		t.Fatalf("detail changed binary bytes: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/ws/detail/0", "/api/ws/detail/-1", "/api/ws/detail/text", "/api/ws/detail/18446744073709551616", "/api/ws/detail/1?limit=2"} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("bad detail ID accepted: %s: %d", path, w.Code)
		}
	}
	st.ClearHistory()
	st.AddWSMessage(&model.WSMessage{Data: "replacement", Opcode: "text"})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ws/detail/1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cleared detail returned wrong frame: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/ws/page", "/api/ws/detail/1"} {
		if isActiveOp(http.MethodGet, path) {
			t.Fatalf("readonly WS route needs active mode: %s", path)
		}
	}
}

func TestWSReadRoutesRegisteredWithActiveModeDisabled(t *testing.T) {
	t.Setenv("CAPX_AUTH", "1")
	t.Setenv("CAPX_TOKEN", "ws-read-test-token")
	srv := newTestAPIServer(t)
	srv.SetActive(false)
	srv.st.AddWSMessage(&model.WSMessage{ConnID: "one", Opcode: "text", Data: "payload"})
	handler := srv.Handler()
	for _, path := range []string{"/api/ws/page", "/api/ws/detail/1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		r.Header.Set("Authorization", "Bearer ws-read-test-token")
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("registered read route rejected with active mode off: %s: %d %s", path, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("new route bypassed authentication: %s: %d", path, w.Code)
		}
	}
}
