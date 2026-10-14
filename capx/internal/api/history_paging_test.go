package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestHTTPPaginationAndFullTextMatchAcrossBackends(t *testing.T) {
	for _, disk := range []bool{false, true} {
		t.Run(fmt.Sprintf("sqlite=%v", disk), func(t *testing.T) {
			st := store.New(800)
			if disk {
				if err := st.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
					t.Fatal(err)
				}
				defer st.CloseHTTPDisk()
			}
			srv := &Server{st: st}
			stamp := time.Now().UTC()
			for i := 0; i < 650; i++ {
				method, status := "GET", 200
				if i%2 == 0 {
					method, status = "POST", 201
				}
				st.AddHTTPTx(&model.HTTPTx{TS: stamp, Host: "example.test", Scheme: "https", Path: fmt.Sprintf("/item/%d", i), Method: method, Status: status, ReqRaw: "GET / HTTP/1.1\r\n\r\ncommon literal_%", RespRaw: "HTTP/1.1 200 OK\r\n\r\n正文 secret"})
			}
			query := url.Values{"q": {"正文 secret"}, "limit": {"100"}, "offset": {"500"}}
			w := httptest.NewRecorder()
			srv.listHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http?"+query.Encode(), nil))
			if w.Code != 200 || w.Header().Get("X-Total-Count") != "650" {
				t.Fatalf("status=%d total=%q body=%s", w.Code, w.Header().Get("X-Total-Count"), w.Body.String())
			}
			var rows []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 100 || rows[0]["id"] != float64(150) || rows[99]["id"] != float64(51) {
				t.Fatalf("wrong page/tie sorting: len=%d first=%v", len(rows), rows[0])
			}
			if rows[0]["has_detail"] != true || rows[0]["req_raw_len"].(float64) <= 0 {
				t.Fatal("summary lost lazy detail metadata")
			}
			if _, exists := rows[0]["req_raw"]; exists {
				t.Fatal("list response exposed full body instead of summary")
			}
			query = url.Values{"q": {"literal_%"}, "method": {"POST"}, "status": {"2xx"}, "scheme": {"https"}, "limit": {"2"}, "offset": {"1"}, "filter": {"status == 201"}}
			w = httptest.NewRecorder()
			srv.listHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http?"+query.Encode(), nil))
			if w.Code != 200 || w.Header().Get("X-Total-Count") != "325" {
				t.Fatalf("combined filter total=%q status=%d", w.Header().Get("X-Total-Count"), w.Code)
			}
			json.Unmarshal(w.Body.Bytes(), &rows)
			if len(rows) != 2 || rows[0]["id"] != float64(647) {
				t.Fatalf("display filter must precede paging: %+v", rows)
			}
			query.Set("offset", "10000")
			w = httptest.NewRecorder()
			srv.listHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http?"+query.Encode(), nil))
			if w.Header().Get("X-Total-Count") != "325" || w.Body.String() != "[]\n" {
				t.Fatalf("out-of-range page lost total/array contract: %s", w.Body.String())
			}
		})
	}
}

func TestClearHistoryAPIUsesDurableClear(t *testing.T) {
	st := store.New(5)
	if err := st.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer st.CloseHTTPDisk()
	for i := 0; i < 12; i++ {
		st.AddHTTPTx(&model.HTTPTx{Host: "old.test"})
	}
	srv := &Server{st: st}
	w := httptest.NewRecorder()
	srv.clearHistory(w, httptest.NewRequest(http.MethodDelete, "/api/history", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("clear failed: %s", w.Body.String())
	}
	var result struct {
		Cleared store.HistoryCounts `json:"cleared"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Cleared.HTTP != 12 {
		t.Fatalf("clear reports memory count rather than disk count: %+v", result)
	}
	w = httptest.NewRecorder()
	srv.listHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http", nil))
	if w.Header().Get("X-Total-Count") != "0" || w.Body.String() != "[]\n" {
		t.Fatalf("clear left disk rows: %s", w.Body.String())
	}
	if recent := st.Recent(); len(recent) != 1 || recent[0].Kind != "history_cleared" {
		t.Fatalf("clear event missing/duplicated: %+v", recent)
	}
}
