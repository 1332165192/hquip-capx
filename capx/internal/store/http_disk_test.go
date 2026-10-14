package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

func TestHTTPDiskQueryAndDetail(t *testing.T) {
	s := New(10)
	path := filepath.Join(t.TempDir(), "http_history.sqlite")
	if err := s.EnableHTTPDisk(path); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()

	for i := 0; i < 5; i++ {
		s.AddHTTPTx(&model.HTTPTx{
			TS:        time.Date(2026, 6, 27, 12, i, 0, 0, time.UTC),
			Scheme:    "https",
			Method:    "GET",
			Host:      "example.com",
			Path:      "/api/" + string(rune('a'+i)),
			URL:       "https://example.com/api",
			Status:    200 + i,
			RespLen:   100 + i,
			MIME:      "application/json",
			ReqRaw:    "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			RespRaw:   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
			ReqHdr:    map[string]string{"Host": "example.com"},
			RespHdr:   map[string]string{"Content-Type": "application/json"},
			Decrypted: true,
		})
	}

	rows, ok, err := s.QueryHTTPTx(HTTPQuery{Filter: HTTPFilter{Host: "example"}, Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("disk query not enabled")
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].ID <= rows[1].ID {
		t.Fatalf("rows not newest-first: %d <= %d", rows[0].ID, rows[1].ID)
	}

	got, ok := s.GetHTTPTx(rows[0].ID)
	if !ok {
		t.Fatal("detail not found")
	}
	if got.ReqRaw == "" || got.RespRaw == "" {
		t.Fatalf("detail missing raw request/response: %+v", got)
	}
	if got.ReqHdr["Host"] != "example.com" {
		t.Fatalf("headers not restored: %+v", got.ReqHdr)
	}
}
