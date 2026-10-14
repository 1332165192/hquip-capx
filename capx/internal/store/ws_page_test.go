package store

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hquip/capx/internal/model"
)

func TestWSPageKeysetAcrossNewArrivals(t *testing.T) {
	s := New(1000)
	for i := 0; i < 350; i++ {
		s.AddWSMessage(&model.WSMessage{ConnID: "same", URL: "wss://example.test/ws", Opcode: "text", Dir: model.WSSend, Data: strings.Repeat("payload-secret-", 300), Length: 4500})
	}
	first, err := s.PageWS(WSPageFilter{Limit: 100})
	if err != nil || first.Total != 350 || len(first.Items) != 100 || first.Items[0].ID != "350" || first.NextCursor != "251" || !first.HasMore {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), "payload-secret") || strings.Contains(string(encoded), `"data"`) || len(encoded) > 30000 {
		t.Fatalf("page included payload or grew with payload size: bytes=%d, err=%v", len(encoded), err)
	}
	// Insert between requests: the original cursor still pages every older
	// item once and neither duplicates nor incorporates the newer arrival.
	s.AddWSMessage(&model.WSMessage{ConnID: "same", Opcode: "text", Data: "new"})
	seen := make(map[string]bool, 350)
	for _, item := range first.Items {
		seen[item.ID] = true
	}
	cursor := first.NextCursor
	for cursor != "" {
		before, _ := strconv.ParseUint(cursor, 10, 64)
		page, err := s.PageWS(WSPageFilter{BeforeID: before, Limit: 100})
		if err != nil || page.Total != 351 {
			t.Fatalf("older page: %+v, %v", page, err)
		}
		for _, item := range page.Items {
			if seen[item.ID] || item.ID == "351" {
				t.Fatalf("duplicate/new item in older history: %s", item.ID)
			}
			seen[item.ID] = true
		}
		cursor = page.NextCursor
		if page.HasMore != (cursor != "") {
			t.Fatal("cursor and has_more disagree")
		}
	}
	if len(seen) != 350 || !seen["1"] {
		t.Fatalf("lost old frames: %d", len(seen))
	}
	newer, err := s.PageWS(WSPageFilter{AfterID: 350, Limit: 100})
	if err != nil || len(newer.Items) != 1 || newer.Items[0].ID != "351" || newer.HasMore {
		t.Fatalf("newer range: %+v, %v", newer, err)
	}
}

func TestWSPageFiltersAndOutOfOrderCapture(t *testing.T) {
	s := New(100)
	s.AddWSMessage(&model.WSMessage{ConnID: "one", URL: "wss://example.test/identical", Dir: model.WSSend, Opcode: "text", Data: "Hello WORLD"})
	s.AddWSMessage(&model.WSMessage{ConnID: "two", URL: "wss://example.test/identical", Dir: model.WSSend, Opcode: "text", Data: "Hello WORLD"})
	s.AddWSMessage(&model.WSMessage{ConnID: "one", URL: "wss://example.test/other", Dir: model.WSRecv, Opcode: "binary", Data: "YmluYXJ5"})
	// Simulate insertion order from concurrently recorded connections.
	s.mu.Lock()
	s.wsMsgs[0], s.wsMsgs[2] = s.wsMsgs[2], s.wsMsgs[0]
	s.mu.Unlock()
	for _, tc := range []struct {
		name   string
		filter WSPageFilter
		want   []string
	}{
		{"unordered", WSPageFilter{Limit: 2}, []string{"3", "2"}},
		{"connection exact", WSPageFilter{ConnID: "one"}, []string{"3", "1"}},
		{"connection case-sensitive", WSPageFilter{ConnID: "ONE"}, []string{}},
		{"same URL distinct connection", WSPageFilter{ConnID: "two", WSFilter: WSFilter{URL: "EXAMPLE", Query: "WORLD", Opcode: "text", Dir: "send"}}, []string{"2"}},
		{"binary", WSPageFilter{WSFilter: WSFilter{Opcode: "binary", Dir: "recv"}}, []string{"3"}},
		{"query is payload", WSPageFilter{WSFilter: WSFilter{Query: "example.test"}}, []string{}},
		{"cursor range", WSPageFilter{AfterID: 1, BeforeID: 3}, []string{"2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.PageWS(tc.filter)
			if err != nil || len(page.Items) != len(tc.want) {
				t.Fatalf("items=%+v, err=%v", page.Items, err)
			}
			for i, want := range tc.want {
				if page.Items[i].ID != want {
					t.Fatalf("item[%d]=%s want=%s", i, page.Items[i].ID, want)
				}
			}
		})
	}
	for _, f := range []WSPageFilter{{Limit: -1}, {Limit: 101}, {AfterID: 3, BeforeID: 2}, {AfterID: 2, BeforeID: 2}, {WSFilter: WSFilter{Dir: "client"}}, {WSFilter: WSFilter{Opcode: "ping"}}} {
		if _, err := s.PageWS(f); err == nil {
			t.Fatalf("accepted invalid filter: %+v", f)
		}
	}
}

func TestWSDetailPayloadPrecisionEvictionAndClear(t *testing.T) {
	s := New(2)
	s.wsSeq.Store(9007199254740992)
	binary := []byte{0, 255, 128, 10, 13, 1}
	m := s.AddWSMessage(&model.WSMessage{ConnID: "binary", Opcode: "binary", Data: base64.StdEncoding.EncodeToString(binary), Length: len(binary)})
	detail, ok := s.GetWSDetail(m.ID)
	if !ok || detail.ID != "9007199254740993" || !detail.IsBase64 || detail.Data != base64.StdEncoding.EncodeToString(binary) || detail.Length != len(binary) {
		t.Fatalf("binary detail corrupted: %+v", detail)
	}
	encoded, err := json.Marshal(detail)
	if err != nil || !strings.Contains(string(encoded), `"id":"9007199254740993"`) {
		t.Fatalf("large detail ID lost JSON precision: %s, %v", encoded, err)
	}
	text := "正文\n{\"exact\":true}\r\n"
	tx := s.AddWSMessage(&model.WSMessage{Opcode: "text", Data: text, Length: len(text)})
	detail, ok = s.GetWSDetail(tx.ID)
	if !ok || detail.IsBase64 || detail.Data != text {
		t.Fatalf("text detail changed: %+v", detail)
	}
	detail.Data = "modified returned copy"
	if again, _ := s.GetWSDetail(tx.ID); again.Data != text {
		t.Fatal("detail mutation changed retained frame")
	}
	s.AddWSMessage(&model.WSMessage{Data: "third"})
	if _, ok := s.GetWSDetail(m.ID); ok {
		t.Fatal("evicted frame still found")
	}
	s.ClearHistory()
	s.AddWSMessage(&model.WSMessage{Data: "after clear"})
	if _, ok := s.GetWSDetail(tx.ID); ok {
		t.Fatal("cleared ID substituted with another frame")
	}
	page, err := s.PageWS(WSPageFilter{})
	if err != nil || page.Total != 1 || page.Items[0].ID != "9007199254740996" {
		t.Fatalf("clear reused IDs: %+v, %v", page, err)
	}
}

func TestWSPageConcurrentCaptureAndRead(t *testing.T) {
	s := New(500)
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.AddWSMessage(&model.WSMessage{ConnID: "capture", Opcode: "text", Data: "concurrent"})
			}
		}()
	}
	for i := 0; i < 100; i++ {
		page, err := s.PageWS(WSPageFilter{Limit: 25})
		if err != nil {
			t.Fatal(err)
		}
		for j := 1; j < len(page.Items); j++ {
			prev, _ := strconv.ParseUint(page.Items[j-1].ID, 10, 64)
			next, _ := strconv.ParseUint(page.Items[j].ID, 10, 64)
			if prev <= next {
				t.Fatal("concurrent page did not have descending unique IDs")
			}
		}
		if len(page.Items) > 0 {
			id, _ := strconv.ParseUint(page.Items[0].ID, 10, 64)
			s.GetWSDetail(id)
		}
	}
	wg.Wait()
}
