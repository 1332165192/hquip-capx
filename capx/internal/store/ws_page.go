package store

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hquip/capx/internal/model"
)

// WSMetadata is the payload-free representation used by the paginated reader.
// String IDs preserve uint64 precision for JavaScript clients.
type WSMetadata struct {
	ID     string      `json:"id"`
	ConnID string      `json:"conn_id"`
	URL    string      `json:"url"`
	TS     time.Time   `json:"ts"`
	Dir    model.WSDir `json:"dir"`
	Opcode string      `json:"opcode"`
	Length int         `json:"length"`
}

type WSPageFilter struct {
	WSFilter
	ConnID   string
	BeforeID uint64
	AfterID  uint64
	Limit    int
}

type WSPage struct {
	Items      []WSMetadata `json:"items"`
	Total      int          `json:"total"`
	NextCursor string       `json:"next_cursor"`
	HasMore    bool         `json:"has_more"`
}

// PageWS returns newest frames first, using exclusive ID bounds. Total counts
// all retained frames matching the filters, independently of the ID bounds.
// Only limit+1 frame pointers are retained while selecting a page; no payload
// is copied into the result or into an intermediate history snapshot.
func (s *Store) PageWS(f WSPageFilter) (WSPage, error) {
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit < 1 || f.Limit > 100 {
		return WSPage{}, fmt.Errorf("limit must be between 1 and 100")
	}
	if f.BeforeID != 0 && f.AfterID != 0 && f.AfterID >= f.BeforeID {
		return WSPage{}, fmt.Errorf("after_id must be smaller than before_id")
	}
	if f.Dir != "" && f.Dir != "send" && f.Dir != "recv" {
		return WSPage{}, fmt.Errorf("dir must be send or recv")
	}
	if f.Opcode != "" && f.Opcode != "text" && f.Opcode != "binary" {
		return WSPage{}, fmt.Errorf("opcode must be text or binary")
	}
	url, query := strings.ToLower(f.URL), strings.ToLower(f.Query)
	page := WSPage{Items: make([]WSMetadata, 0, f.Limit)}
	selected := make([]*model.WSMessage, 0, f.Limit+1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.wsMsgs {
		if m == nil || (f.ConnID != "" && m.ConnID != f.ConnID) ||
			(url != "" && !strings.Contains(strings.ToLower(m.URL), url)) ||
			(f.Dir != "" && !strings.EqualFold(string(m.Dir), f.Dir)) ||
			(f.Opcode != "" && !strings.EqualFold(m.Opcode, f.Opcode)) ||
			(query != "" && !strings.Contains(strings.ToLower(m.Data), query)) {
			continue
		}
		page.Total++
		if (f.BeforeID != 0 && m.ID >= f.BeforeID) || (f.AfterID != 0 && m.ID <= f.AfterID) {
			continue
		}
		// Keep only the largest limit+1 IDs. Capture insertion can occur out of
		// ID order when different connections record frames concurrently.
		pos := sort.Search(len(selected), func(i int) bool { return selected[i].ID <= m.ID })
		if pos > f.Limit {
			continue
		}
		if len(selected) < f.Limit+1 {
			selected = append(selected, nil)
		}
		copy(selected[pos+1:], selected[pos:len(selected)-1])
		selected[pos] = m
	}
	page.HasMore = len(selected) > f.Limit
	if page.HasMore {
		selected = selected[:f.Limit]
	}
	for _, m := range selected {
		page.Items = append(page.Items, wsMetadata(m))
	}
	if page.HasMore && len(page.Items) > 0 {
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

func wsMetadata(m *model.WSMessage) WSMetadata {
	return WSMetadata{
		ID: strconv.FormatUint(m.ID, 10), ConnID: m.ConnID, URL: m.URL,
		TS: m.TS, Dir: m.Dir, Opcode: m.Opcode, Length: m.Length,
	}
}

// WSDetail preserves the original stored payload. Binary frames from the
// capture pipeline are base64 strings; text frames are unmodified text.
type WSDetail struct {
	WSMetadata
	FlowID   string `json:"flow_id"`
	Data     string `json:"data"`
	IsBase64 bool   `json:"is_base64"`
}

// GetWSDetail returns a value snapshot for the exact retained ID. Cleared or
// evicted frames are absent; this never substitutes a frame with another ID.
func (s *Store) GetWSDetail(id uint64) (WSDetail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.wsMsgs {
		if m != nil && m.ID == id {
			return WSDetail{
				WSMetadata: wsMetadata(m), FlowID: m.FlowID, Data: m.Data,
				IsBase64: strings.EqualFold(m.Opcode, "binary"),
			}, true
		}
	}
	return WSDetail{}, false
}
