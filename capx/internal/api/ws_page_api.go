package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hquip/capx/internal/store"
)

func (s *Server) wsPage(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid query encoding")
		return
	}
	allowed := map[string]bool{"before_id": true, "after_id": true, "conn_id": true, "dir": true, "opcode": true, "q": true, "url": true, "limit": true}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			writeErr(w, http.StatusBadRequest, "unknown or repeated query parameter: "+key)
			return
		}
	}
	filter := store.WSPageFilter{
		WSFilter: store.WSFilter{URL: q.Get("url"), Dir: q.Get("dir"), Opcode: q.Get("opcode"), Query: q.Get("q")},
		ConnID:   q.Get("conn_id"), Limit: 50,
	}
	if q.Has("before_id") {
		filter.BeforeID, err = parseWSDecimal(q.Get("before_id"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid before_id")
			return
		}
	}
	if q.Has("after_id") {
		filter.AfterID, err = parseWSDecimal(q.Get("after_id"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid after_id")
			return
		}
	}
	if q.Has("limit") {
		n, parseErr := parseWSDecimal(q.Get("limit"))
		if parseErr != nil || n > 100 {
			writeErr(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
		filter.Limit = int(n)
	}
	page, err := s.st.PageWS(filter)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) wsDetail(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "detail does not accept query parameters")
		return
	}
	id, err := parseWSDecimal(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid WebSocket frame ID")
		return
	}
	detail, ok := s.st.GetWSDetail(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "WebSocket frame not retained")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func parseWSDecimal(value string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("empty decimal")
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("not an unsigned decimal")
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("decimal outside uint64 range")
	}
	return n, nil
}
