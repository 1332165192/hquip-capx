package api

import "net/http"

// correlate returns cross-layer session timelines built from the current
// flow/http/ws/hook state (M7).
func (s *Server) correlate(w http.ResponseWriter, r *http.Request) {
	if s.corr == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.corr.Groups())
}
