package api

// TLS key-log (SSLKEYLOGFILE) support: capx collects the TLS session secrets
// needed to decrypt captured traffic *without* being an inline MITM. Secrets
// arrive two ways — ingested from a client that sets SSLKEYLOGFILE (POST the
// lines here), or dumped by the Frida TLS hook's keylog callback (which works
// even under certificate pinning). The collected log can be exported as a
// standard SSLKEYLOGFILE for Wireshark / capx's own decryption.

import (
	"bufio"
	"net/http"
	"strings"
)

// keylogStatus reports how many key-log lines have been collected.
func (s *Server) keylogStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"lines": len(s.st.Keylog())})
}

// keylogAdd ingests key-log lines. Body is either JSON {"lines":["..."]} /
// {"text":"..."} or a raw text/plain SSLKEYLOGFILE body. Returns how many new
// (deduplicated) lines were added.
func (s *Server) keylogAdd(w http.ResponseWriter, r *http.Request) {
	var added int
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var req struct {
			Lines []string `json:"lines"`
			Text  string   `json:"text"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad json")
			return
		}
		for _, ln := range req.Lines {
			if s.st.AddKeylogLine(ln) {
				added++
			}
		}
		if req.Text != "" {
			added += s.ingestKeylogText(req.Text)
		}
	} else {
		buf := make([]byte, 0, 4096)
		sc := bufio.NewScanner(r.Body)
		sc.Buffer(buf, 1<<20)
		for sc.Scan() {
			if s.st.AddKeylogLine(sc.Text()) {
				added++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "total": len(s.st.Keylog())})
}

func (s *Server) ingestKeylogText(text string) int {
	added := 0
	for _, ln := range strings.Split(text, "\n") {
		if s.st.AddKeylogLine(ln) {
			added++
		}
	}
	return added
}

// keylogExport serves the collected secrets as a downloadable SSLKEYLOGFILE
// (the format Wireshark's tls.keylog_file expects).
func (s *Server) keylogExport(w http.ResponseWriter, r *http.Request) {
	lines := s.st.Keylog()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-sslkeys.log"`)
	for _, ln := range lines {
		_, _ = w.Write([]byte(ln + "\n"))
	}
}
