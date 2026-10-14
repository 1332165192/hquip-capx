package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *Server) memDebugDisasm(w http.ResponseWriter, r *http.Request) {
	s.memDisasm(w, r)
}

func (s *Server) memDebugStack(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(r.PathValue("sid"))
	rspStr := r.URL.Query().Get("rsp")
	if rspStr == "" && e != nil {
		e.mu.Lock()
		wt := e.watch
		e.mu.Unlock()
		if wt != nil {
			if ctx := wt.Context(); ctx["rsp"] != "" {
				rspStr = ctx["rsp"]
			}
		}
	}
	rsp, err := parseAddr(rspStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "rsp required (fill RSP, or start a hardware watch so last RSP is known)")
		return
	}
	width := sess.PtrWidth()
	if width != 4 && width != 8 {
		width = 8
	}
	n := 32
	if q := r.URL.Query().Get("count"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 128 {
			n = v
		}
	}
	buf := make([]byte, n*width)
	got, err := sess.Read(rsp, buf)
	if err != nil || got < width {
		writeErr(w, http.StatusInternalServerError, "cannot read stack")
		return
	}
	type frame struct {
		SP    string `json:"sp"`
		Value string `json:"value"`
		Hint  string `json:"hint,omitempty"`
	}
	var frames []frame
	for i := 0; i+width <= got; i += width {
		var v uint64
		if width == 4 {
			v = uint64(binary.LittleEndian.Uint32(buf[i : i+4]))
		} else {
			v = binary.LittleEndian.Uint64(buf[i : i+8])
		}
		sp := rsp + uint64(i)
		hint := ""
		if e != nil {
			hint = moduleLabel(e.pid, v)
		}
		frames = append(frames, frame{SP: formatHex(sp), Value: formatHex(v), Hint: hint})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rsp": formatHex(rsp), "width": width, "frames": frames,
		"note": "用户态栈槽。先开硬件监视可自动带 RSP。VEH/内核调试未提供。",
	})
}

func (s *Server) memPtrMapSave(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	paths, err := sess.PointerPaths(100000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]ptrPathOut, 0, len(paths))
	for _, p := range paths {
		out = append(out, ptrPathOut{Base: formatHex(p.Base), Offsets: hexOffsets(p.Offsets)})
	}
	doc := map[string]any{"saved": time.Now().UTC().Format(time.RFC3339), "count": len(out), "paths": out}
	dir := filepath.Join(os.TempDir(), "capx")
	_ = os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, "ptrmap-"+r.PathValue("sid")+".json")
	if home, err := os.UserHomeDir(); err == nil {
		d := filepath.Join(home, ".capx")
		_ = os.MkdirAll(d, 0o700)
		path = filepath.Join(d, "ptrmap.json")
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "count": len(out)})
}

func (s *Server) memReattach(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	e := s.extFor(sid)
	if e == nil || e.pid == 0 {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	wantName := ""
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	wantName = strings.TrimSpace(body.Name)
	procs, _ := listProcesses()
	pid := e.pid
	alive := false
	for _, p := range procs {
		if p.PID == pid {
			alive = true
			if wantName == "" {
				wantName = p.Name
			}
			break
		}
	}
	if !alive && wantName == "" {
		writeErr(w, http.StatusConflict, fmt.Sprintf("pid %d 已退出，请在 body 里带 {\"name\":\"进程名\"} 以便按名称重附加", e.pid))
		return
	}
	if !alive {
		for _, p := range procs {
			if wantName != "" && strings.EqualFold(p.Name, wantName) {
				pid = p.PID
				alive = true
				break
			}
		}
	}
	if !alive {
		writeErr(w, http.StatusConflict, fmt.Sprintf("pid %d 已退出，且没有同名进程可重附加", e.pid))
		return
	}
	sess, err := s.scanner.Open(pid)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old, _ := s.session(sid)
	s.mu.Lock()
	if old != nil {
		_ = old.Close()
	}
	s.sessions[sid] = sess
	e.pid = pid
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"session": sid, "pid": pid, "reattached": true})
}
