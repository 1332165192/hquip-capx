package api

// Collaborator-lite: a minimal HTTP out-of-band callback catcher. It binds a
// listener that records every incoming request; testers embed a unique token in
// a payload URL (http://<oob-host>:<port>/<token>) so blind SSRF / XXE / RCE
// callbacks show up here. DNS OOB is covered separately by the DNSLog client.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

type oobHit struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
	Remote string `json:"remote"`
	UA     string `json:"ua"`
	Body   string `json:"body,omitempty"`
}

type oobCatcher struct {
	mu      sync.Mutex
	hits    []oobHit
	srv     *http.Server
	addr    string
	running bool
}

func newOOBCatcher() *oobCatcher { return &oobCatcher{} }

func (c *oobCatcher) record(r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	c.mu.Lock()
	c.hits = append(c.hits, oobHit{
		Time: time.Now().Format("2006-01-02 15:04:05"), Method: r.Method,
		Path: r.URL.RequestURI(), Host: r.Host, Remote: r.RemoteAddr,
		UA: r.UserAgent(), Body: string(body),
	})
	if len(c.hits) > 1000 {
		c.hits = c.hits[len(c.hits)-1000:]
	}
	c.mu.Unlock()
}

func (c *oobCatcher) start(addr string) error {
	c.mu.Lock()
	if c.running {
		a := c.addr
		c.mu.Unlock()
		return fmt.Errorf("OOB 捕获器已在运行: %s", a)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.Header().Set("Server", "capx-oob")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("capx-oob ok\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	c.srv = srv
	c.addr = addr
	c.running = true
	c.mu.Unlock()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.mu.Lock()
			c.running = false
			c.mu.Unlock()
		}
	}()
	return nil
}

func (c *oobCatcher) stop() {
	c.mu.Lock()
	srv := c.srv
	c.running = false
	c.srv = nil
	c.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func oobToken() string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = cs[rand.Intn(len(cs))]
	}
	return string(b)
}

func (s *Server) oobStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Addr) == "" {
		req.Addr = "0.0.0.0:8088"
	}
	if err := s.oob.start(req.Addr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"running": true, "addr": req.Addr})
}

func (s *Server) oobStop(w http.ResponseWriter, r *http.Request) {
	s.oob.stop()
	writeJSON(w, http.StatusOK, map[string]any{"running": false})
}

func (s *Server) oobStatus(w http.ResponseWriter, r *http.Request) {
	s.oob.mu.Lock()
	running, addr, n := s.oob.running, s.oob.addr, len(s.oob.hits)
	s.oob.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"running": running, "addr": addr, "hits": n})
}

func (s *Server) oobHits(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	s.oob.mu.Lock()
	out := make([]oobHit, 0, len(s.oob.hits))
	for _, h := range s.oob.hits {
		if tok == "" || strings.Contains(h.Path, tok) || strings.Contains(h.Host, tok) {
			out = append(out, h)
		}
	}
	s.oob.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"hits": out, "count": len(out)})
}

func (s *Server) oobPayload(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"token": oobToken()})
}
