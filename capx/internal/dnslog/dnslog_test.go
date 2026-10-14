package dnslog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hquip/capx/internal/store"
)

// fakePlatform is a minimal stand-in for the DNSLog platform exposing the three
// endpoints the client uses, gated on the X-API-Key header.
type fakePlatform struct {
	apiKey  string
	hits    atomic.Bool // when true, /check reports the subdomain was hit
	checked atomic.Int32
}

func (f *fakePlatform) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-Key") != f.apiKey {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/api/v1/summary", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dns_total":1}`))
	}))
	mux.HandleFunc("/api/v1/dnslog/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"logs":[],"total":0,"page":1,"page_size":20}`))
	}))
	mux.HandleFunc("/api/v1/dnslog/subdomain", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"subdomain":"abc123","domain":"log.test","full_domain":"abc123.log.test","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	mux.HandleFunc("/api/v1/dnslog/check", auth(func(w http.ResponseWriter, r *http.Request) {
		f.checked.Add(1)
		if f.hits.Load() {
			_, _ = w.Write([]byte(`{"subdomain":"abc123","received":true,"dns_count":1,"http_count":0,"total":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"subdomain":"abc123","received":false,"dns_count":0,"http_count":0,"total":0}`))
	}))
	return mux
}

func TestConfigureAndSummary(t *testing.T) {
	fp := &fakePlatform{apiKey: "secret-key"}
	srv := httptest.NewServer(fp.handler())
	defer srv.Close()

	c := New(store.New(10), "")

	// Unconfigured calls fail fast without touching the network.
	if _, err := c.Summary(context.Background()); err == nil {
		t.Fatal("expected error when unconfigured")
	}
	if c.Status(context.Background()).Configured {
		t.Fatal("should not be configured yet")
	}

	if err := c.Configure(srv.URL, "secret-key"); err != nil {
		t.Fatalf("configure: %v", err)
	}
	st := c.Status(context.Background())
	if !st.Configured || !st.APIKeySet || !st.Reachable {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Error != "" {
		t.Fatalf("unexpected error: %s", st.Error)
	}

	// Wrong key surfaces as unreachable, not a panic.
	if err := c.Configure(srv.URL, "wrong"); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if st := c.Status(context.Background()); st.Reachable {
		t.Fatal("should be unreachable with wrong key")
	}
}

func TestNewPayloadCheckAndHitEvent(t *testing.T) {
	fp := &fakePlatform{apiKey: "k"}
	srv := httptest.NewServer(fp.handler())
	defer srv.Close()

	st := store.New(10)
	sub, unsub := st.Subscribe(8)
	defer unsub()

	c := New(st, "")
	if err := c.Configure(srv.URL, "k"); err != nil {
		t.Fatalf("configure: %v", err)
	}

	p, err := c.NewPayload(context.Background(), "", "login ssrf")
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}
	if p.FullDomain != "abc123.log.test" || p.Note != "login ssrf" {
		t.Fatalf("unexpected payload: %+v", p)
	}
	if got := c.Payloads(); len(got) != 1 || got[0].Subdomain != "abc123" {
		t.Fatalf("payload not tracked: %+v", got)
	}

	// No hit yet: received=false, no event published.
	res, err := c.Check(context.Background(), "abc123", "all", 0, 20)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Received {
		t.Fatal("should not be received yet")
	}

	// Flip the platform to report a hit; the next check must publish exactly one
	// dnslog_hit event andk the payload received.
	fp.hits.Store(true)
	if _, err := c.Check(context.Background(), "abc123", "all", 0, 20); err != nil {
		t.Fatalf("check: %v", err)
	}
	select {
	case ev := <-sub:
		if ev.Kind != "dnslog_hit" || ev.Source != "dnslog" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("expected a dnslog_hit event")
	}
	if got := c.Payloads(); !got[0].Received || got[0].DNSCount != 1 {
		t.Fatalf("payload hit state not updated: %+v", got[0])
	}

	// Forgetting removes local tracking.
	if !c.Forget("abc123") {
		t.Fatal("forget should succeed")
	}
	if len(c.Payloads()) != 0 {
		t.Fatal("payload should be gone")
	}
}

func TestPersistence(t *testing.T) {
	fp := &fakePlatform{apiKey: "k"}
	srv := httptest.NewServer(fp.handler())
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "dnslog.json")
	c1 := New(store.New(10), path)
	if err := c1.Configure(srv.URL, "k"); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if _, err := c1.NewPayload(context.Background(), "", "x"); err != nil {
		t.Fatalf("new payload: %v", err)
	}

	// A fresh client over the same file restores config + payloads.
	c2 := New(store.New(10), path)
	if !c2.configured() {
		t.Fatal("config not restored")
	}
	if got := c2.Payloads(); len(got) != 1 || got[0].Subdomain != "abc123" {
		t.Fatalf("payloads not restored: %+v", got)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"example.com":          "https://example.com",
		"example.com/":         "https://example.com",
		"http://h:8080/":       "http://h:8080",
		"  https://x.io/api  ": "https://x.io/api",
		"":                     "",
	}
	for in, want := range cases {
		if got := normalizeBaseURL(in); got != want {
			t.Errorf("normalizeBaseURL(%q)=%q want %q", in, got, want)
		}
	}
}
