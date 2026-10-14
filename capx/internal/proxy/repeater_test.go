package proxy

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// rawGet builds a minimal raw GET request for path on host.
func rawGet(host, path string) string {
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: capx-test\r\n\r\n", path, host)
}

func TestSendRawNoFollowReturnsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dst", http.StatusFound)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	res := SendRawOpts("http", host, rawGet(host, "/src"), false)
	if res.Error != "" {
		t.Fatalf("err: %s", res.Error)
	}
	if res.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.Status)
	}
	if len(res.Redirects) != 0 {
		t.Fatalf("redirects should be empty when follow=false, got %v", res.Redirects)
	}
}

func TestSendRawFollowsRedirectChain(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusMovedPermanently)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		case "/c":
			fmt.Fprint(w, "arrived")
		default:
			http.Error(w, "no", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	res := SendRawOpts("http", host, rawGet(host, "/a"), true)
	if res.Error != "" {
		t.Fatalf("err: %s", res.Error)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if len(res.Redirects) != 2 {
		t.Fatalf("hops = %d, want 2 (%+v)", len(res.Redirects), res.Redirects)
	}
	if !strings.Contains(res.RespRaw, "arrived") {
		t.Fatalf("final body missing: %q", res.RespRaw)
	}
	if u, _ := url.Parse(res.FinalURL); u == nil || u.Path != "/c" {
		t.Fatalf("final url = %q, want path /c", res.FinalURL)
	}
}

func TestSendRaw303PostBecomesGet(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/submit" {
			http.Redirect(w, r, "/done", http.StatusSeeOther)
			return
		}
		gotMethod = r.Method
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	raw := fmt.Sprintf("POST /submit HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc", host)
	res := SendRawOpts("http", host, raw, true)
	if res.Error != "" {
		t.Fatalf("err: %s", res.Error)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("after 303 the follow-up method = %q, want GET", gotMethod)
	}
}

func TestSendRawRendersGzipDecompressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("hello-gzip-body"))
		_ = gz.Close()
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	res := SendRawOpts("http", host, rawGet(host, "/"), false)
	if res.Error != "" {
		t.Fatalf("err: %s", res.Error)
	}
	if !strings.Contains(res.RespRaw, "hello-gzip-body") {
		t.Fatalf("gzip body not decompressed for display: %q", res.RespRaw)
	}
}

func TestSendRawHTTP2(t *testing.T) {
	srv := startH2Server(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s", r.Proto)
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := SendRawOpts("https", u.Host, rawGet(u.Host, "/h2"), false)
	if res.Error != "" {
		t.Fatalf("err: %s", res.Error)
	}
	if res.Status != 200 {
		t.Fatalf("status=%d raw=%s", res.Status, res.RespRaw)
	}
	if !strings.Contains(res.RespRaw, "HTTP/2") && !strings.Contains(res.RespRaw, "proto=HTTP/2.0") {
		t.Fatalf("expected HTTP/2 response, got %q", res.RespRaw)
	}
}
