package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/store"
)

// startH2Server starts an httptest TLS server with HTTP/2 enabled.
func startH2Server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	trustFixtureCA(t)
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestUpstreamTransportNegotiatesHTTP2(t *testing.T) {
	srv := startH2Server(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s", r.Proto)
	})

	tr := newUpstreamTransport(true)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("ProtoMajor = %d, want 2 (proto %q)", resp.ProtoMajor, resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proto=HTTP/2.0" {
		t.Fatalf("server saw %q, want proto=HTTP/2.0", string(body))
	}
}

func TestUpstreamTransportHTTP1Default(t *testing.T) {
	srv := startH2Server(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s", r.Proto)
	})

	// The HTTP/1.1 transport must NOT upgrade even against an h2-capable server.
	tr := newUpstreamTransport(false)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("ProtoMajor = %d, want 1 (proto %q)", resp.ProtoMajor, resp.Proto)
	}
}

// TestDownstreamHTTP2 drives a real HTTP/2 client through the capx MITM proxy
// (CONNECT + ALPN h2) to an h2 upstream, asserting the client<->capx hop is
// HTTP/2 (i.e. capx served h2 downstream, not just upstream) and the request
// was proxied and recorded.
func TestDownstreamHTTP2(t *testing.T) {
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	upstream := startH2Server(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s path=%s", r.Proto, r.URL.Path)
	})

	p, err := New(store.New(100))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.SetHTTP2Enabled(true) // advertise h2 downstream + use h2 upstream
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Stop()
	_, paddr := p.Status()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CA().CertPEM()) {
		t.Fatal("could not load capx CA")
	}
	proxyURL, _ := url.Parse("http://" + paddr)
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	resp, err := client.Get(upstream.URL + "/h2path")
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("client<->capx proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "path=/h2path") {
		t.Fatalf("unexpected body %q", string(body))
	}
	// The transaction should have been recorded by the proxy.
	if len(p.st.ListHTTPTx("")) == 0 {
		t.Fatal("no HTTP tx recorded for downstream h2 request")
	}
}

// TestTransparentPlainInterception connects straight to the inline listener (no
// CONNECT, as an OS redirect would), and verifies capx recovers the destination
// from the Host header, proxies to the upstream, and records the transaction.
// (The TLS inline path shares serveDecryptedHTTP, exercised by the h2 tests; it
// routes by SNI, which cannot carry a port, so this covers the plain path.)
func TestTransparentPlainInterception(t *testing.T) {
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok path=%s host=%s", r.URL.Path, r.Host)
	}))
	defer upstream.Close()
	upHost := strings.TrimPrefix(upstream.URL, "http://")

	p, err := New(store.New(100))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := p.StartTransparent("127.0.0.1:0"); err != nil {
		t.Fatalf("start transparent: %v", err)
	}
	defer p.StopTransparent()
	_, taddr := p.TransparentStatus()

	conn, err := net.Dial("tcp", taddr)
	if err != nil {
		t.Fatalf("dial inline: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "GET /inline HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upHost); err != nil {
		t.Fatalf("write req: %v", err)
	}
	raw, _ := io.ReadAll(conn) // Connection: close => read to EOF
	resp := string(raw)
	if !contains(resp, "path=/inline") {
		t.Fatalf("unexpected inline response: %q", resp)
	}
	if len(p.st.ListHTTPTx("")) == 0 {
		t.Fatal("transparent request not recorded")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestProxyTransportToggle(t *testing.T) {
	p := &Proxy{tr: newUpstreamTransport(false), trH2: newUpstreamTransport(true)}
	if p.HTTP2Enabled() {
		t.Fatal("http2 should default off")
	}
	if p.transport() != p.tr {
		t.Fatal("default transport should be the HTTP/1.1 one")
	}
	p.SetHTTP2Enabled(true)
	if !p.HTTP2Enabled() || p.transport() != p.trH2 {
		t.Fatal("after enabling, transport should be the HTTP/2 one")
	}
}
