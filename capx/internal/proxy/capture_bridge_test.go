package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hquip/capx/internal/store"
)

// fakeBridgeUpstream is a loopback-only forwarding proxy, not another Capx
// listener. Counters prove every captured request takes all three hops.
type fakeBridgeUpstream struct {
	server   *httptest.Server
	http     atomic.Int32
	connects atomic.Int32
	mu       sync.Mutex
	conns    map[net.Conn]bool
	tr       *http.Transport
}

func newFakeBridgeUpstream(t *testing.T) *fakeBridgeUpstream {
	t.Helper()
	u := &fakeBridgeUpstream{conns: map[net.Conn]bool{}, tr: &http.Transport{Proxy: nil}}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Hostname()
		if r.Method == http.MethodConnect {
			host, _, _ = net.SplitHostPort(r.Host)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "fixture only permits loopback origins", 403)
			return
		}
		if r.Method == http.MethodConnect {
			u.connects.Add(1)
			up, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			down, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				up.Close()
				return
			}
			u.mu.Lock()
			u.conns[up], u.conns[down] = true, true
			u.mu.Unlock()
			defer func() {
				down.Close()
				up.Close()
				u.mu.Lock()
				delete(u.conns, up)
				delete(u.conns, down)
				u.mu.Unlock()
			}()
			fmt.Fprint(down, "HTTP/1.1 200 Connection Established\r\n\r\n")
			copied := make(chan struct{})
			go func() { io.Copy(up, buffered); up.Close(); close(copied) }()
			io.Copy(down, up)
			down.Close()
			<-copied
			return
		}
		u.http.Add(1)
		r.RequestURI = ""
		r.Header.Set("X-Fixture-Upstream", "visited")
		resp, err := u.tr.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(resp.StatusCode)
		w.(http.Flusher).Flush()
		io.Copy(responseFlushWriter{w}, resp.Body)
	}))
	t.Cleanup(func() {
		u.mu.Lock()
		for conn := range u.conns {
			conn.Close()
		}
		u.mu.Unlock()
		u.tr.CloseIdleConnections()
		u.server.Close()
	})
	return u
}

func newBridgeProxy(t *testing.T) *Proxy {
	t.Helper()
	trustFixtureCA(t)
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	p, err := New(store.New(100))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.StopCaptureBridge(); p.tr.CloseIdleConnections(); p.trH2.CloseIdleConnections() })
	return p
}

func bridgeClient(t *testing.T, p *Proxy, upstream string, h2 bool) (*http.Client, string) {
	t.Helper()
	p.SetHTTP2Enabled(h2)
	addr, err := p.StartCaptureBridge(upstream)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://" + addr)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CA().CertPEM())
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: h2}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, addr
}

func waitBridgeHistory(t *testing.T, p *Proxy, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(p.st.ListHTTPTx("")) >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bridge traffic did not enter shared HTTP history")
}

func TestCaptureBridgeThreeHopHTTPAndHTTPS(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			upstream := newFakeBridgeUpstream(t)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if mode == "http" && r.Header.Get("X-Fixture-Upstream") != "visited" {
					http.Error(w, "bridge bypassed its upstream", 400)
					return
				}
				fmt.Fprintf(w, "%s:%s:%s:%s", r.Method, r.URL.Path, body, r.Header.Get("X-Capx-Rule"))
			}))
			if mode == "http" {
				origin.Start()
			} else {
				origin.EnableHTTP2 = mode == "h2"
				origin.StartTLS()
			}
			defer origin.Close()
			p := newBridgeProxy(t)
			originalH1, originalH2 := p.tr, p.trH2
			mustAdd(t, p.rules, &Rule{Enabled: true, Target: "request", Where: "header", Header: "X-Capx-Rule", Match: "^$", Replace: "shared"})
			mustAdd(t, p.rules, &Rule{Enabled: true, Target: "response", Where: "header", Header: "X-Bridge-Rule", Match: "^$", Replace: "shared"})
			client, addr := bridgeClient(t, p, upstream.server.URL, mode == "h2")
			resp, err := client.Post(origin.URL+"/three-hop", "text/plain", strings.NewReader("body"))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "POST:/three-hop:body:shared" || resp.Header.Get("X-Bridge-Rule") != "shared" {
				t.Fatalf("body=%q status=%d error=%v", body, resp.StatusCode, err)
			}
			if mode == "h2" && resp.ProtoMajor != 2 {
				t.Fatalf("not a real downstream HTTP/2 request: %s", resp.Proto)
			}
			if (mode == "http" && upstream.http.Load() != 1) || (mode != "http" && upstream.connects.Load() != 1) {
				t.Fatalf("upstream bypass: HTTP=%d CONNECT=%d", upstream.http.Load(), upstream.connects.Load())
			}
			waitBridgeHistory(t, p, 1)
			tx := p.st.ListHTTPTx("")[0]
			if !strings.Contains(tx.ReqRaw, "X-Capx-Rule: shared") || !strings.Contains(tx.RespRaw, "POST:/three-hop:body:shared") || tx.Decrypted != (mode != "http") {
				t.Fatalf("incorrect shared history: %+v", tx)
			}
			if p.tr != originalH1 || p.trH2 != originalH2 {
				t.Fatal("bridge replaced normal proxy transports")
			}
			if on, got, via := p.CaptureBridgeStatus(); !on || got != addr || via != upstream.server.URL {
				t.Fatalf("bridge status: %v %s %s", on, got, via)
			}
		})
	}
}

func TestCaptureBridgeEditedRequestKeepsUpstreamContext(t *testing.T) {
	upstream := newFakeBridgeUpstream(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	defer origin.Close()
	p := newBridgeProxy(t)
	client, _ := bridgeClient(t, p, upstream.server.URL, false)
	p.SetInterceptEnabled(true)
	result := make(chan error, 1)
	go func() {
		resp, err := client.Post(origin.URL+"/edited", "text/plain", strings.NewReader("old"))
		if err == nil {
			defer resp.Body.Close()
			body, e := io.ReadAll(resp.Body)
			if e != nil || string(body) != "new" {
				err = fmt.Errorf("body=%q error=%v", body, e)
			}
		}
		result <- err
	}()
	held := waitForHeld(t, p)
	u, _ := url.Parse(origin.URL)
	p.icept.Decide(held.ID, fmt.Sprintf("POST /edited HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\n\r\nnew", u.Host), false)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if upstream.connects.Load() != 1 {
		t.Fatal("intercept edit lost routing context and connected directly")
	}
}

func TestCaptureBridgeRejectsUnsafeUpstreamsAndLoops(t *testing.T) {
	p := newBridgeProxy(t)
	for _, raw := range []string{"", "127.0.0.1:7897", "https://127.0.0.1:7897", "socks5://127.0.0.1:7897", "http://example.com:80", "http://192.168.1.1:80", "http://user:secret@127.0.0.1:7897", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:7897/path", "http://127.0.0.1:7897?x=y", "http://127.0.0.1:7897#x"} {
		if _, err := p.StartCaptureBridge(raw); err == nil {
			t.Errorf("unsafe upstream accepted: %q", raw)
			p.StopCaptureBridge()
		}
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if err := p.StartTransparent("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.StopTransparent()
	_, explicit := p.Status()
	_, transparent := p.TransparentStatus()
	for _, addr := range []string{explicit, transparent} {
		if _, err := p.StartCaptureBridge("http://" + addr); err == nil {
			t.Fatalf("self upstream accepted: %s", addr)
		}
	}
	upstream := newFakeBridgeUpstream(t)
	client, addr := bridgeClient(t, p, upstream.server.URL, false)
	if same, err := p.StartCaptureBridge(upstream.server.URL); err != nil || same != addr {
		t.Fatalf("idempotent start = %q %v", same, err)
	}
	if _, err := p.StartCaptureBridge("http://" + addr); err == nil {
		t.Fatal("active bridge was accepted as its own upstream")
	}
	for _, target := range []string{addr, explicit, transparent, strings.TrimPrefix(upstream.server.URL, "http://")} {
		resp, err := client.Get("http://" + target + "/loop")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 502 {
			t.Fatalf("loop target %s returned %d", target, resp.StatusCode)
		}
	}
	if upstream.http.Load() != 0 || upstream.connects.Load() != 0 {
		t.Fatal("loop request escaped bridge guards")
	}
	if err := p.StopCaptureBridge(); err != nil {
		t.Fatal(err)
	}
	if err := p.StopCaptureBridge(); err != nil {
		t.Fatal("stop is not idempotent:", err)
	}
}

func TestCaptureBridgeLargeBodiesAndSSE(t *testing.T) {
	SetMaxBodyCapture(1024)
	defer SetMaxBodyCapture(0)
	payload := bytes.Repeat([]byte("B"), maxEditableBody+1234)
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			upstream := newFakeBridgeUpstream(t)
			release := make(chan struct{})
			defer close(release)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/events" {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: first\n\n")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
					return
				}
				n, err := io.Copy(io.Discard, r.Body)
				if err != nil || n != int64(len(payload)) {
					http.Error(w, fmt.Sprintf("upload=%d error=%v", n, err), 400)
					return
				}
				w.Write(payload)
			}))
			origin.EnableHTTP2 = h2
			origin.StartTLS()
			t.Cleanup(origin.Close)
			p := newBridgeProxy(t)
			client, _ := bridgeClient(t, p, upstream.server.URL, h2)
			resp, err := client.Post(origin.URL+"/large", "application/octet-stream", io.NopCloser(bytes.NewReader(payload)))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, payload) {
				t.Fatalf("large bridged body=%d error=%v", len(body), err)
			}
			waitBridgeHistory(t, p, 1)
			tx := p.st.ListHTTPTx("")[0]
			if !tx.BodyTruncated || len(tx.ReqRaw)+len(tx.RespRaw) > 4096 || tx.RespLen != len(payload) {
				t.Fatal("bridge history limit affected real body")
			}
			resp, err = client.Get(origin.URL + "/events")
			if err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(resp.Body).ReadString('\n')
			resp.Body.Close()
			if err != nil || line != "data: first\n" {
				t.Fatalf("SSE did not stream before origin close: %q %v", line, err)
			}
		})
	}
}

func TestCaptureBridgeStopCancelsOwnedConnectionsOnly(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			upstream := newFakeBridgeUpstream(t)
			closed := make(chan struct{})
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: open\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(closed)
			}))
			origin.EnableHTTP2 = h2
			origin.StartTLS()
			t.Cleanup(origin.Close)
			p := newBridgeProxy(t)
			client, addr := bridgeClient(t, p, upstream.server.URL, h2)
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(resp.Body)
			if _, err := reader.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if err := p.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.Stop()
			if err := p.StartTransparent("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.StopTransparent()
			if err := p.StopCaptureBridge(); err != nil {
				t.Fatal(err)
			}
			if on, _, _ := p.CaptureBridgeStatus(); on {
				t.Fatal("bridge still running")
			}
			if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				conn.Close()
				t.Fatal("stopped bridge listener is still open")
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("bridge stop left CONNECT upstream/origin alive")
			}
			io.Copy(io.Discard, reader)
			resp.Body.Close()
			plainOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "still-alive") }))
			defer plainOrigin.Close()
			_, explicit := p.Status()
			_, transparent := p.TransparentStatus()
			for _, listener := range []string{explicit, transparent} {
				u, _ := url.Parse("http://" + listener)
				tr := &http.Transport{Proxy: http.ProxyURL(u)}
				ordinary := &http.Client{Transport: tr, Timeout: 2 * time.Second}
				r, err := ordinary.Get(plainOrigin.URL)
				if err != nil {
					t.Fatal("bridge stop damaged another listener:", err)
				}
				body, err := io.ReadAll(r.Body)
				r.Body.Close()
				tr.CloseIdleConnections()
				if err != nil || string(body) != "still-alive" {
					t.Fatalf("other listener body=%q error=%v", body, err)
				}
			}
			if upstream.http.Load() != 0 {
				t.Fatal("normal listeners inherited the capture bridge upstream")
			}
		})
	}
}

func TestCaptureBridgeWebSocketsNeverBypassUpstream(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			upstream := newFakeBridgeUpstream(t)
			origin, hits := routedWSOrigin(t, secure)
			p := newBridgeProxy(t)
			_, addr := bridgeClient(t, p, upstream.server.URL, false)
			socket := routedWSClient(t, p, addr, origin.URL)
			assertWSEcho(t, socket, "through-capture-bridge")
			if hits.Load() != 1 || upstream.connects.Load() != 1 {
				t.Fatalf("WS bypassed configured bridge: origin=%d CONNECT=%d", hits.Load(), upstream.connects.Load())
			}
		})
	}
	upstream := newFakeBridgeUpstream(t)
	origin, hits := routedWSOrigin(t, true)
	p := newBridgeProxy(t)
	if _, err := p.StartCaptureBridge(upstream.server.URL); err != nil {
		t.Fatal(err)
	}
	p.bridgeMu.Lock()
	ctx := p.bridge.ctx
	p.bridgeMu.Unlock()
	request, _ := http.NewRequestWithContext(ctx, "CONNECT", origin.URL+"/h2ws", nil)
	request.Header.Set("Protocol", "websocket")
	response := httptest.NewRecorder()
	p.tunnelH2WebSocket(response, request, request.Host)
	if response.Code != 200 || hits.Load() != 1 || upstream.connects.Load() != 1 {
		t.Fatalf("H2 WS bridge bypassed route: status=%d origin=%d connects=%d", response.Code, hits.Load(), upstream.connects.Load())
	}
}
func TestCaptureBridgeStopCancelsHeldRequests(t *testing.T) {
	upstream := newFakeBridgeUpstream(t)
	p := newBridgeProxy(t)
	client, _ := bridgeClient(t, p, upstream.server.URL, false)
	p.SetInterceptEnabled(true)
	done := make(chan struct{})
	go func() {
		resp, _ := client.Get("http://127.0.0.1:1/never-forward")
		if resp != nil {
			resp.Body.Close()
		}
		close(done)
	}()
	waitForHeld(t, p)
	if err := p.StopCaptureBridge(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("held request did not cancel when bridge stopped")
	}
	deadline := time.Now().Add(time.Second)
	for len(p.icept.Queue()) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(p.icept.Queue()) != 0 || upstream.http.Load() != 0 {
		t.Fatal("stopped bridge retained an interception or forwarded it")
	}
}

func TestCaptureBridgeReportsTLSAndUpstreamErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
	}))
	defer upstream.Close()
	p := newBridgeProxy(t)
	client, addr := bridgeClient(t, p, upstream.URL, false)
	for _, target := range []string{"http://127.0.0.1:1/fail", "https://127.0.0.1:1/fail"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	proxyURL, _ := url.Parse("http://" + addr)
	// Empty trust roots intentionally reject only our local test CA.
	badTLS := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	defer badTLS.CloseIdleConnections()
	_, err := (&http.Client{Transport: badTLS, Timeout: 2 * time.Second}).Get("https://127.0.0.1:1/certificate-test")
	if err == nil {
		t.Fatal("untrusted bridge certificate unexpectedly accepted")
	}
	deadline := time.Now().Add(time.Second)
	stages := map[string]bool{}
	for time.Now().Before(deadline) {
		for _, ev := range p.st.Recent() {
			if ev.Kind == "capture_bridge_error" {
				if data, ok := ev.Data.(map[string]string); ok {
					stages[data["stage"]] = true
				}
			}
		}
		if stages["client_tls"] && stages["upstream"] && stages["upstream_http"] {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("missing bridge diagnostics: %v", stages)
}
