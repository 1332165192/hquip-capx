package proxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func routedWSOrigin(t *testing.T, secure bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked to WS origin")
		}
		socket, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer socket.Close()
		hash := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(socket, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(hash[:]))
		for {
			_, opcode, payload, err := readWSFrame(buffered.Reader)
			if err != nil {
				return
			}
			if opcode == 8 {
				return
			}
			if _, err = socket.Write(buildWSFrame(opcode, payload, false)); err != nil {
				return
			}
		}
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server, hits
}
func routedWSClient(t *testing.T, p *Proxy, proxyAddr, target string) io.ReadWriteCloser {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.CA().CertPEM())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	request, _ := http.NewRequest(http.MethodGet, target+"/socket", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	request = request.WithContext(ctx)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	request.Header.Set("Sec-WebSocket-Version", "13")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("WS handshake status=%d body=%s", response.StatusCode, body)
	}
	socket, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		response.Body.Close()
		t.Fatal("WS upgrade has no writable tunnel")
	}
	t.Cleanup(func() { socket.Close() })
	return socket
}
func assertWSEcho(t *testing.T, socket io.ReadWriteCloser, text string) {
	t.Helper()
	if _, err := socket.Write(buildWSFrame(1, []byte(text), true)); err != nil {
		t.Fatal(err)
	}
	_, _, payload, err := readWSFrame(bufio.NewReader(socket))
	if err != nil || string(payload) != text {
		t.Fatalf("WS echo=%q err=%v", payload, err)
	}
}
func TestRoutedWebSocketUpgradeReplayAndMacrosUseSelectedProxy(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			p := newBridgeProxy(t)
			upstream := newFakeBridgeUpstream(t)
			origin, hits := routedWSOrigin(t, secure)
			if err := p.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.Stop()
			if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: upstream.server.URL}); err != nil {
				t.Fatal(err)
			}
			_, addr := p.Status()
			socket := routedWSClient(t, p, addr, origin.URL)
			assertWSEcho(t, socket, "through-selected-upstream")
			if upstream.connects.Load() != 1 || hits.Load() != 1 {
				t.Fatalf("WS bypassed secondary: CONNECT=%d origin=%d", upstream.connects.Load(), hits.Load())
			}
			connections := p.WSConns()
			if len(connections) != 1 {
				t.Fatal("WS not registered", connections)
			}
			if _, err := p.ReplayWS(connections[0].ID, "send", "text", "manual-replay"); err != nil {
				t.Fatal(err)
			}
			_, _, payload, err := readWSFrame(bufio.NewReader(socket))
			if err != nil || string(payload) != "manual-replay" {
				t.Fatal("replay not forwarded", string(payload), err)
			}
			if upstream.connects.Load() != 1 {
				t.Fatal("manual replay unexpectedly opened another direct socket")
			}
			if err := p.SetUpstream(UpstreamConfig{}); err != nil {
				t.Fatal(err)
			}
			if len(p.WSConns()) != 0 {
				t.Fatal("route change retained old WS sockets")
			}
			if _, err := p.ReplayWS(connections[0].ID, "send", "text", "must-not-bypass-new-route"); err == nil {
				t.Fatal("old route replay survived a route change")
			}
		})
	}
}
func TestRoutedRepeaterAndHTTPSProxyCredentialsRemainPrivate(t *testing.T) {
	for _, proxyTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(proxyTLS), func(t *testing.T) {
			p := newBridgeProxy(t)
			forwarder := newFakeBridgeUpstream(t)
			const user = "fixture-proxy-user"
			const password = "fixture-proxy-password"
			var authSeen atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
				if r.Header.Get("Proxy-Authorization") != want {
					http.Error(w, "authentication required", 407)
					return
				}
				authSeen.Add(1)
				forwarder.server.Config.Handler.ServeHTTP(w, r)
			})
			var secondary *httptest.Server
			if proxyTLS {
				secondary = httptest.NewTLSServer(handler)
			} else {
				secondary = httptest.NewServer(handler)
			}
			defer secondary.Close()
			configPath := filepath.Join(t.TempDir(), "proxy.json")
			p.UseConfigPath(configPath)
			if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: secondary.URL, Username: user, Password: password}); err != nil {
				t.Fatal(err)
			}
			if proxyTLS {
				pool := x509.NewCertPool()
				pool.AddCert(secondary.Certificate())
				route := p.upstream.Load()
				route.tr.TLSClientConfig.RootCAs = pool
				route.trH2.TLSClientConfig.RootCAs = pool
			}
			var originAuthLeak atomic.Bool
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					originAuthLeak.Store(true)
				}
				fmt.Fprint(w, "routed-origin")
			}))
			defer origin.Close()
			parsed, _ := url.Parse(origin.URL)
			result := p.SendRawTLS("http", parsed.Host, rawGet(parsed.Host, "/repeater"), false, nil)
			if result.Error != "" || result.Status != 200 || !strings.Contains(result.RespRaw, "routed-origin") || authSeen.Load() != 1 || forwarder.connects.Load() != 1 {
				t.Fatalf("repeater didn't use authenticated route: %+v auth=%d connects=%d", result, authSeen.Load(), forwarder.connects.Load())
			}
			p.Session().SetMacros([]Macro{{Name: "fixture-session", Steps: []MacroStep{{Scheme: "http", Host: parsed.Host, Raw: rawGet(parsed.Host, "/macro")}}}})
			run, err := p.Session().RunMacroByName("fixture-session")
			if err != nil || len(run.Steps) != 1 || run.Steps[0].Status != 200 || authSeen.Load() != 2 {
				t.Fatalf("macro bypassed shared route: %+v %v auth=%d", run, err, authSeen.Load())
			}
			serialized, _ := json.Marshal(p.ExportConfig())
			saved, _ := os.ReadFile(configPath)
			public, _ := json.Marshal(p.UpstreamConfig())
			for _, raw := range [][]byte{serialized, saved, public} {
				if strings.Contains(string(raw), user) || strings.Contains(string(raw), password) {
					t.Fatal("proxy credentials persisted or exposed")
				}
			}
			if originAuthLeak.Load() {
				t.Fatal("proxy authorization reached the origin")
			}
			p.loadConfig(configPath)
			if !p.UpstreamConfig().CredentialsMissing {
				t.Fatal("restart silently dropped credential requirement")
			}
			if result := p.SendRawTLS("http", parsed.Host, rawGet(parsed.Host, "/after-restart"), false, nil); result.Error == "" {
				t.Fatal("missing runtime credentials allowed a request")
			}
			if authSeen.Load() != 2 {
				t.Fatal("credential-missing route still dialed")
			}
		})
	}
}
func TestRoutedFailureAndProxyLoopNeverFallBackDirect(t *testing.T) {
	p := newBridgeProxy(t)
	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originHits.Add(1); fmt.Fprint(w, "must-not-be-visited") }))
	defer origin.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "proxy refused", http.StatusForbidden) }))
	defer secondary.Close()
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: secondary.URL}); err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(origin.URL)
	if result := p.SendRawTLS("http", target.Host, rawGet(target.Host, "/"), false, nil); result.Error == "" || !strings.Contains(result.Error, "403") {
		t.Fatalf("CONNECT failure ignored: %+v", result)
	}
	if originHits.Load() != 0 {
		t.Fatal("failed route bypassed to origin")
	}
	proxyURL, _ := url.Parse(secondary.URL)
	if _, err := p.dialRoutedTarget(context.Background(), "ws", proxyURL.Host, nil); err == nil {
		t.Fatal("loop into selected proxy accepted")
	}
}
func TestRoutedRedirectDropsOriginCredentialsAcrossHosts(t *testing.T) {
	p := newBridgeProxy(t)
	upstream := newFakeBridgeUpstream(t)
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: upstream.server.URL}); err != nil {
		t.Fatal(err)
	}
	var leaked atomic.Bool
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			leaked.Store(true)
		}
		fmt.Fprint(w, "redirected")
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, second.URL, http.StatusFound) }))
	defer first.Close()
	parsed, _ := url.Parse(first.URL)
	raw := "GET / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nAuthorization: Bearer private-origin-token\r\nCookie: session=private\r\n\r\n"
	result := p.SendRawTLS("http", parsed.Host, raw, true, nil)
	if result.Error != "" || result.Status != 200 || upstream.connects.Load() != 2 || leaked.Load() {
		t.Fatalf("redirect route/privacy failure: %+v connections=%d leaked=%v", result, upstream.connects.Load(), leaked.Load())
	}
}
