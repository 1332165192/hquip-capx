package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalUpstreamHTTPAndHTTPS(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			up := newFakeBridgeUpstream(t)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Path) }))
			if mode == "http" {
				origin.Start()
			} else {
				origin.EnableHTTP2 = mode == "h2"
				origin.StartTLS()
			}
			defer origin.Close()
			p := newBridgeProxy(t)
			p.SetHTTP2Enabled(mode == "h2")
			if err := p.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.Stop()
			if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: up.server.URL}); err != nil {
				t.Fatal(err)
			}
			_, addr := p.Status()
			proxyURL, _ := url.Parse("http://" + addr)
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(p.CA().CertPEM())
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: mode == "h2"}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr}
			resp, err := client.Get(origin.URL + "/routed")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || string(body) != "/routed" {
				t.Fatalf("status=%d body=%s", resp.StatusCode, body)
			}
			if mode == "http" && up.http.Load() != 1 || mode != "http" && up.connects.Load() != 1 {
				t.Fatal("request bypassed secondary proxy")
			}
			tr.CloseIdleConnections()
			if err := p.SetUpstream(UpstreamConfig{}); err != nil {
				t.Fatal(err)
			}
			resp, err = client.Get(origin.URL + "/restored")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if mode == "http" && up.http.Load() != 1 || mode != "http" && up.connects.Load() != 1 {
				t.Fatal("disabled secondary route still forwarded")
			}
		})
	}
}

func TestGlobalUpstreamValidationAndPersistence(t *testing.T) {
	p := newBridgeProxy(t)
	path := filepath.Join(t.TempDir(), "proxy.json")
	p.UseConfigPath(path)
	valid := UpstreamConfig{Enabled: true, URL: "http://localhost:18888"}
	if err := p.SetUpstream(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://user:secret@127.0.0.1:8080", "http://example.com:8080", "socks5://127.0.0.1:8080", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?q=secret", "http://127.0.0.1", "http://127.0.0.1:0"} {
		if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: raw}); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	_, own := p.Status()
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: "http://" + own}); err == nil {
		t.Fatal("accepted own listener")
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:18888/", nil)
	if _, err := p.selectUpstream(req); err == nil {
		t.Fatal("accepted target proxy loop")
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "secret") {
		t.Fatal("credential persisted")
	}
	p.loadConfig(path)
	if cfg := p.UpstreamConfig(); cfg.URL != "http://127.0.0.1:18888" || !cfg.Enabled {
		t.Fatalf("not restored: %#v", cfg)
	}
	p.persistPath = t.TempDir() // Cannot atomically replace a directory with config.
	if err := p.SetUpstream(UpstreamConfig{}); err == nil || !p.UpstreamConfig().Enabled {
		t.Fatal("failed save changed route")
	}
}

func TestGlobalUpstreamErrorsNeverBypassAndRejectUntrustedTLSProxy(t *testing.T) {
	p := newBridgeProxy(t)
	up := newFakeBridgeUpstream(t)
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: up.server.URL}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:1/ws", nil)
	if result := p.SendRawTLS("http", r.Host, rawGet(r.Host, "/ws"), false, nil); result.Error == "" || up.connects.Load() != 1 {
		t.Fatal("failed CONNECT bypassed selected route", result, up.connects.Load())
	}
	tlsProxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted proxy was reached") }))
	defer tlsProxy.Close()
	p.tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	p.trH2.TLSClientConfig.RootCAs = x509.NewCertPool()
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: tlsProxy.URL}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "http://127.0.0.1:1/", nil)
	r.RequestURI = ""
	if _, err := p.transport().RoundTrip(r); err == nil {
		t.Fatal("untrusted HTTPS secondary proxy accepted")
	}
}

func TestGlobalUpstreamTrustedHTTPSProxy(t *testing.T) {
	for _, originTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(originTLS), func(t *testing.T) {
			up := newFakeBridgeUpstream(t)
			tlsUp := httptest.NewTLSServer(up.server.Config.Handler)
			defer tlsUp.Close()
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "trusted-secondary") }))
			if originTLS {
				origin.StartTLS()
			} else {
				origin.Start()
			}
			defer origin.Close()
			p := newBridgeProxy(t)
			if err := p.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.Stop()
			if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: tlsUp.URL}); err != nil {
				t.Fatal(err)
			}
			// Fixture trust is scoped to these in-memory transports; no OS trust store is changed.
			secondaryRoots := x509.NewCertPool()
			secondaryRoots.AddCert(tlsUp.Certificate())
			route := p.upstream.Load()
			route.tr.TLSClientConfig.RootCAs = secondaryRoots
			route.trH2.TLSClientConfig.RootCAs = secondaryRoots
			_, addr := p.Status()
			proxyURL, _ := url.Parse("http://" + addr)
			captureRoots := x509.NewCertPool()
			captureRoots.AppendCertsFromPEM(p.CA().CertPEM())
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: captureRoots}}
			defer tr.CloseIdleConnections()
			resp, err := (&http.Client{Transport: tr}).Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "trusted-secondary" || originTLS && up.connects.Load() != 1 || !originTLS && up.http.Load() != 1 {
				t.Fatal("HTTPS secondary proxy was bypassed")
			}
		})
	}
}
