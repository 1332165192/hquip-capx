package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UpstreamConfig exposes only a credential-free endpoint. Basic credentials
// are memory-only; a restored authenticated endpoint stays blocked until the
// user supplies them again, rather than bypassing the selected route.
// Disabling the explicit route restores the pre-existing environment routing.
type UpstreamConfig struct {
	Enabled            bool   `json:"enabled"`
	URL                string `json:"url,omitempty"`
	HasCredentials     bool   `json:"has_credentials,omitempty"`
	CredentialsMissing bool   `json:"credentials_missing,omitempty"`
	Username           string `json:"-"`
	Password           string `json:"-"`
	KeepCredentials    bool   `json:"-"`
}

type upstreamRoute struct {
	config UpstreamConfig
	url    *url.URL
	tr     *http.Transport
	trH2   *http.Transport
}

// NormalizeUpstream pins localhost to a loopback IP to avoid DNS-dependent
// routing. HTTPS proxies must present a certificate trusted by the OS.
func NormalizeUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("upstream must be a local HTTP/HTTPS URL without credentials, path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 1 || n > 65535 {
		return nil, errors.New("upstream must include a valid explicit port")
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("upstream must be a loopback IP or localhost")
	}
	return &url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(ip.String(), strconv.Itoa(n))}, nil
}

func (p *Proxy) UpstreamConfig() UpstreamConfig {
	if route := p.upstream.Load(); route != nil {
		return route.config
	}
	return UpstreamConfig{}
}

func (p *Proxy) upstreamOwnPort(addr string) bool {
	if p.bridgeOwnPort(addr, "") {
		return true
	}
	if on, bridge, _ := p.CaptureBridgeStatus(); on && samePort(addr, bridge) {
		return true
	}
	return false
}

func (p *Proxy) parseUpstream(cfg UpstreamConfig) (*upstreamRoute, error) {
	if !cfg.Enabled {
		return &upstreamRoute{}, nil
	}
	u, err := NormalizeUpstream(cfg.URL)
	if err != nil {
		return nil, err
	}
	if p.upstreamOwnPort(u.Host) {
		return nil, errors.New("upstream points to this instance's capture listener")
	}
	if len(cfg.Username) > 256 || len(cfg.Password) > 2048 || strings.ContainsAny(cfg.Username+cfg.Password, "\r\n\x00") || strings.Contains(cfg.Username, ":") || cfg.Username == "" && cfg.Password != "" {
		return nil, errors.New("invalid upstream credentials")
	}
	public := UpstreamConfig{Enabled: true, URL: u.String()}
	if cfg.Username != "" {
		public.HasCredentials = true
		u.User = url.UserPassword(cfg.Username, cfg.Password)
	} else if cfg.KeepCredentials {
		old := p.upstream.Load()
		if old == nil || !old.config.Enabled || old.config.URL != public.URL || old.url.User == nil {
			return nil, errors.New("no matching runtime credentials to retain")
		}
		u.User = old.url.User
		public.HasCredentials = true
	} else if cfg.HasCredentials {
		public.HasCredentials = true
		public.CredentialsMissing = true
	}
	route := &upstreamRoute{config: public, url: u, tr: newUpstreamTransport(false), trH2: newUpstreamTransport(true)}
	if p.tr != nil {
		route.tr.TLSClientConfig.RootCAs = p.tr.TLSClientConfig.RootCAs
		route.trH2.TLSClientConfig.RootCAs = p.tr.TLSClientConfig.RootCAs
	}
	p.configureUpstreamTransport(route.tr, route)
	p.configureUpstreamTransport(route.trH2, route)
	return route, nil
}

// SetUpstream writes the accepted configuration before reporting success.
// Failed persistence leaves both routing and the previous saved config intact.
// It never edits OS proxy settings or other instances' transport pools.
func (p *Proxy) SetUpstream(cfg UpstreamConfig) error {
	p.upstreamMu.Lock()
	defer p.upstreamMu.Unlock()
	route, err := p.parseUpstream(cfg)
	if err != nil {
		return err
	}
	p.persistMu.Lock()
	defer p.persistMu.Unlock()
	if p.persistPath != "" {
		snapshot := p.snapshotConfig()
		snapshot.Upstream = route.config
		if err := writeConfigAtomic(p.persistPath, snapshot); err != nil {
			return errors.New("cannot save upstream configuration; previous route retained")
		}
	}
	// Existing sockets cannot be rerouted. Close them so a later manual frame
	// cannot continue down a route the user has just disabled or replaced.
	if p.ws != nil {
		p.ws.closeAll()
	}
	p.installUpstream(route)
	return nil
}

func (p *Proxy) selectUpstream(req *http.Request) (*url.URL, error) {
	route := p.upstream.Load()
	return p.selectRoute(route, req)
}

func (p *Proxy) selectRoute(route *upstreamRoute, req *http.Request) (*url.URL, error) {
	if route == nil || !route.config.Enabled {
		return http.ProxyFromEnvironment(req)
	}
	if route.config.CredentialsMissing {
		return nil, errors.New("upstream credentials must be entered again after restart")
	}
	if p.upstreamOwnPort(route.url.Host) {
		return nil, errors.New("upstream now points to this instance's capture listener")
	}
	host := req.URL.Hostname()
	if strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		if p.upstreamOwnPort(req.URL.Host) || samePort(req.URL.Host, route.url.Host) {
			return nil, errors.New("target would create a local proxy loop")
		}
	}
	return route.url, nil
}

func (p *Proxy) unsupportedUpstreamWS() bool { return false }

func (p *Proxy) configureUpstreamTransport(tr *http.Transport, route *upstreamRoute) {
	tr.Proxy = func(req *http.Request) (*url.URL, error) { return p.selectRoute(route, req) }
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cfg := tr.TLSClientConfig.Clone()
		cfg.ServerName = stripPort(addr)
		if route.url.Scheme == "https" && route.url.Host == addr {
			// The capture CA exception is for origins, never the secondary proxy.
			cfg = &tls.Config{ServerName: stripPort(addr), RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		}
		return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: cfg}).DialContext(ctx, network, addr)
	}
}

func (p *Proxy) installUpstream(route *upstreamRoute) {
	old := p.upstream.Swap(route)
	if old != nil && old.tr != nil {
		old.tr.CloseIdleConnections()
		if old.trH2 != nil {
			old.trH2.CloseIdleConnections()
		}
	}
	if p.tr != nil {
		p.tr.CloseIdleConnections()
	}
	if p.trH2 != nil {
		p.trH2.CloseIdleConnections()
	}
}

func (p *Proxy) CloseIdleConnections() {
	if p.tr != nil {
		p.tr.CloseIdleConnections()
	}
	if p.trH2 != nil {
		p.trH2.CloseIdleConnections()
	}
	if route := p.upstream.Load(); route != nil && route.tr != nil {
		route.tr.CloseIdleConnections()
		if route.trH2 != nil {
			route.trH2.CloseIdleConnections()
		}
	}
}
