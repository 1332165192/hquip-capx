package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
)

type captureBridgeKey struct{}

// A bridge owns both sides of its connections and its transports. It shares
// only application-level policy/CA/history with Proxy, never the normal
// listeners' upstream route or connection pools.
type captureBridge struct {
	parent   *Proxy
	addr     string
	upstream *url.URL
	ctx      context.Context
	cancel   context.CancelFunc
	srv      *http.Server
	ln       net.Listener
	tr       *http.Transport
	trH2     *http.Transport
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	conns    map[*bridgeConn]struct{}
	handlers sync.WaitGroup
}

func bridgeForContext(ctx context.Context) *captureBridge {
	bridge, _ := ctx.Value(captureBridgeKey{}).(*captureBridge)
	return bridge
}

func enterCaptureBridgeRequest(ctx context.Context) (done func(), ok bool) {
	b := bridgeForContext(ctx)
	if b == nil {
		return func() {}, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return func() {}, false
	}
	// Stop marks closed under this same lock before waiting, so no Add can
	// race a zero-count Wait or begin forwarding after shutdown has started.
	b.handlers.Add(1)
	return b.handlers.Done, true
}

func reportCaptureBridgeError(ctx context.Context, stage string, err error) {
	b := bridgeForContext(ctx)
	if b == nil || err == nil || b.ctx.Err() != nil || ctx.Err() != nil {
		return
	}
	// Upstream validation excludes credentials. Never include request headers,
	// Proxy-Authorization, raw URLs, or edited request bodies in diagnostics.
	b.parent.st.Publish(model.Event{Source: model.SourceProxy, Kind: "capture_bridge_error", Data: map[string]string{
		"addr": b.addr, "upstream": b.upstream.String(), "stage": stage, "error": capStr(err.Error(), 2048),
	}})
}

func captureBridgeUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("capture bridge upstream must be an HTTP loopback URL without credentials, path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, errors.New("capture bridge upstream must include an explicit port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid capture bridge upstream port")
	}
	// Pin localhost rather than re-resolving a hostname during every dial.
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("capture bridge upstream must be a loopback IP or localhost")
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(n))}, nil
}

func samePort(a, b string) bool {
	_, ap, ae := net.SplitHostPort(a)
	_, bp, be := net.SplitHostPort(b)
	return ae == nil && be == nil && ap == bp
}

func (p *Proxy) bridgeOwnPort(addr, bridgeAddr string) bool {
	if bridgeAddr != "" && samePort(addr, bridgeAddr) {
		return true
	}
	if on, own := p.Status(); on && samePort(addr, own) {
		return true
	}
	if on, own := p.TransparentStatus(); on && samePort(addr, own) {
		return true
	}
	return false
}

// StartCaptureBridge starts an independent explicit HTTP proxy chained through
// the selected local HTTP upstream. It never changes system proxy settings or
// p.tr/p.trH2. Repeating the same configuration is idempotent; changing an
// active bridge requires an explicit stop first.
func (p *Proxy) StartCaptureBridge(upstream string) (string, error) {
	u, err := captureBridgeUpstream(upstream)
	if err != nil {
		return "", err
	}
	p.bridgeMu.Lock()
	defer p.bridgeMu.Unlock()
	if p.bridge != nil {
		p.bridge.mu.Lock()
		closed := p.bridge.closed
		p.bridge.mu.Unlock()
		if closed {
			return "", errors.New("capture bridge shutdown is still pending; stop it before restarting")
		}
		if p.bridge.upstream.String() == u.String() {
			return p.bridge.addr, nil
		}
		return "", errors.New("capture bridge is already running with a different upstream")
	}
	if p.bridgeOwnPort(u.Host, "") {
		return "", errors.New("capture bridge upstream points to this instance's proxy listener")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if samePort(addr, u.Host) {
		ln.Close()
		return "", errors.New("capture bridge upstream would point to the bridge itself")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &captureBridge{parent: p, addr: addr, upstream: u, cancel: cancel, done: make(chan struct{}), conns: make(map[*bridgeConn]struct{})}
	b.ctx = context.WithValue(ctx, captureBridgeKey{}, b)
	b.tr, b.trH2 = b.transport(false), b.transport(true)
	b.ln = &bridgeListener{Listener: ln, bridge: b}
	b.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			done, ok := enterCaptureBridgeRequest(r.Context())
			if !ok {
				http.Error(w, "capture bridge is stopping", http.StatusServiceUnavailable)
				return
			}
			defer done()
			p.serve(w, r)
		}), ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(net.Listener) context.Context { return b.ctx },
	}
	p.bridge = b
	go func() {
		defer close(b.done)
		if err := b.srv.Serve(b.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "capture_bridge_error", Data: map[string]string{"addr": addr, "error": err.Error()}})
		}
	}()
	p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "capture_bridge_started", Data: map[string]string{"addr": addr, "upstream": u.String()}})
	return addr, nil
}

func (p *Proxy) CaptureBridgeStatus() (running bool, addr string, upstream string) {
	p.bridgeMu.Lock()
	defer p.bridgeMu.Unlock()
	if p.bridge == nil {
		return false, "", ""
	}
	p.bridge.mu.Lock()
	defer p.bridge.mu.Unlock()
	return !p.bridge.closed, p.bridge.addr, p.bridge.upstream.String()
}

// StopCaptureBridge cancels all requests and closes all owned sockets,
// including CONNECT connections removed from net/http by Hijack. Normal
// explicit/transparent listeners and their transports are left untouched.
func (p *Proxy) StopCaptureBridge() error {
	p.bridgeMu.Lock()
	defer p.bridgeMu.Unlock()
	b := p.bridge
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.closed = true
	conns := make([]*bridgeConn, 0, len(b.conns))
	for conn := range b.conns {
		conns = append(conns, conn)
	}
	b.mu.Unlock()
	b.cancel()
	err := b.srv.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	b.tr.CloseIdleConnections()
	b.trH2.CloseIdleConnections()
	<-b.done
	handlersDone := make(chan struct{})
	go func() { b.handlers.Wait(); close(handlersDone) }()
	select {
	case <-handlersDone:
	case <-time.After(5 * time.Second):
		return errors.New("capture bridge connections closed, but request cleanup has not finished")
	}
	p.bridge = nil
	p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "capture_bridge_stopped", Data: map[string]string{"addr": b.addr}})
	return err
}

func (b *captureBridge) transport(h2 bool) *http.Transport {
	tr := newUpstreamTransport(h2)
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		if err := b.ctx.Err(); err != nil {
			return nil, err
		}
		// Recheck in case another listener was started after this bridge.
		if b.parent.bridgeOwnPort(b.upstream.Host, b.addr) {
			return nil, errors.New("capture bridge upstream now points to this instance's listener")
		}
		if host := req.URL.Hostname(); strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
			if b.parent.bridgeOwnPort(req.URL.Host, b.addr) || samePort(req.URL.Host, b.upstream.Host) {
				return nil, errors.New("capture bridge target would create a local proxy loop")
			}
		}
		return b.upstream, nil
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// A Transport may detach a pooled dial from its request's cancellation.
		// The bridge lifetime must still cancel it and own the resulting socket.
		dialCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(b.ctx, cancel)
		defer stop()
		defer cancel()
		conn, err := (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}
		return b.track(conn)
	}
	return tr
}

func (p *Proxy) transportForRequest(r *http.Request) *http.Transport {
	if b := bridgeForContext(r.Context()); b != nil {
		if p.http2.Load() {
			return b.trH2
		}
		return b.tr
	}
	return p.transport()
}

type bridgeListener struct {
	net.Listener
	bridge *captureBridge
}

func (ln *bridgeListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return ln.bridge.track(conn)
}

type bridgeConn struct {
	net.Conn
	bridge *captureBridge
	once   sync.Once
	err    error
}

func (b *captureBridge) track(conn net.Conn) (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	tracked := &bridgeConn{Conn: conn, bridge: b}
	b.conns[tracked] = struct{}{}
	return tracked, nil
}

func (c *bridgeConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.bridge.mu.Lock()
		delete(c.bridge.conns, c)
		c.bridge.mu.Unlock()
	})
	return c.err
}

func bridgeWebSocketError() error {
	return fmt.Errorf("WebSocket forwarding through a secondary capture proxy is not supported; no direct connection was made")
}
