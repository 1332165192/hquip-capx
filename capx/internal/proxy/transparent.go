package proxy

// Transparent (inline) interception. A normal proxy only sees traffic from
// clients that honour system proxy settings. With an OS-level redirect (e.g.
// WinDivert/NFQUEUE or `iptables -j REDIRECT`) pointing :80/:443 at this
// listener, capx intercepts apps that ignore proxy settings entirely: it peeks
// the first bytes to tell TLS from plain HTTP, recovers the destination from
// the TLS SNI (or the HTTP Host header), and feeds the connection into the same
// MITM pipeline used for explicit CONNECT.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
)

// transparentServer is the inline interception listener.
type transparentServer struct {
	p *Proxy

	mu      sync.Mutex
	ln      net.Listener
	addr    string
	running bool
}

// TransparentStatus reports the inline listener state.
func (p *Proxy) TransparentStatus() (running bool, addr string) {
	p.mu.Lock()
	t := p.transparent
	p.mu.Unlock()
	if t == nil {
		return false, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running, t.addr
}

// StartTransparent binds the transparent interception listener on addr.
func (p *Proxy) StartTransparent(addr string) error {
	p.mu.Lock()
	if p.transparent == nil {
		p.transparent = &transparentServer{p: p}
	}
	t := p.transparent
	p.mu.Unlock()
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return fmt.Errorf("transparent listener already running on %s", t.addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	t.ln, t.addr, t.running = ln, ln.Addr().String(), true
	t.mu.Unlock()

	p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "transparent_started",
		Data: map[string]string{"addr": t.addr}})
	go t.serve(ln)
	if err := p.StartHTTP3Extra(t.addr); err != nil {
		p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "http3_error",
			Data: map[string]string{"addr": t.addr, "error": err.Error()}})
	}
	return nil
}

// StopTransparent shuts the transparent listener down.
func (p *Proxy) StopTransparent() error {
	p.mu.Lock()
	t := p.transparent
	p.mu.Unlock()
	if t == nil {
		return fmt.Errorf("transparent listener not running")
	}
	t.mu.Lock()
	ln := t.ln
	t.running = false
	t.ln = nil
	t.mu.Unlock()
	_ = p.StopHTTP3Extra()
	if ln == nil {
		return fmt.Errorf("transparent listener not running")
	}
	return ln.Close()
}

func (t *transparentServer) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go t.handle(c)
	}
}

// peekConn wraps a net.Conn with a buffered reader so the first bytes can be
// peeked (to classify TLS vs HTTP) without consuming them.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (t *transparentServer) handle(c net.Conn) {
	t.handleContext(context.Background(), c, "")
}

// ServeVPNConn accepts a stream already authenticated by the WireGuard peer.
// It does not create a listener, install a CA, or modify the host network.
func (p *Proxy) ServeVPNConn(ctx context.Context, c net.Conn, destination string) {
	info := model.CaptureTransport(ctx)
	info.Mode = "mobile-vpn"
	info.ClientAddr = c.RemoteAddr().String()
	ctx = model.WithCaptureTransport(ctx, info)
	(&transparentServer{p: p}).handleContext(ctx, c, destination)
}

func (t *transparentServer) handleContext(ctx context.Context, c net.Conn, destination string) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := &peekConn{Conn: c, r: br}

	// TLS records start with a handshake content type (0x16).
	if first[0] == 0x16 {
		t.handleTLSContext(ctx, pc, destination)
		return
	}
	t.handlePlainContext(ctx, pc, br)
}

// handleTLS terminates TLS with a leaf chosen from the ClientHello SNI, then
// serves the decrypted HTTP through the shared pipeline.
func (t *transparentServer) handleTLS(c net.Conn) {
	t.handleTLSContext(context.Background(), c, "")
}

func (t *transparentServer) handleTLSContext(ctx context.Context, c net.Conn, destination string) {
	var sni string
	cfg := t.p.leafTLSConfig(destination)
	// Wrap GetCertificate to also capture the SNI for the upstream authority.
	base := cfg.GetCertificate
	cfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi.ServerName != "" {
			sni = chi.ServerName
		}
		return base(chi)
	}
	tlsConn := tls.Server(c, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "transparent_tls_error",
			Data: map[string]string{"host": sni, "stage": "client_tls", "error": err.Error()}})
		return
	}
	defer tlsConn.Close()
	host := sni
	if host != "" && destination != "" {
		if _, port, err := net.SplitHostPort(destination); err == nil && port != "443" {
			host = net.JoinHostPort(host, port)
		}
	}
	if host == "" {
		host = destination
	}
	if host == "" && t.p.origDst != nil {
		host = t.p.origDst(c)
	}
	if host == "" {
		return
	}
	t.p.serveDecryptedHTTPContext(ctx, tlsConn, host, t.p.nextConnID())
}

// handlePlain handles a transparently-redirected plain HTTP connection: it
// reads requests, fills in the absolute target from the Host header, and runs
// them through the same forward path as the explicit proxy.
func (t *transparentServer) handlePlain(c net.Conn, br *bufio.Reader) {
	t.handlePlainContext(context.Background(), c, br)
}

func (t *transparentServer) handlePlainContext(ctx context.Context, c net.Conn, br *bufio.Reader) {
	connID := t.p.nextConnID()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Host == "" {
			return
		}
		req.URL.Scheme = "http"
		req = req.WithContext(ctx)
		req.URL.Host = req.Host
		if isWebSocketUpgrade(req) {
			t.p.tunnelWebSocketConn(c, br, req, "ws")
			return
		}
		if !t.p.forwardConn(c, req, "http", connID) {
			return
		}
	}
}
