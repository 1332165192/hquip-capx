package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

const maxBodyCapture = 1 << 20 // 1 MiB of body captured into raw text (overridable)

var maxBodyCaptureOverride atomic.Int64

// SetMaxBodyCapture sets the history body capture cap in bytes (0 restores 1 MiB).
func SetMaxBodyCapture(n int) {
	if n <= 0 {
		maxBodyCaptureOverride.Store(0)
		return
	}
	if n > 16<<20 {
		n = 16 << 20
	}
	maxBodyCaptureOverride.Store(int64(n))
}

// MaxBodyCapture returns the current history body capture cap in bytes.
func MaxBodyCapture() int {
	if v := maxBodyCaptureOverride.Load(); v > 0 {
		return int(v)
	}
	return maxBodyCapture
}

// Proxy is the L7 MITM intercepting proxy.
type Proxy struct {
	st   *store.Store
	ca   *CA
	tr   *http.Transport // upstream HTTP/1.1 only (readable raw)
	trH2 *http.Transport // upstream HTTP/2-capable (ALPN h2)

	http2 atomic.Bool

	mu      sync.Mutex
	addr    string
	ln      net.Listener
	srv     *http.Server
	running bool

	interceptReq  atomic.Bool
	interceptResp atomic.Bool
	interceptWS   atomic.Bool
	scope         *Scope
	icept         *intercept
	rules         *RuleSet
	wsRules       *WSRuleSet
	conds         *condSet
	ws            *wsHub
	session       *sessionEngine
	transparent   *transparentServer
	h3            *http3Server
	h3extra       *http3Server
	origDst       func(net.Conn) string
	mutator       HTTPMutator
	connSeq       atomic.Uint64
	bridgeMu      sync.Mutex
	bridge        *captureBridge
	lanMu         sync.Mutex
	lan           *lanProxy
	upstream      atomic.Pointer[upstreamRoute]
	upstreamMu    sync.Mutex

	persistPath string     // ~/.capx/config.json; "" disables persistence
	persistMu   sync.Mutex // serializes config writes to persistPath
}

// nextConnID returns a per-connection id used as the HTTPTx FlowID so the
// correlation engine (M7) can group requests sharing a connection.
func (p *Proxy) nextConnID() string {
	return "px-" + strconv.FormatUint(p.connSeq.Add(1), 10)
}

// New builds a proxy bound to the given store, generating/loading the CA.
func New(st *store.Store) (*Proxy, error) {
	if _, err := upstreamTLSConfig(""); err != nil {
		return nil, err
	}
	ca, err := LoadOrCreateCA()
	if err != nil {
		return nil, err
	}
	ic := newIntercept()
	ic.bind(st)
	p := &Proxy{
		st:      st,
		ca:      ca,
		scope:   newScope(),
		icept:   ic,
		rules:   newRuleSet(),
		wsRules: newWSRuleSet(),
		conds:   newCondSet(),
		ws:      newWSHub(),
		session: newSessionEngine(),
		tr:      newUpstreamTransport(false),
		trH2:    newUpstreamTransport(true),
	}
	p.session.sender = func(scheme, host, raw string, follow bool) RepeaterResult {
		return p.SendRawTLS(scheme, host, raw, follow, nil)
	}
	// Load any persisted scope / intercept conditions / rules / macros from
	// disk and wire write-back so future edits survive restarts. A config-path
	// failure only disables persistence; it never blocks proxy startup.
	if path, err := configPath(); err != nil {
		log.Printf("capx: proxy config persistence disabled: %v", err)
	} else {
		p.wirePersistence(path)
	}
	return p, nil
}

// newUpstreamTransport builds the shared transport used to reach origin
// servers. When h2 is false it stays on HTTP/1.1 (so captured raw is readable
// 1:1 wire text); when true it advertises ALPN "h2" so HTTP/2-only origins
// negotiate HTTP/2 (the response is still decoded to a normal *http.Response
// and rendered as readable text via dumpResponse).
func newUpstreamTransport(h2 bool) *http.Transport {
	tlsCfg, err := upstreamTLSConfig("")
	if err != nil {
		tlsCfg = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	}
	if h2 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     h2,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   256,
		MaxConnsPerHost:       512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsCfg,
	}
}

// transport returns the upstream transport for the current HTTP/2 setting.
func (p *Proxy) transport() *http.Transport {
	if route := p.upstream.Load(); route != nil && route.config.Enabled {
		if p.http2.Load() {
			return route.trH2
		}
		return route.tr
	}
	if p.http2.Load() {
		return p.trH2
	}
	return p.tr
}

// SetHTTP2Enabled toggles upstream HTTP/2 negotiation (ALPN h2).
func (p *Proxy) SetHTTP2Enabled(on bool) { p.http2.Store(on) }

// HTTP2Enabled reports whether upstream HTTP/2 negotiation is on.
func (p *Proxy) HTTP2Enabled() bool { return p.http2.Load() }

func (p *Proxy) SetOrigDstLookup(fn func(net.Conn) string) {
	p.origDst = fn
}

// CA exposes the certificate authority (for cert download endpoint).
func (p *Proxy) CA() *CA { return p.ca }

// Scope exposes the scope ruleset.
func (p *Proxy) Scope() *Scope { return p.scope }

// Intercept exposes the interception queue.
func (p *Proxy) Intercept() *intercept { return p.icept }

// Rules exposes the inline Match&Replace ruleset (M6).
func (p *Proxy) Rules() *RuleSet { return p.rules }

// WSRules exposes the inline WebSocket Match&Replace ruleset.
func (p *Proxy) WSRules() *WSRuleSet { return p.wsRules }

// SetInterceptEnabled toggles request interception.
func (p *Proxy) SetInterceptEnabled(on bool) { p.interceptReq.Store(on) }

// InterceptEnabled reports whether request interception is on.
func (p *Proxy) InterceptEnabled() bool { return p.interceptReq.Load() }

// SetInterceptRespEnabled toggles response interception (Burp-style response
// breakpoints).
func (p *Proxy) SetInterceptRespEnabled(on bool) { p.interceptResp.Store(on) }

// InterceptRespEnabled reports whether response interception is on.
func (p *Proxy) InterceptRespEnabled() bool { return p.interceptResp.Load() }

// SetInterceptWSEnabled toggles WebSocket frame interception (breakpoints on
// text/binary frames in either direction).
func (p *Proxy) SetInterceptWSEnabled(on bool) { p.interceptWS.Store(on) }

// InterceptWSEnabled reports whether WebSocket frame interception is on.
func (p *Proxy) InterceptWSEnabled() bool { return p.interceptWS.Load() }

// WSConns lists the live WebSocket connections available for replay.
func (p *Proxy) WSConns() []WSConnInfo { return p.ws.list() }

// Session exposes the session-handling engine (macros, rules, variables).
func (p *Proxy) Session() *sessionEngine { return p.session }

// InterceptConds returns the current ordered interception conditions.
func (p *Proxy) InterceptConds() []InterceptCond { return p.conds.snapshot() }

// SetInterceptConds replaces the ordered interception conditions.
func (p *Proxy) SetInterceptConds(rules []InterceptCond) { p.conds.set(rules) }

// ReplayWS injects a text/binary frame onto a live WebSocket connection in the
// given direction ("send" = client->server, "recv" = server->client). It records
// the injected frame in history. Returns the recorded frame, or an error if the
// connection is gone.
func (p *Proxy) ReplayWS(connID, dir, opcode, data string) (*model.WSMessage, error) {
	wc, ok := p.ws.get(connID)
	if !ok {
		return nil, fmt.Errorf("websocket connection %q not found (closed?)", connID)
	}
	wsDir := model.WSRecv
	if dir == string(model.WSSend) {
		wsDir = model.WSSend
	}
	var op byte = 0x1
	payload := []byte(data)
	if opcode == "binary" {
		op = 0x2
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
		if err != nil {
			return nil, fmt.Errorf("binary payload must be base64: %w", err)
		}
		payload = dec
	}
	if err := wc.inject(wsDir, op, payload); err != nil {
		return nil, err
	}
	return p.recordWSFrame(wc, wsDir, op, payload), nil
}

// RunWSMacro injects a stored WebSocket macro's frames onto a live connection,
// resolving {{var}} placeholders from the session store before each send and
// recording every injected frame in history. Returns the transcript.
func (p *Proxy) RunWSMacro(name, connID string) (WSMacroRun, error) {
	wc, ok := p.ws.get(connID)
	if !ok {
		return WSMacroRun{}, fmt.Errorf("websocket connection %q not found (closed?)", connID)
	}
	m, ok := p.session.wsMacro(name)
	if !ok {
		return WSMacroRun{}, fmt.Errorf("ws macro %q not found", name)
	}
	var run WSMacroRun
	for _, step := range m.Steps {
		data := applyVars(step.Data, p.session.Vars())
		dir := model.WSSend
		if strings.EqualFold(strings.TrimSpace(step.Dir), "recv") {
			dir = model.WSRecv
		}
		op := byte(0x1)
		opStr := "text"
		payload := []byte(data)
		if strings.EqualFold(strings.TrimSpace(step.Opcode), "binary") {
			op, opStr = 0x2, "binary"
			dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
			if err != nil {
				run.Steps = append(run.Steps, WSStepResult{Dir: string(dir), Opcode: opStr, Error: "binary payload must be base64: " + err.Error()})
				break
			}
			payload = dec
		}
		sr := WSStepResult{Dir: string(dir), Opcode: opStr, Length: len(payload)}
		if err := wc.inject(dir, op, payload); err != nil {
			sr.Error = err.Error()
			run.Steps = append(run.Steps, sr)
			break
		}
		p.recordWSFrame(wc, dir, op, payload)
		run.Steps = append(run.Steps, sr)
		if step.DelayMs > 0 {
			time.Sleep(time.Duration(step.DelayMs) * time.Millisecond)
		}
	}
	run.Vars = p.session.Vars()
	return run, nil
}

// applyWSAutoReply evaluates the configured WS auto-replay rules against a just
// observed (and already recorded) frame, injecting any matching replies onto
// the same connection. It only runs for in-scope connections. Injected frames
// are recorded but do not themselves re-trigger rules (they bypass copyWSFrames).
func (p *Proxy) applyWSAutoReply(wc *wsConn, dir model.WSDir, opcode byte, payload []byte) {
	if p.session == nil || len(p.session.snapshotWSRules()) == 0 {
		return
	}
	if !p.scope.InScope(wc.scheme, wc.host, wc.path) {
		return
	}
	frameText := string(payload)
	if opcode == 0x2 { // binary frames are matched/replied as base64
		frameText = base64.StdEncoding.EncodeToString(payload)
	}
	for _, inj := range p.session.evalWSReply(wc.url, string(dir), frameText) {
		op := byte(0x1)
		pl := []byte(inj.Data)
		if inj.Opcode == "binary" {
			dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(inj.Data))
			if err != nil {
				continue // skip a reply with a bad base64 payload
			}
			op, pl = 0x2, dec
		}
		injDir := model.WSSend
		if inj.Dir == string(model.WSRecv) {
			injDir = model.WSRecv
		}
		if err := wc.inject(injDir, op, pl); err == nil {
			p.recordWSFrame(wc, injDir, op, pl)
		}
	}
}

// interceptRequest holds an outgoing request for manual editing when request
// interception is enabled and the request is in scope. It returns the
// (possibly replaced) request, its raw text, and whether the user dropped it.
func (p *Proxy) interceptRequest(scheme string, r *http.Request, reqRaw string) (*http.Request, string, bool, error) {
	if !p.interceptReq.Load() || !p.scope.InScope(scheme, r.Host, r.URL.Path) || !p.conds.shouldIntercept(r.Method, r.Host, r.URL.Path, r.URL.RawQuery) {
		return r, reqRaw, false, nil
	}
	full, restored, err := bufferEditableBody(r.Body, r.ContentLength)
	r.Body = restored
	if err != nil {
		return r, reqRaw, false, err
	}
	reqRaw = editableRequestText(r, full)
	edited, drop := p.icept.holdContext(r.Context(), "request", scheme, r.Host, reqRaw)
	if drop {
		return r, reqRaw, true, nil
	}
	if edited != "" {
		if nr := parseEditedRequest(edited, r.Host, scheme); nr != nil {
			return nr.WithContext(r.Context()), edited, false, nil
		}
		return r, reqRaw, false, fmt.Errorf("capx could not parse complete edited request (maximum body %d bytes)", maxEditableBody)
	}
	return r, reqRaw, false, nil
}

// Interception buffers only when explicitly enabled. Oversized or endless
// entities are rejected explicitly, never replaced by a captured prefix.
func (p *Proxy) interceptResponse(scheme, host string, resp *http.Response) (bool, error) {
	if !p.interceptResp.Load() || !p.scope.InScope(scheme, host, "") {
		return false, nil
	}
	raw, _, err := dumpResponse(resp)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	edited, drop := p.icept.holdContext(ctx, "response", scheme, host, raw)
	if drop {
		return true, nil
	}
	if edited != "" && !parseEditedResponse(edited, resp) {
		return false, fmt.Errorf("capx could not parse complete edited response (maximum body %d bytes)", maxEditableBody)
	}
	return false, nil
}

// Status reports the proxy listener state.
func (p *Proxy) Status() (running bool, addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running, p.addr
}

// Start binds the listener and serves until Stop. Idempotent-ish: returns an
// error if already running.
func (p *Proxy) Start(addr string) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy already running on %s", p.addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.serve)}
	p.ln, p.srv, p.addr, p.running = ln, srv, ln.Addr().String(), true
	p.mu.Unlock()

	p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "proxy_started",
		Data: map[string]string{"addr": p.addr}})

	go func() {
		_ = srv.Serve(ln)
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
		p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "proxy_stopped",
			Data: map[string]string{"addr": addr}})
	}()
	if err := p.StartHTTP3(p.addr); err != nil {
		p.st.Publish(model.Event{Source: model.SourceProxy, Kind: "http3_error",
			Data: map[string]string{"addr": p.addr, "error": err.Error()}})
	}
	return nil
}

// Stop shuts the proxy listener down.
func (p *Proxy) Stop() error {
	_ = p.StopLAN()
	defer p.CloseIdleConnections()
	if p.ws != nil {
		p.ws.closeAll()
	}
	p.mu.Lock()
	srv := p.srv
	p.mu.Unlock()
	if srv == nil {
		return fmt.Errorf("proxy not running")
	}
	_ = p.http3Slot().stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// serve is the top-level proxy handler: CONNECT => MITM TLS, else plain HTTP.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

// handlePlain proxies a plain-HTTP request (absolute-form URI).
func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	if isWebSocketUpgrade(r) {
		p.tunnelWebSocket(w, r, "ws")
		return
	}
	p.forward(w, r, "http", p.nextConnID())
}

// handleConnect establishes a MITM TLS session for HTTPS, then serves the
// decrypted HTTP requests on that connection.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, p.leafTLSConfig(host))
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		reportCaptureBridgeError(r.Context(), "client_tls", err)
		return
	}
	defer tlsConn.Close()

	connID := p.nextConnID()
	p.serveDecryptedHTTPContext(r.Context(), tlsConn, host, connID)
}

// leafTLSConfig returns the server TLS config for MITM: a per-host leaf signed
// by the capx CA, and ALPN h2 advertised only when HTTP/2 is enabled (so
// h2-only / gRPC-web clients can be intercepted instead of forced to HTTP/1.1).
func (p *Proxy) leafTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = host
			}
			return p.ca.LeafFor(name)
		},
		MinVersion: tls.VersionTLS12,
	}
	if p.http2.Load() {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	return cfg
}

// serveDecryptedHTTP serves HTTP requests over an already-handshaked MITM TLS
// connection: HTTP/2 when ALPN negotiated it, otherwise an HTTP/1.1 read loop
// (with WebSocket upgrade handling). Shared by explicit-CONNECT and transparent
// interception. host is the upstream authority (from CONNECT or SNI).
func (p *Proxy) serveDecryptedHTTP(tlsConn *tls.Conn, host, connID string) {
	p.serveDecryptedHTTPContext(context.Background(), tlsConn, host, connID)
}

func (p *Proxy) serveDecryptedHTTPContext(ctx context.Context, tlsConn *tls.Conn, host, connID string) {
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.serveDownstreamH2Context(ctx, tlsConn, host, connID)
		return
	}
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req = req.WithContext(ctx)
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.RemoteAddr = tlsConn.RemoteAddr().String()

		if isWebSocketUpgrade(req) {
			p.tunnelWebSocketConn(tlsConn, br, req, "wss")
			return
		}
		keepAlive := p.forwardConn(tlsConn, req, "https", connID)
		if !keepAlive {
			return
		}
	}
}

// serveDownstreamH2 serves an HTTP/2 client connection (already TLS-decrypted),
// proxying each request stream through the same pipeline as HTTP/1.1 (scope,
// interception, rules, session handling, history). The h2 framing for both the
// client side (here) and the upstream side (the transport) is handled by the
// net/http2 stack; capx still records the readable request/response text.
func (p *Proxy) serveDownstreamH2(conn net.Conn, host, connID string) {
	p.serveDownstreamH2Context(context.Background(), conn, host, connID)
}

func (p *Proxy) serveDownstreamH2Context(ctx context.Context, conn net.Conn, host, connID string) {
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		if r.URL.Host == "" {
			r.URL.Host = host
		}
		if r.Host == "" {
			r.Host = host
		}
		if r.Method == http.MethodConnect {
			proto := r.Header.Get("Protocol")
			if proto == "" {
				proto = r.Header.Get(":protocol")
			}
			if strings.EqualFold(proto, "websocket") {
				p.tunnelH2WebSocket(w, r, host)
				return
			}
		}
		p.forward(w, r, "https", connID)
	})
	h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: handler, Context: ctx})
}

// prepareForwardRequest only reads a body when an explicit transformation or
// interception requires it. Header-only rules leave streaming uploads alone.
func (p *Proxy) prepareForwardRequest(r *http.Request, scheme string) (*http.Request, int, error) {
	r.RequestURI = ""
	r.URL.Scheme = scheme
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	nr, _, drop, err := p.interceptRequest(scheme, r, "")
	if err != nil {
		return r, http.StatusRequestEntityTooLarge, err
	}
	if drop {
		return r, http.StatusForbidden, fmt.Errorf("dropped by capx")
	}
	r = nr
	if _, err := p.session.applyToRequest(r); err != nil {
		return r, http.StatusRequestEntityTooLarge, err
	}
	blocked, err := p.rules.applyRequest(r)
	if err != nil {
		return r, http.StatusRequestEntityTooLarge, err
	}
	if blocked {
		return r, http.StatusForbidden, fmt.Errorf("blocked by capx rule")
	}
	if err := p.applyRequestMutator(r); err != nil {
		return r, http.StatusRequestEntityTooLarge, err
	}
	r.Header = forwardHeaders(r.Header)
	return r, 0, nil
}

func (p *Proxy) prepareForwardResponse(scheme, host string, resp *http.Response) (int, error) {
	if err := p.rules.applyResponse(resp); err != nil {
		return http.StatusBadGateway, err
	}
	if err := p.applyResponseMutator(resp); err != nil {
		return http.StatusBadGateway, err
	}
	drop, err := p.interceptResponse(scheme, host, resp)
	if err != nil {
		return http.StatusBadGateway, err
	}
	if drop {
		return http.StatusForbidden, fmt.Errorf("dropped by capx")
	}
	return 0, nil
}

// forward handles plain HTTP, HTTP/2 and HTTP/3 with bounded history tees.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, scheme, connID string) {
	done, ok := enterCaptureBridgeRequest(r.Context())
	if !ok {
		http.Error(w, "capture bridge is stopping", http.StatusServiceUnavailable)
		return
	}
	defer done()
	start := time.Now()
	r, status, err := p.prepareForwardRequest(r, scheme)
	if err != nil {
		http.Error(w, err.Error(), status)
		p.recordRequestFailure(scheme, connID, r, status, err, start)
		return
	}
	reqCap := captureBody(r.Body)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = reqCap
	}
	r, serverAddr := traceServerAddr(r)
	resp, err := p.transportForRequest(r).RoundTrip(r)
	if err != nil {
		reportCaptureBridgeError(r.Context(), "upstream", err)
		http.Error(w, "capx proxy upstream error: "+err.Error(), http.StatusBadGateway)
		p.record(scheme, r, nil, requestCaptureText(r, reqCap), "", 0, start, connID, serverAddr.get())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusProxyAuthRequired || resp.StatusCode >= 500 {
		reportCaptureBridgeError(r.Context(), "upstream_http", fmt.Errorf("HTTP response status %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	}
	if status, err := p.prepareForwardResponse(scheme, r.Host, resp); err != nil {
		http.Error(w, err.Error(), status)
		p.record(scheme, r, nil, requestCaptureText(r, reqCap), "", 0, start, connID, serverAddr.get())
		return
	}
	respRaw, n, err := writeResponse(w, resp)
	p.record(scheme, r, resp, requestCaptureText(r, reqCap), respRaw, n, start, connID, serverAddr.get())
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	if bridgeForContext(r.Context()) == nil {
		go p.session.maybeRelogin(r.Host, respRaw)
	}
}

// forwardConn uses standard HTTP/1.1 framing on the decrypted MITM connection.
func (p *Proxy) forwardConn(conn net.Conn, r *http.Request, scheme, connID string) bool {
	done, ok := enterCaptureBridgeRequest(r.Context())
	if !ok {
		return false
	}
	defer done()
	start := time.Now()
	r, status, err := p.prepareForwardRequest(r, scheme)
	if err != nil {
		writeProxyErrorConn(conn, status, err)
		p.recordRequestFailure(scheme, connID, r, status, err, start)
		return false
	}
	reqCap := captureBody(r.Body)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = reqCap
	}
	r, serverAddr := traceServerAddr(r)
	resp, err := p.transportForRequest(r).RoundTrip(r)
	if err != nil {
		reportCaptureBridgeError(r.Context(), "upstream", err)
		writeProxyErrorConn(conn, http.StatusBadGateway, err)
		p.record(scheme, r, nil, requestCaptureText(r, reqCap), "", 0, start, connID, serverAddr.get())
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusProxyAuthRequired || resp.StatusCode >= 500 {
		reportCaptureBridgeError(r.Context(), "upstream_http", fmt.Errorf("HTTP response status %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	}
	if status, err := p.prepareForwardResponse(scheme, r.Host, resp); err != nil {
		writeProxyErrorConn(conn, status, err)
		p.record(scheme, r, nil, requestCaptureText(r, reqCap), "", 0, start, connID, serverAddr.get())
		return false
	}
	respRaw, n, err := writeResponseConn(conn, resp)
	p.record(scheme, r, resp, requestCaptureText(r, reqCap), respRaw, n, start, connID, serverAddr.get())
	if err != nil {
		return false
	}
	if bridgeForContext(r.Context()) == nil {
		go p.session.maybeRelogin(r.Host, respRaw)
	}
	return !resp.Close && !r.Close
}

func writeProxyErrorConn(conn io.Writer, status int, err error) {
	body := err.Error() + "\n"
	resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Close: true}
	_ = resp.Write(conn)
}

// Keep rejected requests visible without trying to drain a possibly endless
// upload merely to populate history. No rejected prefix is sent upstream.
func (p *Proxy) recordRequestFailure(scheme, connID string, r *http.Request, status int, err error, started time.Time) {
	reqRaw := requestCaptureText(r, captureBody(http.NoBody))
	if r.Body != nil && r.Body != http.NoBody {
		reqRaw += "\r\n... [body history truncated by capx: request rejected before forwarding]"
	}
	body := err.Error() + "\n"
	resp := &http.Response{Proto: "HTTP/1.1", StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}}}
	cap := captureBody(io.NopCloser(strings.NewReader(body)))
	_, _ = io.Copy(io.Discard, cap)
	p.record(scheme, r, resp, reqRaw, responseCaptureText(resp, cap), len(body), started, connID, "")
}

// serverAddrTrap captures the upstream connection's remote address (resolved
// server ip:port) for a single round trip via httptrace.
type serverAddrTrap struct {
	mu   sync.Mutex
	addr string
}

func (t *serverAddrTrap) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}

// traceServerAddr attaches an httptrace to the request that records the upstream
// server's ip:port once the connection is obtained. The returned trap is read
// after RoundTrip via get().
func traceServerAddr(r *http.Request) (*http.Request, *serverAddrTrap) {
	trap := &serverAddrTrap{}
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				trap.mu.Lock()
				trap.addr = info.Conn.RemoteAddr().String()
				trap.mu.Unlock()
			}
		},
	}
	return r.WithContext(httptrace.WithClientTrace(r.Context(), trace)), trap
}

// record stores an HTTPTx for the Burp-style history (subject to scope).
func (p *Proxy) record(scheme string, r *http.Request, resp *http.Response, reqRaw, respRaw string, respLen int, start time.Time, connID, serverAddr string) {
	provenance := model.CaptureTransport(r.Context())
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	inScope := p.scope.InScope(scheme, host, r.URL.Path)
	tx := &model.HTTPTx{
		FlowID:        connID,
		Scheme:        scheme,
		Method:        r.Method,
		Host:          host,
		Path:          r.URL.RequestURI(),
		URL:           scheme + "://" + host + r.URL.RequestURI(),
		ReqRaw:        reqRaw,
		RespRaw:       respRaw,
		RespLen:       respLen,
		Decrypted:     scheme == "https",
		ReqHdr:        flattenHeader(r.Header),
		ServerAddr:    serverAddr,
		CaptureMode:   provenance.Mode,
		ClientAddr:    provenance.ClientAddr,
		CapturePeer:   provenance.PeerID,
		InScope:       inScope,
		OutOfScope:    !inScope,
		BodyTruncated: rawTruncated(reqRaw) || rawTruncated(respRaw),
	}
	if resp != nil {
		tx.Status = resp.StatusCode
		tx.Proto = resp.Proto
		tx.MIME = simpleMIME(resp.Header.Get("Content-Type"))
		tx.RespHdr = flattenHeader(resp.Header)
	}
	p.st.AddHTTPTx(tx)
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func simpleMIME(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return strings.TrimSpace(ct)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func writeRawResponse(conn net.Conn, s string) { _, _ = io.WriteString(conn, s) }
