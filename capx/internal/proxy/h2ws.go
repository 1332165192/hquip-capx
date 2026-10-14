package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/hquip/capx/internal/model"
)

// tunnelH2WebSocket handles RFC 8441 Extended CONNECT (:protocol = websocket).
// After a 200 on the HTTP/2 stream, DATA frames are a raw WebSocket byte stream.
func (p *Proxy) tunnelH2WebSocket(w http.ResponseWriter, r *http.Request, defaultHost string) {
	host := r.Host
	if host == "" {
		host = defaultHost
	}
	if host == "" {
		http.Error(w, "missing :authority", http.StatusBadRequest)
		return
	}
	r.Host = host
	if r.URL != nil && r.URL.Host == "" {
		r.URL.Host = host
	}
	stripWSExtensionsHeaders(r.Header)
	r.Header.Del("Proxy-Authorization")
	p.upstreamMu.Lock()
	locked := true
	defer func() {
		if locked {
			p.upstreamMu.Unlock()
		}
	}()

	up, scheme, handshake, err := p.dialWSForH2(r, host)
	if err != nil {
		http.Error(w, "websocket upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	reqRaw, _ := dumpRequest(cloneH2WSHeaders(r))
	p.recordWSUpgrade(scheme, r, handshake, reqRaw, []byte(handshake))

	client := newStreamConn(r.Body, &flushWriter{w: w}, r.Body)
	p.relayWS(client, bufio.NewReader(client), up, bufio.NewReader(up), r, scheme, func() { locked = false; p.upstreamMu.Unlock() })
}

func cloneH2WSHeaders(r *http.Request) *http.Request {
	nr := r.Clone(context.Background())
	nr.Body = http.NoBody
	nr.ContentLength = 0
	return nr
}

// dialWSForH2 prefers an HTTP/2 Extended CONNECT to the origin; if the peer
// does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL it falls back to a
// HTTP/1.1 Upgrade handshake and returns the post-101 connection.
func (p *Proxy) dialWSForH2(r *http.Request, host string) (net.Conn, string, string, error) {
	routed := p.UpstreamConfig().Enabled || bridgeForContext(r.Context()) != nil
	if !routed {
		if conn, status, err := dialUpstreamH2WS(r, host); err == nil {
			return conn, "wss", status, nil
		}
	}
	var up net.Conn
	var err error
	if routed {
		up, err = p.dialRoutedTarget(r.Context(), "wss", host, nil)
	} else {
		up, err = dialUpstreamWS("wss", host)
	}
	if err != nil {
		if routed {
			return nil, "", "", err
		}
		up, err = dialUpstreamWS("ws", host)
		if err != nil {
			return nil, "", "", err
		}
		nr := h2WSToH1Request(r, host)
		stripWSExtensionsHeaders(nr.Header)
		if err := nr.Write(up); err != nil {
			up.Close()
			return nil, "", "", err
		}
		upR := bufio.NewReader(up)
		statusLine, headerBlock, err := readHeaderBlock(upR)
		if err != nil {
			up.Close()
			return nil, "", "", err
		}
		headerBlock = stripWSExtensionsBlock(headerBlock)
		if !strings.Contains(statusLine, "101") {
			up.Close()
			return nil, "", "", io.EOF
		}
		return &prefixConn{r: upR, Conn: up}, "ws", string(headerBlock), nil
	}
	nr := h2WSToH1Request(r, host)
	stripWSExtensionsHeaders(nr.Header)
	if err := nr.Write(up); err != nil {
		up.Close()
		return nil, "", "", err
	}
	upR := bufio.NewReader(up)
	statusLine, headerBlock, err := readHeaderBlock(upR)
	if err != nil {
		up.Close()
		return nil, "", "", err
	}
	headerBlock = stripWSExtensionsBlock(headerBlock)
	if !strings.Contains(statusLine, "101") {
		up.Close()
		return nil, "", "", io.EOF
	}
	return &prefixConn{r: upR, Conn: up}, "wss", string(headerBlock), nil
}

func h2WSToH1Request(r *http.Request, host string) *http.Request {
	path := "/"
	if r.URL != nil {
		if u := r.URL.RequestURI(); u != "" {
			path = u
		} else if r.URL.Path != "" {
			path = r.URL.Path
		}
	}
	nr, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	for k, vs := range r.Header {
		if strings.HasPrefix(k, ":") {
			continue
		}
		nr.Header[k] = append([]string(nil), vs...)
	}
	nr.Header.Set("Upgrade", "websocket")
	nr.Header.Set("Connection", "Upgrade")
	if nr.Header.Get("Sec-WebSocket-Version") == "" {
		nr.Header.Set("Sec-WebSocket-Version", "13")
	}
	nr.Host = host
	return nr
}

func dialUpstreamH2WS(r *http.Request, host string) (net.Conn, string, error) {
	pr, pw := io.Pipe()
	req := r.Clone(context.Background())
	req.Body = pr
	req.ContentLength = -1
	req.RequestURI = ""
	req.Method = http.MethodConnect
	if req.URL == nil {
		req.URL = &url.URL{}
	}
	req.URL.Scheme = "https"
	req.URL.Host = host
	if req.Header.Get(":protocol") == "" {
		req.Header.Set(":protocol", "websocket")
	}
	stripWSExtensionsHeaders(req.Header)

	config, err := upstreamTLSConfig(host, "h2")
	if err != nil {
		_ = pw.Close()
		return nil, "", err
	}
	tr := &http2.Transport{TLSClientConfig: config}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, "", io.EOF
	}
	conn := newStreamConn(resp.Body, pw, resp.Body, pw)
	return conn, resp.Status, nil
}

func (p *Proxy) relayWS(client net.Conn, clientR *bufio.Reader, up net.Conn, upR *bufio.Reader, r *http.Request, scheme string, routeReady func()) {
	path := "/"
	uri := "/"
	if r.URL != nil {
		path = r.URL.Path
		if u := r.URL.RequestURI(); u != "" {
			uri = u
		}
	}
	wsURL := scheme + "://" + r.Host + uri
	httpScheme := "http"
	if scheme == "wss" || scheme == "https" {
		httpScheme = "https"
	}
	wc := &wsConn{
		url: wsURL, scheme: httpScheme, host: r.Host, path: path,
		client: client, clientR: clientR, up: up, upR: upR,
	}
	p.ws.register(wc)
	if routeReady != nil {
		routeReady()
	}
	defer p.ws.unregister(wc.id)

	done := make(chan struct{}, 2)
	go func() { p.copyWSFrames(wc, model.WSSend); done <- struct{}{} }()
	go func() { p.copyWSFrames(wc, model.WSRecv); done <- struct{}{} }()
	<-done
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

type streamConn struct {
	r io.Reader
	w io.Writer
	c []io.Closer
}

func newStreamConn(r io.Reader, w io.Writer, closers ...io.Closer) *streamConn {
	if r == nil {
		r = http.NoBody
	}
	return &streamConn{r: r, w: w, c: closers}
}

func (s *streamConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *streamConn) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *streamConn) Close() error {
	var err error
	for _, c := range s.c {
		if c == nil {
			continue
		}
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
func (s *streamConn) LocalAddr() net.Addr              { return dummyAddr("h2-ws") }
func (s *streamConn) RemoteAddr() net.Addr             { return dummyAddr("h2-ws") }
func (s *streamConn) SetDeadline(time.Time) error      { return nil }
func (s *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (s *streamConn) SetWriteDeadline(time.Time) error { return nil }

type flushWriter struct {
	w  http.ResponseWriter
	mu sync.Mutex
}

func (f *flushWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// prefixConn reads leftover handshake bytes then the underlying conn.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }
