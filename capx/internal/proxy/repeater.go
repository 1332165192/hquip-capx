package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const maxRedirectHops = 10

// RepeaterResult is the outcome of a single Repeater send.
type RepeaterResult struct {
	Status  int    `json:"status"`
	RespRaw string `json:"resp_raw"`
	RespLen int    `json:"resp_len"`
	MIME    string `json:"mime,omitempty"`
	Millis  int64  `json:"millis"`
	Error   string `json:"error,omitempty"`

	// Redirects lists each hop followed when follow=true (empty otherwise).
	Redirects []RedirectHop `json:"redirects,omitempty"`
	// FinalURL is the URL of the response actually returned (after redirects).
	FinalURL string `json:"final_url,omitempty"`
}

// RedirectHop records one followed 3xx response.
type RedirectHop struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
	URL      string `json:"url"`
}

// SendRaw sends an edited raw HTTP request to host over scheme (http|https)
// and returns the response as raw text. This is what powers the Repeater tab;
// it does not depend on the proxy listener or MITM CA.
func SendRaw(scheme, host, raw string) RepeaterResult {
	return SendRawOpts(scheme, host, raw, false)
}

// SendRawOpts is SendRaw with optional redirect following. When follow is true,
// 3xx responses carrying a Location are chased (up to maxRedirectHops); the
// returned result is the final non-redirect response and Redirects lists the
// chain. Per RFC 7231, 303 (and 301/302 for non-GET/HEAD) downgrade to GET and
// drop the body; 307/308 preserve method and body.
func SendRawOpts(scheme, host, raw string, follow bool) RepeaterResult {
	return SendRawTLS(scheme, host, raw, follow, nil)
}

// SendRawTLS is SendRawOpts with an optional client certificate for mTLS.
func SendRawTLS(scheme, host, raw string, follow bool, clientCert *tls.Certificate) RepeaterResult {
	return sendRawTLSWithSender(scheme, host, raw, follow, clientCert, sendOnce)
}

func sendRawTLSWithSender(scheme, host, raw string, follow bool, clientCert *tls.Certificate, sender func(string, *http.Request, *tls.Certificate) (*http.Response, error)) RepeaterResult {
	req := parseEditedRequest(raw, host, scheme)
	if req == nil {
		return RepeaterResult{Error: "无法解析请求原文 (请检查请求行/换行)"}
	}
	if host == "" {
		host = req.Host
	}
	// Buffer the body so it can be replayed on method-preserving redirects.
	if req.Body != nil {
		buf, restored, err := bufferEditableBody(req.Body, req.ContentLength)
		_ = restored.Close()
		if err != nil {
			return RepeaterResult{Error: err.Error()}
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
	}

	start := time.Now()
	var hops []RedirectHop
	curScheme := scheme
	for i := 0; ; i++ {
		resp, err := sender(curScheme, req, clientCert)
		if err != nil {
			return RepeaterResult{Error: err.Error(), Redirects: hops}
		}

		loc := resp.Header.Get("Location")
		if follow && isRedirect(resp.StatusCode) && loc != "" && i < maxRedirectHops {
			_ = resp.Body.Close() // closes the underlying connection
			next, nScheme, err := redirectRequest(req, curScheme, resp.StatusCode, loc)
			if err != nil {
				return RepeaterResult{Error: "重定向解析失败: " + err.Error(), Redirects: hops}
			}
			hops = append(hops, RedirectHop{Status: resp.StatusCode, Location: loc, URL: next.URL.String()})
			req, curScheme = next, nScheme
			continue
		}

		respRaw, n := dumpResponseText(resp)
		_ = resp.Body.Close()
		return RepeaterResult{
			Status:    resp.StatusCode,
			RespRaw:   respRaw,
			RespLen:   n,
			MIME:      simpleMIME(resp.Header.Get("Content-Type")),
			Millis:    time.Since(start).Milliseconds(),
			Redirects: hops,
			FinalURL:  req.URL.String(),
		}
	}
}

// sendOnce dials, writes req, and reads one response. The caller owns resp.Body.
func sendOnce(scheme string, req *http.Request, clientCert *tls.Certificate) (*http.Response, error) {
	addr := ensurePort(req.Host, defPort(scheme))
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if scheme == "https" {
		cfg, err := upstreamTLSConfig(req.Host, "h2", "http/1.1")
		if err != nil {
			return nil, err
		}
		if clientCert != nil {
			cfg.Certificates = []tls.Certificate{*clientCert}
		}
		tlsConn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
		if err != nil {
			return nil, fmt.Errorf("连接失败: %s", err.Error())
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			if err := tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				tlsConn.Close()
				return nil, err
			}
			return sendHTTP2(tlsConn, req)
		}
		conn = tlsConn
	} else {
		conn, err = d.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("连接失败: %s", err.Error())
		}
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送失败: %s", err.Error())
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取响应失败: %s", err.Error())
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

func sendHTTP2(tlsConn *tls.Conn, req *http.Request) (*http.Response, error) {
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 握手失败: %s", err.Error())
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 请求失败: %s", err.Error())
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: tlsConn}
	return resp, nil
}

// connClosingBody closes the underlying connection when the body is closed.
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// redirectRequest builds the follow-up request for a 3xx response, resolving a
// relative Location against the current request URL and applying RFC 7231
// method/body rules.
func redirectRequest(prev *http.Request, scheme string, code int, loc string) (*http.Request, string, error) {
	base := &url.URL{Scheme: scheme, Host: prev.Host, Path: prev.URL.Path, RawQuery: prev.URL.RawQuery}
	ref, err := url.Parse(loc)
	if err != nil {
		return nil, scheme, err
	}
	target := base.ResolveReference(ref)
	nScheme := target.Scheme
	if nScheme == "" {
		nScheme = scheme
	}

	method := prev.Method
	var body io.ReadCloser
	contentLen := int64(0)
	switch code {
	case http.StatusSeeOther:
		method = http.MethodGet
	case http.StatusMovedPermanently, http.StatusFound:
		if method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
		}
	}
	// For 307/308 (and same-method 301/302) preserve the original body.
	if method == prev.Method && prev.GetBody != nil {
		if b, err := prev.GetBody(); err == nil {
			body = b
			contentLen = prev.ContentLength
		}
	}

	nr, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, nScheme, err
	}
	// Carry forward a minimal, safe header set.
	for _, h := range []string{"User-Agent", "Accept", "Accept-Encoding"} {
		if v := prev.Header.Get(h); v != "" {
			nr.Header.Set(h, v)
		}
	}
	if strings.EqualFold(prev.URL.Host, target.Host) && prev.URL.Scheme == target.Scheme {
		for _, header := range []string{"Cookie", "Authorization"} {
			if value := prev.Header.Get(header); value != "" {
				nr.Header.Set(header, value)
			}
		}
	}
	if body != nil {
		nr.ContentLength = contentLen
		for _, h := range []string{"Content-Type", "Content-Encoding"} {
			if v := prev.Header.Get(h); v != "" {
				nr.Header.Set(h, v)
			}
		}
	}
	nr.Host = target.Host
	nr.URL.Scheme = nScheme
	nr.RequestURI = ""
	return nr, nScheme, nil
}

func defPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// dumpResponseText serializes a response to raw text (status + headers + body).
// A supported Content-Encoding is rendered decompressed (with the shown
// Content-Length adjusted) so the body is human-readable in the Repeater.
func dumpResponseText(resp *http.Response) (string, int) {
	cap := captureBody(resp.Body)
	n, err := io.Copy(io.Discard, cap)
	raw := responseCaptureText(resp, cap)
	if err != nil {
		raw += "\r\n... [capx response read error: " + err.Error() + "]"
	}
	return raw, int(n)
}
