package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// dialRoutedTarget establishes one origin socket through the selected local
// HTTP(S) proxy using CONNECT. HTTP proxy failures never fall back to direct.
// A capture bridge's explicitly selected route retains its own lifetime.
func (p *Proxy) dialRoutedTarget(ctx context.Context, scheme, host string, certificate *tls.Certificate) (net.Conn, error) {
	secure := scheme == "https" || scheme == "wss"
	port := "80"
	httpScheme := "http"
	if secure {
		port = "443"
		httpScheme = "https"
	}
	address := ensurePort(host, port)
	request := &http.Request{URL: &url.URL{Scheme: httpScheme, Host: address}, Header: make(http.Header)}
	route := p.upstream.Load()
	var proxyURL *url.URL
	var err error
	roots := p.tr.TLSClientConfig.RootCAs
	bridge := bridgeForContext(ctx)
	if bridge != nil {
		if err = bridge.ctx.Err(); err != nil {
			return nil, err
		}
		if p.bridgeOwnPort(bridge.upstream.Host, bridge.addr) || p.bridgeOwnPort(address, bridge.addr) || samePort(address, bridge.upstream.Host) {
			return nil, errors.New("secondary route would create a local proxy loop")
		}
		proxyURL = bridge.upstream
		roots = bridge.tr.TLSClientConfig.RootCAs
	} else {
		proxyURL, err = p.selectRoute(route, request)
		if err != nil {
			return nil, err
		}
		if route != nil && route.tr != nil {
			roots = route.tr.TLSClientConfig.RootCAs
		}
	}
	connectContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var stopBridge func() bool
	if bridge != nil {
		stopBridge = context.AfterFunc(bridge.ctx, cancel)
		defer stopBridge()
	}
	target := address
	if proxyURL != nil {
		target = ensurePort(proxyURL.Host, "80")
		if proxyURL.Scheme == "https" {
			target = ensurePort(proxyURL.Host, "443")
		}
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(connectContext, "tcp", target)
	if err != nil {
		return nil, errors.New("cannot connect to selected upstream route")
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	stopContext := context.AfterFunc(connectContext, func() { _ = conn.Close() })
	defer stopContext()
	if deadline, ok := connectContext.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if proxyURL != nil {
		if proxyURL.Scheme == "https" {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			if err = tlsConn.HandshakeContext(connectContext); err != nil {
				return nil, errors.New("secondary HTTPS proxy certificate or TLS handshake failed")
			}
			conn = tlsConn
		}
		tunnel := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			authorization := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
			tunnel.Header.Set("Proxy-Authorization", "Basic "+authorization)
		}
		if err = tunnel.Write(conn); err != nil {
			return nil, errors.New("secondary proxy CONNECT write failed")
		}
		reader := bufio.NewReader(io.LimitReader(conn, 64<<10))
		response, readErr := http.ReadResponse(reader, tunnel)
		if readErr != nil {
			return nil, errors.New("secondary proxy CONNECT response failed")
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("secondary proxy CONNECT returned HTTP %d", response.StatusCode)
		}
		// ReadResponse may prefetch bytes immediately following the CONNECT header.
		// Preserve them without imposing the temporary header bound on the tunnel.
		buffered := reader.Buffered()
		if buffered > 0 {
			prefix, _ := reader.Peek(buffered)
			conn = &prefixConn{Conn: conn, r: bufio.NewReader(io.MultiReader(bytes.NewReader(append([]byte(nil), prefix...)), conn))}
		}
	}
	if secure {
		config := &tls.Config{RootCAs: roots, ServerName: stripPort(host), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		if certificate != nil {
			config.Certificates = []tls.Certificate{*certificate}
		}
		tlsConn := tls.Client(conn, config)
		if err = tlsConn.HandshakeContext(connectContext); err != nil {
			return nil, errors.New("origin TLS handshake through selected route failed")
		}
		conn = tlsConn
	}
	if bridge != nil {
		tracked, err := bridge.track(conn)
		if err != nil {
			return nil, err
		}
		conn = tracked
	}
	_ = conn.SetDeadline(time.Time{})
	success = true
	return conn, nil
}

func (p *Proxy) SendRawTLSContext(ctx context.Context, scheme, host, raw string, follow bool, certificate *tls.Certificate) RepeaterResult {
	return sendRawTLSWithSender(scheme, host, raw, follow, certificate, func(scheme string, request *http.Request, certificate *tls.Certificate) (*http.Response, error) {
		request = request.Clone(ctx)
		conn, err := p.dialRoutedTarget(ctx, scheme, request.Host, certificate)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		if err = conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			stop()
			conn.Close()
			return nil, err
		}
		request.Header.Del("Proxy-Authorization")
		if err = request.Write(conn); err != nil {
			stop()
			conn.Close()
			return nil, errors.New("repeater request through selected route failed")
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			stop()
			conn.Close()
			return nil, errors.New("repeater response through selected route failed")
		}
		response.Body = &routedClosingBody{connClosingBody: &connClosingBody{ReadCloser: response.Body, conn: conn}, stop: stop}
		return response, nil
	})
}

type routedClosingBody struct {
	*connClosingBody
	stop func() bool
}

func (b *routedClosingBody) Close() error { b.stop(); return b.connClosingBody.Close() }
func (p *Proxy) SendRawTLS(scheme, host, raw string, follow bool, certificate *tls.Certificate) RepeaterResult {
	return p.SendRawTLSContext(context.Background(), scheme, host, raw, follow, certificate)
}
