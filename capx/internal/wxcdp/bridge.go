// Package wxcdp connects to an operator-supplied, standard CDP WebSocket.
// This implementation contains no WeChat hooks, offset tables or private protocols.
package wxcdp

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

type response struct {
	raw json.RawMessage
	err error
}
type Bridge struct {
	mu       sync.Mutex
	writeMu  sync.Mutex
	conn     *websocket.Conn
	endpoint string
	next     uint64
	pending  map[uint64]chan response
}

func New(_ func(string)) *Bridge { return &Bridge{pending: make(map[uint64]chan response)} }

func normalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "ws" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("CAPX_CDP_WS must be a standard ws:// loopback URL without credentials or query")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return "", errors.New("CDP endpoint must use a loopback IP and explicit port")
	}
	u.Host = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	return u.String(), nil
}

func (b *Bridge) Start() (map[string]any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return b.statusLocked(), nil
	}
	endpoint, err := normalizeEndpoint(os.Getenv("CAPX_CDP_WS"))
	if err != nil {
		return nil, err
	}
	config, err := websocket.NewConfig(endpoint, "http://127.0.0.1/")
	if err != nil {
		return nil, errors.New("invalid CDP configuration")
	}
	config.Dialer = &net.Dialer{Timeout: 5 * time.Second}
	conn, err := websocket.DialConfig(config)
	if err != nil {
		return nil, errors.New("cannot connect to external CDP endpoint")
	}
	conn.MaxPayloadBytes = 16 << 20
	b.conn, b.endpoint = conn, endpoint
	go b.receive(conn)
	return b.statusLocked(), nil
}

func (b *Bridge) statusLocked() map[string]any {
	devtools := ""
	if b.conn != nil {
		devtools = "devtools://devtools/bundled/inspector.html?ws=" + strings.TrimPrefix(b.endpoint, "ws://")
	}
	return map[string]any{"running": b.conn != nil, "miniapp_connected": b.conn != nil, "provider": "external-cdp", "ws": b.endpoint, "devtools_url": devtools, "devtools_clients": 0, "debug_port": 0, "cdp_port": 0}
}
func (b *Bridge) Status() map[string]any { b.mu.Lock(); defer b.mu.Unlock(); return b.statusLocked() }

func (b *Bridge) disconnected(conn *websocket.Conn) {
	b.mu.Lock()
	if b.conn == conn {
		b.conn = nil
		for id, ch := range b.pending {
			ch <- response{err: errors.New("CDP connection closed")}
			delete(b.pending, id)
		}
	}
	b.mu.Unlock()
	conn.Close()
}
func (b *Bridge) Stop() error {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	if conn != nil {
		b.disconnected(conn)
	}
	return nil
}
func (b *Bridge) receive(conn *websocket.Conn) {
	defer b.disconnected(conn)
	for {
		var raw string
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return
		}
		var envelope struct {
			ID uint64 `json:"id"`
		}
		if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.ID == 0 {
			continue
		}
		b.mu.Lock()
		if b.conn == conn {
			if ch := b.pending[envelope.ID]; ch != nil {
				delete(b.pending, envelope.ID)
				ch <- response{raw: json.RawMessage(raw)}
			}
		}
		b.mu.Unlock()
	}
}

func (b *Bridge) Call(method string, params any, timeout time.Duration) (json.RawMessage, error) {
	if method == "" {
		return nil, errors.New("CDP method required")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 8 * time.Second
	}
	b.mu.Lock()
	conn := b.conn
	if conn == nil {
		b.mu.Unlock()
		return nil, errors.New("start the external CDP connection first")
	}
	b.next++
	id := b.next
	ch := make(chan response, 1)
	b.pending[id] = ch
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pending, id); b.mu.Unlock() }()
	raw, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	b.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(timeout))
	err = websocket.Message.Send(conn, string(raw))
	b.writeMu.Unlock()
	if err != nil {
		b.disconnected(conn)
		return nil, errors.New("CDP send failed")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case reply := <-ch:
		return reply.raw, reply.err
	case <-timer.C:
		return nil, errors.New("CDP response timed out")
	}
}
func (b *Bridge) Eval(expression string, timeout time.Duration) (string, error) {
	raw, err := b.Call("Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "awaitPromise": true, "userGesture": true}, timeout)
	return string(raw), err
}
