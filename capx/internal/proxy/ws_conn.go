package proxy

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/hquip/capx/internal/model"
)

// wsConn is a live, upgraded WebSocket connection capx is proxying. It exposes
// direction-aware writers (guarded by per-side mutexes) so the two relay
// goroutines and user-driven replays can write frames without interleaving.
type wsConn struct {
	id     string
	url    string // ws:// or wss:// endpoint
	scheme string // http|https (for scope checks)
	host   string
	path   string

	client  net.Conn
	clientR *bufio.Reader
	up      net.Conn
	upR     *bufio.Reader

	muClient sync.Mutex // serializes writes toward the client (recv direction)
	muUp     sync.Mutex // serializes writes toward the server (send direction)
}

// writeRaw writes pre-framed bytes in the given direction under the proper lock.
// WSSend goes toward the server, WSRecv toward the client.
func (wc *wsConn) writeRaw(dir model.WSDir, b []byte) error {
	if dir == model.WSSend {
		wc.muUp.Lock()
		defer wc.muUp.Unlock()
		_, err := wc.up.Write(b)
		return err
	}
	wc.muClient.Lock()
	defer wc.muClient.Unlock()
	_, err := wc.client.Write(b)
	return err
}

// inject builds and writes a (text/binary) frame in the given direction. Frames
// toward the server are masked per RFC 6455; frames toward the client are not.
func (wc *wsConn) inject(dir model.WSDir, opcode byte, payload []byte) error {
	return wc.writeRaw(dir, buildWSFrame(opcode, payload, dir == model.WSSend))
}

// wsHub tracks active WebSocket connections so the UI/API can list them and
// replay frames onto a chosen connection (Burp-style WS repeater).
type wsHub struct {
	mu    sync.Mutex
	conns map[string]*wsConn
	seq   int
}

func newWSHub() *wsHub { return &wsHub{conns: map[string]*wsConn{}} }

func (h *wsHub) register(wc *wsConn) {
	h.mu.Lock()
	h.seq++
	wc.id = fmt.Sprintf("ws-%d", h.seq)
	h.conns[wc.id] = wc
	h.mu.Unlock()
}

func (h *wsHub) unregister(id string) {
	h.mu.Lock()
	delete(h.conns, id)
	h.mu.Unlock()
}

func (h *wsHub) closeAll() {
	h.mu.Lock()
	connections := make([]*wsConn, 0, len(h.conns))
	for _, connection := range h.conns {
		connections = append(connections, connection)
	}
	h.conns = map[string]*wsConn{}
	h.mu.Unlock()
	for _, connection := range connections {
		if connection.up != nil {
			_ = connection.up.Close()
		}
		if connection.client != nil {
			_ = connection.client.Close()
		}
	}
}

func (h *wsHub) get(id string) (*wsConn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	wc, ok := h.conns[id]
	return wc, ok
}

// WSConnInfo is a serializable summary of a live WebSocket connection.
type WSConnInfo struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
}

func (h *wsHub) list() []WSConnInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]WSConnInfo, 0, len(h.conns))
	for _, wc := range h.conns {
		out = append(out, WSConnInfo{ID: wc.id, URL: wc.url, Host: wc.host, Scheme: wc.scheme})
	}
	return out
}

// buildWSFrame assembles a single final (FIN=1) WebSocket frame for opcode with
// payload, masking the payload with a fresh random key when masked is true.
func buildWSFrame(opcode byte, payload []byte, masked bool) []byte {
	return buildWSFrameFlags(opcode, payload, masked, false)
}

func buildWSFrameFlags(opcode byte, payload []byte, masked, rsv1 bool) []byte {
	h0 := byte(0x80 | (opcode & 0x0f))
	if rsv1 {
		h0 |= 0x40
	}
	out := []byte{h0}
	n := len(payload)
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	switch {
	case n <= 125:
		out = append(out, maskBit|byte(n))
	case n <= 0xffff:
		out = append(out, maskBit|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		out = append(out, ext[:]...)
	default:
		out = append(out, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		out = append(out, ext[:]...)
	}
	if !masked {
		return append(out, payload...)
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	out = append(out, mask...)
	for i := 0; i < n; i++ {
		out = append(out, payload[i]^mask[i&3])
	}
	return out
}
