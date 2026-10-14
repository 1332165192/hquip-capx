package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hquip/capx/internal/model"
)

// tunnelWebSocket handles a plain (ws://) upgrade through the ResponseWriter
// path by hijacking the client connection.
func (p *Proxy) tunnelWebSocket(w http.ResponseWriter, r *http.Request, scheme string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	p.pumpWS(client, bufio.NewReader(client), r, scheme)
}

// tunnelWebSocketConn handles a wss:// upgrade on an already-decrypted MITM
// connection (the request was read off clientR).
func (p *Proxy) tunnelWebSocketConn(client net.Conn, clientR *bufio.Reader, r *http.Request, scheme string) {
	p.pumpWS(client, clientR, r, scheme)
}

// pumpWS forwards the upgrade handshake to the upstream, relays the 101
// response, then relays WebSocket frames in both directions while recording
// each frame. Non-101 upstreams fall back to a plain byte tunnel.
func (p *Proxy) pumpWS(client net.Conn, clientR *bufio.Reader, r *http.Request, scheme string) {
	p.upstreamMu.Lock()
	locked := true
	defer func() {
		if locked {
			p.upstreamMu.Unlock()
		}
	}()
	up, err := p.dialRoutedTarget(r.Context(), scheme, r.Host, nil)
	if err != nil {
		writeRawResponse(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()

	stripWSExtensionsHeaders(r.Header)
	r.Header.Del("Proxy-Authorization")
	reqRaw, body := dumpRequest(r)
	r.Body = body
	if err := r.Write(up); err != nil {
		return
	}

	upR := bufio.NewReader(up)
	statusLine, headerBlock, err := readHeaderBlock(upR)
	if err != nil {
		return
	}
	headerBlock = stripWSExtensionsBlock(headerBlock)
	if _, err := client.Write(headerBlock); err != nil {
		return
	}

	url := scheme + "://" + r.Host + r.URL.RequestURI()
	p.recordWSUpgrade(scheme, r, statusLine, reqRaw, headerBlock)

	if !strings.Contains(statusLine, "101") {
		locked = false
		p.upstreamMu.Unlock()
		// Not a WebSocket upgrade after all: plain bidirectional tunnel.
		go func() {
			_, _ = io.Copy(up, clientR)
			if cw, ok := up.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		_, _ = io.Copy(client, upR)
		return
	}

	httpScheme := "http"
	if scheme == "wss" {
		httpScheme = "https"
	}
	wc := &wsConn{
		url: url, scheme: httpScheme, host: r.Host, path: r.URL.Path,
		client: client, clientR: clientR, up: up, upR: upR,
	}
	p.ws.register(wc)
	locked = false
	p.upstreamMu.Unlock()
	defer p.ws.unregister(wc.id)

	done := make(chan struct{}, 2)
	go func() { p.copyWSFrames(wc, model.WSSend); done <- struct{}{} }()
	go func() { p.copyWSFrames(wc, model.WSRecv); done <- struct{}{} }()
	<-done
}

// dialUpstreamWS connects to the upstream for a ws/wss upgrade.
func dialUpstreamWS(scheme, host string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	if scheme == "wss" {
		config, err := upstreamTLSConfig(host)
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(d, "tcp", ensurePort(host, "443"), config)
	}
	return d.Dial("tcp", ensurePort(host, "80"))
}

func ensurePort(host, def string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, def)
}

// readHeaderBlock reads an HTTP status line + header block (up to the blank
// line) verbatim, returning the status line and the full raw block.
func readHeaderBlock(r *bufio.Reader) (statusLine string, block []byte, err error) {
	var buf []byte
	for {
		line, e := r.ReadBytes('\n')
		if len(line) > 0 {
			buf = append(buf, line...)
			if statusLine == "" {
				statusLine = strings.TrimRight(string(line), "\r\n")
			}
		}
		if e != nil {
			return statusLine, buf, e
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return statusLine, buf, nil
		}
	}
}

// recordWSUpgrade records the upgrade handshake as an HTTP transaction so it
// also shows in HTTP history, mapping ws->http / wss->https.
func (p *Proxy) recordWSUpgrade(scheme string, r *http.Request, statusLine, reqRaw string, headerBlock []byte) {
	provenance := model.CaptureTransport(r.Context())
	httpScheme := "http"
	if scheme == "wss" {
		httpScheme = "https"
	}
	inScope := p.scope.InScope(httpScheme, r.Host, r.URL.Path)
	status := 0
	if parts := strings.Fields(statusLine); len(parts) >= 2 {
		if n, err := atoiSafe(parts[1]); err == nil {
			status = n
		}
	}
	p.st.AddHTTPTx(&model.HTTPTx{
		Scheme: httpScheme, Method: r.Method, Host: r.Host,
		Path: r.URL.RequestURI(), URL: httpScheme + "://" + r.Host + r.URL.RequestURI(),
		Status: status, ReqRaw: reqRaw, RespRaw: string(headerBlock),
		CaptureMode: provenance.Mode, ClientAddr: provenance.ClientAddr, CapturePeer: provenance.PeerID,
		MIME: "websocket", Decrypted: scheme == "wss", ReqHdr: flattenHeader(r.Header),
		InScope: inScope, OutOfScope: !inScope, BodyTruncated: rawTruncated(reqRaw) || rawTruncated(string(headerBlock)),
	})
}

// copyWSFrames reads WebSocket frames for direction dir off the connection,
// optionally pauses text/binary frames for interactive edit/drop, records them,
// and forwards them. Control frames (ping/pong/close) are always relayed as-is.
func (p *Proxy) copyWSFrames(wc *wsConn, dir model.WSDir) {
	src := wc.upR
	if dir == model.WSSend {
		src = wc.clientR
	}
	var asm wsAssembler
	for {
		frame, h0, opcode, fin, payload, err := readWSFrameEx(src)
		if err != nil {
			return
		}
		if opcode >= 0x8 { // control frames: never fragmented
			if err := wc.writeRaw(dir, frame); err != nil {
				return
			}
			if opcode == 0x8 {
				return
			}
			continue
		}
		if opcode == 0x0 {
			if !asm.active() {
				continue // orphan continuation: drop, do not forward
			}
			if !asm.append(payload) {
				return
			}
			if !fin {
				continue
			}
			if err := p.handleWSData(wc, dir, asm.opcode, asm.rsv1, asm.buf); err != nil {
				return
			}
			asm.reset()
			continue
		}
		rsv1 := h0&0x40 != 0
		if !fin {
			if !asm.start(opcode, rsv1, payload) {
				return
			}
			continue
		}
		if !rsv1 && p.canPassthroughWS(wc) {
			if err := wc.writeRaw(dir, frame); err != nil {
				return
			}
			p.recordWSFrame(wc, dir, opcode, payload)
			p.applyWSAutoReply(wc, dir, opcode, payload)
			continue
		}
		if err := p.handleWSData(wc, dir, opcode, rsv1, payload); err != nil {
			return
		}
	}
}

const wsMaxMessage = 16 << 20

type wsAssembler struct {
	opcode byte
	rsv1   bool
	buf    []byte
}

func (a *wsAssembler) active() bool { return a.opcode == 0x1 || a.opcode == 0x2 }

func (a *wsAssembler) start(opcode byte, rsv1 bool, payload []byte) bool {
	if len(payload) > wsMaxMessage {
		a.reset()
		return false
	}
	a.opcode = opcode
	a.rsv1 = rsv1
	a.buf = append(a.buf[:0], payload...)
	return true
}

func (a *wsAssembler) append(payload []byte) bool {
	if uint64(len(a.buf))+uint64(len(payload)) > uint64(wsMaxMessage) {
		a.reset()
		return false
	}
	a.buf = append(a.buf, payload...)
	return true
}

func (a *wsAssembler) reset() { a.opcode, a.rsv1, a.buf = 0, false, a.buf[:0] }

func (p *Proxy) canPassthroughWS(wc *wsConn) bool {
	if p.interceptWS.Load() && p.scope.InScope(wc.scheme, wc.host, wc.path) {
		return false
	}
	return p.wsRules == nil || !p.wsRules.hasEnabled()
}

func (p *Proxy) handleWSData(wc *wsConn, dir model.WSDir, opcode byte, rsv1 bool, payload []byte) error {
	plain := payload
	compressed := rsv1
	if rsv1 {
		dec, err := inflatePMD(payload)
		if err != nil {
			compressed = false
		} else {
			plain = dec
		}
	}
	editedPayload, drop, _ := p.interceptWSFrame(wc, dir, opcode, plain)
	if drop {
		return nil
	}
	if p.wsRules != nil {
		var ruleDrop bool
		editedPayload, ruleDrop, _ = p.wsRules.apply(wc, dir, opcode, editedPayload)
		if ruleDrop {
			return nil
		}
	}
	outPayload, rsvOut := editedPayload, false
	if compressed {
		if enc, err := deflatePMD(editedPayload); err == nil {
			outPayload, rsvOut = enc, true
		}
	}
	if err := wc.writeRaw(dir, buildWSFrameFlags(opcode, outPayload, dir == model.WSSend, rsvOut)); err != nil {
		return err
	}
	p.recordWSFrame(wc, dir, opcode, editedPayload)
	p.applyWSAutoReply(wc, dir, opcode, editedPayload)
	return nil
}

// recordWSFrame stores a text/binary frame payload in the history store.
func (p *Proxy) recordWSFrame(wc *wsConn, dir model.WSDir, opcode byte, payload []byte) *model.WSMessage {
	if wc == nil {
		return nil
	}
	if opcode == 0x2 {
		return p.st.AddWSMessage(&model.WSMessage{ConnID: wc.id, URL: wc.url, Dir: dir, Opcode: "binary",
			Length: len(payload), Data: base64.StdEncoding.EncodeToString(payload)})
	}
	return p.st.AddWSMessage(&model.WSMessage{ConnID: wc.id, URL: wc.url, Dir: dir, Opcode: "text",
		Length: len(payload), Data: string(payload)})
}

// interceptWSFrame holds a text/binary frame for manual editing when WS
// interception is enabled and the connection is in scope. It returns the
// (possibly edited) payload, whether the user dropped the frame, and whether
// the payload was changed (so the caller re-frames it).
func (p *Proxy) interceptWSFrame(wc *wsConn, dir model.WSDir, opcode byte, payload []byte) (out []byte, drop, changed bool) {
	if !p.interceptWS.Load() || !p.scope.InScope(wc.scheme, wc.host, wc.path) {
		return payload, false, false
	}
	opStr, raw := "text", string(payload)
	if opcode == 0x2 {
		opStr, raw = "binary", base64.StdEncoding.EncodeToString(payload)
	}
	edited, dropped := p.icept.holdMsg(&HeldRequest{
		Kind: "ws", Scheme: wc.scheme, Host: wc.host, Raw: raw,
		ConnID: wc.id, Dir: string(dir), Opcode: opStr, URL: wc.url,
	})
	if dropped {
		return payload, true, false
	}
	if edited == "" || edited == raw {
		return payload, false, false
	}
	if opcode == 0x2 {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(edited)); err == nil {
			return dec, false, true
		}
		return payload, false, false // bad base64: forward original unchanged
	}
	return []byte(edited), false, true
}

// readWSFrame reads one frame, returning the raw frame bytes (for forwarding),
// the opcode, and the unmasked payload (for recording).
func readWSFrame(r *bufio.Reader) (raw []byte, opcode byte, payload []byte, err error) {
	raw, _, opcode, _, payload, err = readWSFrameEx(r)
	return raw, opcode, payload, err
}

func readWSFrameEx(r *bufio.Reader) (raw []byte, h0, opcode byte, fin bool, payload []byte, err error) {
	h0, err = r.ReadByte()
	if err != nil {
		return nil, 0, 0, false, nil, err
	}
	h1, err := r.ReadByte()
	if err != nil {
		return nil, 0, 0, false, nil, err
	}
	raw = []byte{h0, h1}
	opcode = h0 & 0x0f
	fin = h0&0x80 != 0
	masked := h1&0x80 != 0
	ln := uint64(h1 & 0x7f)

	switch ln {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		raw = append(raw, ext...)
		ln = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		raw = append(raw, ext...)
		ln = binary.BigEndian.Uint64(ext)
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(r, mask); err != nil {
			return
		}
		raw = append(raw, mask...)
	}

	if ln > 64<<20 { // 64 MiB sanity cap
		return raw, h0, opcode, fin, nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, ln)
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	raw = append(raw, data...)

	payload = make([]byte, ln)
	if masked {
		for i := range data {
			payload[i] = data[i] ^ mask[i&3]
		}
	} else {
		copy(payload, data)
	}
	return raw, h0, opcode, fin, payload, nil
}

func atoiSafe(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, io.ErrUnexpectedEOF
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
