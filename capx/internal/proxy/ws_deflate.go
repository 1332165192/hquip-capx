package proxy

import (
	"bytes"
	"compress/flate"
	"io"
	"strings"
)

// stripPMDExtensions removes permessage-deflate (and any other WS extension)
// from a header value so Chrome/Firefox do not compress frames. Compressed
// payloads would otherwise show up as garbage in history / match-replace.
func stripPMDExtensions(v string) string {
	if v == "" {
		return v
	}
	parts := strings.Split(v, ",")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name := p
		if i := strings.IndexByte(p, ';'); i >= 0 {
			name = strings.TrimSpace(p[:i])
		}
		if strings.EqualFold(name, "permessage-deflate") {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, ", ")
}

func stripWSExtensionsHeaders(h interface {
	Get(string) string
	Del(string)
	Set(string, string)
}) {
	v := h.Get("Sec-WebSocket-Extensions")
	if v == "" {
		return
	}
	stripped := stripPMDExtensions(v)
	if stripped == "" {
		h.Del("Sec-WebSocket-Extensions")
		return
	}
	h.Set("Sec-WebSocket-Extensions", stripped)
}

func stripWSExtensionsBlock(block []byte) []byte {
	text := string(block)
	const key = "sec-websocket-extensions:"
	out := text
	for {
		i := strings.Index(strings.ToLower(out), key)
		if i < 0 {
			break
		}
		end := i
		for end < len(out) && out[end] != '\n' {
			end++
		}
		if end < len(out) {
			end++
		}
		line := out[i:end]
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			break
		}
		val := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(line[colon+1:], "\n"), "\r"))
		stripped := stripPMDExtensions(val)
		if stripped == "" {
			out = out[:i] + out[end:]
			continue
		}
		out = out[:i] + "Sec-WebSocket-Extensions: " + stripped + "\r\n" + out[end:]
		break
	}
	return []byte(out)
}

// inflatePMD inflates an RFC 7692 permessage-deflate payload (no zlib wrapper;
// a 00 00 ff ff trailer is appended for flate).
func inflatePMD(b []byte) ([]byte, error) {
	in := make([]byte, 0, len(b)+4)
	in = append(in, b...)
	in = append(in, 0x00, 0x00, 0xff, 0xff)
	r := flate.NewReader(bytes.NewReader(in))
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 16<<20))
}

func deflatePMD(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) >= 4 && bytes.Equal(out[len(out)-4:], []byte{0x00, 0x00, 0xff, 0xff}) {
		out = out[:len(out)-4]
	}
	return out, nil
}
