package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// maxDecompressed caps the size of a transparently-decompressed body so a
// malicious or broken upstream cannot exhaust memory ("zip bomb").
const maxDecompressed = 64 << 20 // 64 MiB

// decodableEncoding returns the normalized Content-Encoding token capx can
// transparently decode (gzip, deflate, br), or "" when the body is identity or
// uses an encoding we do not handle. Only a single encoding is supported; a
// comma-separated chain (e.g. "br, gzip") is left untouched.
func decodableEncoding(h http.Header) string {
	switch strings.TrimSpace(strings.ToLower(h.Get("Content-Encoding"))) {
	case "gzip", "x-gzip":
		return "gzip"
	case "deflate":
		return "deflate"
	case "br":
		return "br"
	case "zstd":
		return "zstd"
	}
	return ""
}

// decompress decodes body per enc. It returns ok=false when the bytes could not
// be decoded, in which case the caller must keep the original (compressed)
// bytes and treat the message as opaque.
func decompress(enc string, body []byte) ([]byte, bool) {
	var r io.Reader
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		r = zr
	case "deflate":
		// Per RFC 7230 "deflate" is zlib-wrapped, but some servers emit raw
		// DEFLATE. Try zlib first, fall back to raw flate.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zr.Close()
			r = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(body))
			defer fr.Close()
			r = fr
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		r = zr
	default:
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressed+1))
	if err != nil || len(out) > maxDecompressed {
		return nil, false
	}
	return out, true
}

// compress re-encodes body per enc so an edited (plaintext) body can be sent
// back on the wire with the same Content-Encoding the peer expects. It returns
// ok=false on failure so the caller can fall back to sending identity bytes.
func compress(enc string, body []byte) ([]byte, bool) {
	var buf bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	default:
		return nil, false
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return nil, false
	}
	if err := w.Close(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// displayBody returns the body to render in raw text for human editing
// (decompressed when h advertises a supported Content-Encoding) together with
// the header to render. When the body is decompressed the returned header is a
// clone with Content-Length set to the decompressed length so the raw text
// round-trips through the standard HTTP parser; otherwise h is returned as-is.
func displayBody(h http.Header, full []byte) (display []byte, hdr http.Header) {
	if enc := decodableEncoding(h); enc != "" {
		if dec, ok := decompress(enc, full); ok {
			clone := h.Clone()
			clone.Set("Content-Length", strconv.Itoa(len(dec)))
			return dec, clone
		}
	}
	return full, h
}

// wireBody re-encodes an edited (plaintext) body per h's Content-Encoding for
// sending on the wire. If h advertises an encoding capx cannot produce, the
// Content-Encoding header is dropped so the peer reads the identity bytes.
func wireBody(h http.Header, body []byte) []byte {
	if enc := decodableEncoding(h); enc != "" {
		if out, ok := compress(enc, body); ok {
			return out
		}
		h.Del("Content-Encoding")
	}
	return body
}
