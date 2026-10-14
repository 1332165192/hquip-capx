package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Only operations that require the entire entity (editing, body rules and
// scripts) have a body-size limit. Ordinary forwarding never uses this limit.
const maxEditableBody = 16 << 20

type replayBody struct {
	io.Reader
	io.Closer
}

// bufferEditableBody restores every byte, including the unread suffix on
// failure. Callers must surface errors rather than operate on a partial body.
func bufferEditableBody(body io.ReadCloser, length int64) ([]byte, io.ReadCloser, error) {
	if body == nil || body == http.NoBody {
		return nil, http.NoBody, nil
	}
	if length > maxEditableBody {
		return nil, body, fmt.Errorf("capx body editing limit exceeded (%d bytes; maximum %d); disable body editing/interception to stream this message", length, maxEditableBody)
	}
	data, err := io.ReadAll(io.LimitReader(body, maxEditableBody+1))
	if err != nil || len(data) > maxEditableBody {
		restored := &replayBody{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}
		if err != nil {
			return nil, restored, fmt.Errorf("capx could not read complete body for editing: %w", err)
		}
		return nil, restored, fmt.Errorf("capx body editing limit exceeded (maximum %d bytes); disable body editing/interception to stream this message", maxEditableBody)
	}
	_ = body.Close()
	return data, io.NopCloser(bytes.NewReader(data)), nil
}

func rejectStreamingEdit(h http.Header) error {
	if strings.EqualFold(strings.TrimSpace(strings.Split(h.Get("Content-Type"), ";")[0]), "text/event-stream") {
		return fmt.Errorf("capx cannot apply whole-body editing/interception to text/event-stream; disable body editing/interception to stream this response")
	}
	return nil
}

func setRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		r.Body = http.NoBody
	}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Trailer = nil
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Trailer")
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
}

func setResponseBody(r *http.Response, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Trailer = nil
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Trailer")
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
}

// bodyCapture records a bounded prefix while the transport consumes the real
// body. A transport can finish receiving response headers before its request
// writer exits, so snapshots and Read must be synchronized.
type bodyCapture struct {
	io.ReadCloser
	mu    sync.Mutex
	data  []byte
	total int64
	limit int
}

func captureBody(body io.ReadCloser) *bodyCapture {
	if body == nil {
		body = http.NoBody
	}
	return &bodyCapture{ReadCloser: body, limit: bodyCaptureLimit()}
}

func (b *bodyCapture) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.total += int64(n)
	keep := n
	if keep > b.limit-len(b.data) {
		keep = b.limit - len(b.data)
	}
	if keep > 0 {
		b.data = append(b.data, p[:keep]...)
	}
	b.mu.Unlock()
	return n, err
}

func (b *bodyCapture) snapshot() ([]byte, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.total
}

func appendCapturedBody(out *strings.Builder, h http.Header, b *bodyCapture, utf8 bool) http.Header {
	data, total := b.snapshot()
	captured := len(data)
	hdr := h
	if total == int64(len(data)) {
		data, hdr = displayBody(h, data)
	}
	if utf8 {
		data = toUTF8(hdr, data)
	}
	appendBody(out, data)
	if total > int64(captured) {
		// Count omitted on-wire bytes, not decompressed/display bytes.
		fmt.Fprintf(out, "\r\n... [%d more wire bytes truncated by capx]", total-int64(captured))
	}
	return hdr
}

func responseHasBody(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified &&
		(resp.Request == nil || resp.Request.Method != http.MethodHead)
}
