package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

// dumpRequest makes a bounded preview without discarding the unread suffix.
// Live forwarding uses requestCaptureText after streaming, not this preview.
func dumpRequest(r *http.Request) (raw string, body io.ReadCloser) {
	body = r.Body
	if body == nil {
		body = http.NoBody
	}
	prefix, _ := io.ReadAll(io.LimitReader(body, int64(bodyCaptureLimit()+1)))
	restored := &replayBody{Reader: io.MultiReader(bytes.NewReader(prefix), body), Closer: body}
	r.Body = restored
	cap := captureBody(http.NoBody)
	cap.data, cap.total = prefix, int64(len(prefix))
	return requestCaptureText(r, cap), restored
}

func requestCaptureText(r *http.Request, cap *bodyCapture) string {
	var body, out strings.Builder
	hdr := appendCapturedBody(&body, r.Header, cap, false).Clone()
	if r.ContentLength > 0 && hdr.Get("Content-Length") == "" {
		hdr.Set("Content-Length", fmt.Sprint(r.ContentLength))
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&out, "%s %s %s\r\n", r.Method, path, proto)
	if r.Host != "" {
		fmt.Fprintf(&out, "Host: %s\r\n", r.Host)
	}
	writeHeaders(&out, hdr)
	out.WriteString("\r\n")
	out.WriteString(body.String())
	return out.String()
}

func editableRequestText(r *http.Request, full []byte) string {
	data, hdr := displayBody(r.Header, full)
	hdr = hdr.Clone()
	hdr.Del("Transfer-Encoding")
	hdr.Set("Content-Length", fmt.Sprint(len(data)))
	var out strings.Builder
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&out, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), proto)
	if r.Host != "" {
		fmt.Fprintf(&out, "Host: %s\r\n", r.Host)
	}
	writeHeaders(&out, hdr)
	out.WriteString("\r\n")
	out.Write(data)
	return out.String()
}

func responseCaptureText(resp *http.Response, cap *bodyCapture) string {
	var body, out strings.Builder
	hdr := appendCapturedBody(&body, resp.Header, cap, true)
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	fmt.Fprintf(&out, "%s %s\r\n", proto, status)
	writeHeaders(&out, hdr)
	out.WriteString("\r\n")
	out.WriteString(body.String())
	return out.String()
}

// Copy hop-by-hop-independent headers. net/http owns the downstream framing.
func forwardHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, name := range strings.Split(out.Get("Connection"), ",") {
		out.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		out.Del(name)
	}
	return out
}

type responseFlushWriter struct{ w http.ResponseWriter }

func (f responseFlushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		if fl, ok := f.w.(http.Flusher); ok {
			fl.Flush()
		}
	}
	return n, err
}

// writeResponse streams the real entity and retains only a bounded history
// prefix. Flush both headers and chunks so SSE/long polls do not wait for EOF.
func writeResponse(w http.ResponseWriter, resp *http.Response) (string, int, error) {
	cap := captureBody(resp.Body)
	for k, vs := range forwardHeaders(resp.Header) {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	hasBody := responseHasBody(resp)
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		// A 304 representation length is optional; omitting it also avoids
		// HTTP/2 clients treating it as promised DATA after END_STREAM.
		w.Header().Del("Content-Length")
	}
	if hasBody && len(resp.Trailer) > 0 {
		w.Header().Del("Content-Length")
		for k := range resp.Trailer {
			w.Header().Add("Trailer", k)
		}
	}
	announcedTrailers := make(map[string]bool, len(resp.Trailer))
	for k := range resp.Trailer {
		announcedTrailers[k] = true
	}
	w.WriteHeader(resp.StatusCode)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	var n int64
	var err error
	if hasBody {
		n, err = io.CopyBuffer(responseFlushWriter{w}, cap, make([]byte, 32<<10))
	}
	if err == nil && hasBody {
		for k, vs := range resp.Trailer {
			key := k
			if !announcedTrailers[k] {
				key = http.TrailerPrefix + k
			}
			w.Header()[key] = vs
		}
	}
	return responseCaptureText(resp, cap), int(n), err
}

// writeResponseConn delegates HTTP/1.1 framing to net/http. Unknown lengths use
// chunked encoding, including trailers, rather than buffering or closing an
// otherwise reusable MITM connection. HEAD/204/304 never consume a body.
func writeResponseConn(conn io.Writer, resp *http.Response) (string, int, error) {
	cap := captureBody(resp.Body)
	wire := *resp
	wire.Header = forwardHeaders(resp.Header)
	wire.Proto, wire.ProtoMajor, wire.ProtoMinor = "HTTP/1.1", 1, 1
	wire.Body = cap
	wire.TransferEncoding = nil
	if !responseHasBody(resp) {
		wire.Body = http.NoBody
	} else if wire.ContentLength < 0 || len(wire.Trailer) > 0 {
		wire.ContentLength = -1
		wire.TransferEncoding = []string{"chunked"}
	}
	err := wire.Write(conn)
	_, n := cap.snapshot()
	return responseCaptureText(resp, cap), int(n), err
}

// toUTF8 transcodes a text body to UTF-8 when it advertises (via Content-Type
// or an HTML <meta charset>) a non-UTF-8 charset like GBK/GB2312/GB18030/Big5,
// so the captured history is readable instead of mojibake (□□□). Non-text or
// already-UTF-8 bodies are returned unchanged.
func toUTF8(h http.Header, body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	ct := strings.ToLower(h.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "text") && !strings.Contains(ct, "json") &&
		!strings.Contains(ct, "xml") && !strings.Contains(ct, "javascript") && !strings.Contains(ct, "html") {
		return body
	}
	e, name, _ := charset.DetermineEncoding(body, h.Get("Content-Type"))
	if e == nil || name == "" || name == "utf-8" {
		return body
	}
	out, _, err := transform.Bytes(e.NewDecoder(), body)
	if err != nil || len(out) == 0 {
		return body
	}
	return out
}

func writeHeaders(b *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

func appendBody(b *strings.Builder, full []byte) {
	if len(full) == 0 {
		return
	}
	capN := bodyCaptureLimit()
	if len(full) > capN {
		b.Write(full[:capN])
		fmt.Fprintf(b, "\r\n... [%d more bytes truncated by capx]", len(full)-capN)
		return
	}
	b.Write(full)
}

func bodyCaptureLimit() int {
	if v := maxBodyCaptureOverride.Load(); v > 0 {
		return int(v)
	}
	return maxBodyCapture
}

func rawTruncated(raw string) bool {
	return strings.Contains(raw, "truncated by capx")
}

// dumpResponse serializes a response to raw text (status line + headers + body)
// for the interceptor to present for editing, and resets resp.Body so the
// caller can still stream it. The body is buffered with an explicit 16 MiB
// editing limit; a larger body returns an error without losing its suffix. Bodies
// carrying a supported Content-Encoding are rendered decompressed (with the
// shown Content-Length adjusted) so they can be edited; resp.Body is left as
// the original on-wire bytes for a forward-unchanged decision.
func dumpResponse(resp *http.Response) (raw string, body []byte, err error) {
	if err := rejectStreamingEdit(resp.Header); err != nil {
		return "", nil, err
	}
	full, restored, err := bufferEditableBody(resp.Body, resp.ContentLength)
	resp.Body = restored
	if err != nil {
		return "", nil, err
	}

	disp, hdr := displayBody(resp.Header, full)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	writeHeaders(&b, hdr)
	b.WriteString("\r\n")
	b.Write(toUTF8(hdr, disp))
	return b.String(), full, nil
}

// parseEditedResponse parses user-edited raw response text back into the given
// response in place (status line, headers, body). Content-Length is recomputed
// and chunked framing dropped so the client sees a consistent message. Returns
// false on parse failure (caller keeps the original response).
func parseEditedResponse(raw string, resp *http.Response) bool {
	br := bufio.NewReader(strings.NewReader(normalizeCRLF(raw)))
	nr, err := http.ReadResponse(br, nil)
	if err != nil {
		return false
	}
	full, restored, err := bufferEditableBody(nr.Body, nr.ContentLength)
	_ = restored.Close()
	if err != nil {
		return false
	}

	resp.StatusCode = nr.StatusCode
	resp.Status = nr.Status
	resp.Header = nr.Header
	// Recompress the edited (plaintext) body per the response's
	// Content-Encoding so the client still receives valid encoded bytes.
	wire := wireBody(resp.Header, full)
	setResponseBody(resp, wire)
	return true
}

// parseEditedRequest turns user-edited raw request text back into a request
// targeting host over scheme. Returns nil on parse failure (caller keeps original).
func parseEditedRequest(raw, host, scheme string) *http.Request {
	br := bufio.NewReader(strings.NewReader(normalizeCRLF(raw)))
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil
	}
	if req.Host == "" {
		req.Host = host
	}
	req.URL.Scheme = scheme
	req.URL.Host = req.Host
	req.RequestURI = ""
	// Recompress an edited (plaintext) body if the request advertises a
	// supported Content-Encoding so the upstream receives valid encoded bytes.
	full, restored, err := bufferEditableBody(req.Body, req.ContentLength)
	_ = restored.Close()
	if err != nil {
		return nil
	}
	setRequestBody(req, wireBody(req.Header, full))
	return req
}

func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func capStr(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
