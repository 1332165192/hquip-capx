// Package export renders captured capx data into portable interchange formats:
// HAR (HTTP Archive) for the proxy HTTP history, CSV for Intruder attack
// results, and a "Copy as curl" command line for a single transaction. It
// depends only on the shared model (plus the proxy result type for CSV) so it
// stays a leaf package the API layer can call directly.
package export

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/proxy"
)

// HAR (HTTP Archive 1.2) document types. Only the subset capx can populate from
// an HTTPTx is modeled; optional objects are emitted empty for validator
// compatibility.
type har struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []harNV      `json:"headers"`
	QueryString []harNV      `json:"queryString"`
	Cookies     []harNV      `json:"cookies"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
	PostData    *harPostData `json:"postData,omitempty"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Headers     []harNV    `json:"headers"`
	Cookies     []harNV    `json:"cookies"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"` // "base64" when Text is not UTF-8
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HAR renders a slice of HTTP transactions into an indented HAR 1.2 document.
func HAR(txs []*model.HTTPTx) ([]byte, error) {
	doc := har{Log: harLog{
		Version: "1.2",
		Creator: harCreator{Name: "capx", Version: "1.0"},
		Entries: make([]harEntry, 0, len(txs)),
	}}
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		doc.Log.Entries = append(doc.Log.Entries, entryFor(tx))
	}
	return json.MarshalIndent(doc, "", "  ")
}

func entryFor(tx *model.HTTPTx) harEntry {
	reqHead, reqBody := splitHeadBody(tx.ReqRaw)
	respHead, respBody := splitHeadBody(tx.RespRaw)

	reqHeaders := headerPairs(reqHead, tx.ReqHdr)
	respHeaders := headerPairs(respHead, tx.RespHdr)

	started := tx.TS
	if started.IsZero() {
		started = time.Now().UTC()
	}

	req := harRequest{
		Method:      tx.Method,
		URL:         tx.URL,
		HTTPVersion: requestProto(reqHead),
		Headers:     reqHeaders,
		QueryString: queryPairs(tx.URL),
		Cookies:     []harNV{},
		HeadersSize: -1,
		BodySize:    len(reqBody),
	}
	if reqBody != "" {
		req.PostData = &harPostData{MimeType: headerValue(reqHeaders, "Content-Type"), Text: reqBody}
	}

	contentText, contentEnc := contentBody(respBody)
	resp := harResponse{
		Status:      tx.Status,
		StatusText:  responseStatusText(respHead, tx.Status),
		HTTPVersion: responseProto(tx.Proto, respHead),
		Headers:     respHeaders,
		Cookies:     []harNV{},
		Content: harContent{
			Size:     len(respBody),
			MimeType: firstNonEmpty(tx.MIME, headerValue(respHeaders, "Content-Type")),
			Text:     contentText,
			Encoding: contentEnc,
		},
		RedirectURL: headerValue(respHeaders, "Location"),
		HeadersSize: -1,
		BodySize:    len(respBody),
	}

	return harEntry{
		StartedDateTime: started.Format(time.RFC3339Nano),
		Time:            0,
		Request:         req,
		Response:        resp,
		Timings:         harTimings{Send: 0, Wait: 0, Receive: 0},
	}
}

// Curl builds a "Copy as curl" command line for a single transaction. The Host
// and Content-Length headers are dropped (curl derives them); the request body,
// if any, is passed via --data-raw.
func Curl(tx *model.HTTPTx) string {
	reqHead, reqBody := splitHeadBody(tx.ReqRaw)
	headers := headerPairs(reqHead, tx.ReqHdr)

	var b strings.Builder
	b.WriteString("curl -i -X ")
	b.WriteString(shellQuote(firstNonEmpty(tx.Method, "GET")))
	b.WriteString(" ")
	b.WriteString(shellQuote(tx.URL))
	for _, h := range headers {
		if curlSkipHeader(h.Name) {
			continue
		}
		b.WriteString(" \\\n  -H ")
		b.WriteString(shellQuote(h.Name + ": " + h.Value))
	}
	if reqBody != "" {
		b.WriteString(" \\\n  --data-raw ")
		b.WriteString(shellQuote(reqBody))
	}
	return b.String()
}

// curlSkipHeader reports headers that should not be replayed via curl: ones
// curl sets itself (Host, Content-Length) and hop-by-hop / proxy artifacts
// that are meaningless to the origin server.
func curlSkipHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "connection", "proxy-connection", "proxy-authorization":
		return true
	}
	return false
}

// IntruderCSV renders Intruder results as CSV with a fixed header row. The
// payloads and grep-extract columns (both variable-length) are joined with
// " | " so the column count stays stable across rows.
func IntruderCSV(results []proxy.IntruderResult) ([]byte, error) {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	if err := cw.Write([]string{"index", "payloads", "status", "length", "millis", "matched", "extracts", "error"}); err != nil {
		return nil, err
	}
	for _, r := range results {
		row := []string{
			strconv.Itoa(r.Index),
			strings.Join(r.Payloads, " | "),
			strconv.Itoa(r.Status),
			strconv.Itoa(r.Length),
			strconv.FormatInt(r.Millis, 10),
			strconv.FormatBool(r.Matched),
			strings.Join(r.Extracts, " | "),
			r.Error,
		}
		if err := cw.Write(row); err != nil {
			return nil, err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- raw HTTP parsing helpers -------------------------------------------------

// splitHeadBody splits a raw HTTP message into its header block (start line +
// header lines, no trailing CRLF) and body, tolerating LF-only separators.
func splitHeadBody(raw string) (head, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, ""
}

// headerPairs parses ordered header name/value pairs from a raw header block
// (skipping the start line), preserving order and duplicates. When the raw
// block is empty it falls back to the provided map (order undefined).
func headerPairs(head string, fallback map[string]string) []harNV {
	out := []harNV{}
	if strings.TrimSpace(head) != "" {
		sc := bufio.NewScanner(strings.NewReader(head))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		first := true
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if first { // skip request/status start line
				first = false
				continue
			}
			if line == "" {
				continue
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				out = append(out, harNV{
					Name:  strings.TrimSpace(line[:idx]),
					Value: strings.TrimSpace(line[idx+1:]),
				})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for k, v := range fallback {
		out = append(out, harNV{Name: k, Value: v})
	}
	return out
}

func headerValue(headers []harNV, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// requestProto returns the HTTP version token from a request start line
// ("GET / HTTP/1.1" -> "HTTP/1.1"), defaulting to HTTP/1.1.
func requestProto(reqHead string) string {
	line := firstLine(reqHead)
	if fields := strings.Fields(line); len(fields) >= 3 {
		return fields[len(fields)-1]
	}
	return "HTTP/1.1"
}

// responseProto prefers the negotiated proto recorded on the tx, else parses
// the response start line ("HTTP/1.1 200 OK" -> "HTTP/1.1").
func responseProto(proto, respHead string) string {
	if proto != "" {
		return proto
	}
	line := firstLine(respHead)
	if fields := strings.Fields(line); len(fields) >= 1 && strings.HasPrefix(fields[0], "HTTP/") {
		return fields[0]
	}
	return "HTTP/1.1"
}

// responseStatusText extracts the reason phrase from a response start line,
// falling back to the standard text for the status code.
func responseStatusText(respHead string, status int) string {
	line := firstLine(respHead)
	if fields := strings.SplitN(line, " ", 3); len(fields) == 3 {
		return strings.TrimSpace(fields[2])
	}
	return http.StatusText(status)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimRight(s[:i], "\r")
	}
	return s
}

func queryPairs(rawURL string) []harNV {
	out := []harNV{}
	u, err := url.Parse(rawURL)
	if err != nil {
		return out
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, harNV{Name: k, Value: v})
		}
	}
	return out
}

// contentBody returns the response body as HAR content text. Non-UTF-8 bodies
// (e.g. still-compressed or binary) are base64-encoded with encoding="base64".
func contentBody(body string) (text, encoding string) {
	if body == "" {
		return "", ""
	}
	if utf8.ValidString(body) {
		return body, ""
	}
	return base64.StdEncoding.EncodeToString([]byte(body)), "base64"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// shellQuote wraps s in single quotes, escaping embedded single quotes the
// POSIX way ('\” ), so the result is safe to paste into a shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
