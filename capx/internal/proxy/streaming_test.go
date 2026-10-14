package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hquip/capx/internal/store"
)

// All listeners and origins in this suite are ephemeral loopback fixtures.
func streamingFixture(t *testing.T, mode string, handler http.HandlerFunc) (*Proxy, *http.Client, string) {
	t.Helper()
	trustFixtureCA(t)
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	up := httptest.NewUnstartedServer(handler)
	if mode == "http" {
		up.Start()
	} else {
		up.EnableHTTP2 = mode == "h2"
		up.StartTLS()
	}
	t.Cleanup(up.Close)
	p, err := New(store.New(20))
	if err != nil {
		t.Fatal(err)
	}
	p.SetHTTP2Enabled(mode == "h2")
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(); p.tr.CloseIdleConnections(); p.trH2.CloseIdleConnections() })
	_, addr := p.Status()
	proxyURL, _ := url.Parse("http://" + addr)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CA().CertPEM())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: mode == "h2"}
	t.Cleanup(tr.CloseIdleConnections)
	return p, &http.Client{Transport: tr, Timeout: 10 * time.Second}, up.URL
}

// Regression for the original review reproduction: limits apply to history
// copies, never to the actual forwarded request or response entity.
func TestRegressionLargeBodiesUnchanged(t *testing.T) {
	SetMaxBodyCapture(1024)
	defer SetMaxBodyCapture(0)
	payload := strings.Repeat("x", maxEditableBody+4096)
	req, _ := http.NewRequest("POST", "http://fixture.local/upload", strings.NewReader(payload))
	_, body := dumpRequest(req)
	got, err := io.ReadAll(body)
	if err != nil || string(got) != payload {
		t.Fatalf("preview changed body: length=%d error=%v", len(got), err)
	}
	for _, conn := range []bool{false, true} {
		resp := &http.Response{Proto: "HTTP/1.1", Status: "200 OK", StatusCode: 200, Header: http.Header{"Content-Length": {strconv.Itoa(len(payload))}}, Body: io.NopCloser(strings.NewReader(payload)), ContentLength: int64(len(payload))}
		var raw string
		var n int
		if conn {
			var wire bytes.Buffer
			raw, n, err = writeResponseConn(&wire, resp)
			parsed, e := http.ReadResponse(bufio.NewReader(&wire), req)
			if e != nil {
				t.Fatal(e)
			}
			got, e = io.ReadAll(parsed.Body)
			if e != nil || string(got) != payload {
				t.Fatalf("HTTPS body corrupted: length=%d error=%v", len(got), e)
			}
		} else {
			w := httptest.NewRecorder()
			raw, n, err = writeResponse(w, resp)
			if w.Body.String() != payload {
				t.Fatal("HTTP body corrupted")
			}
		}
		if err != nil || n != len(payload) || !rawTruncated(raw) || len(raw) > 2048 {
			t.Fatalf("conn=%v count=%d raw_length=%d error=%v", conn, n, len(raw), err)
		}
	}
}

func TestRegressionProxyLargeUploadDownloadProtocols(t *testing.T) {
	SetMaxBodyCapture(1024)
	defer SetMaxBodyCapture(0)
	payload := strings.Repeat("0123456789abcdef", (maxEditableBody/16)+513)
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			p, client, origin := streamingFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil || n != int64(len(payload)) {
						http.Error(w, fmt.Sprintf("received=%d error=%v", n, err), 400)
						return
					}
					fmt.Fprint(w, n)
					return
				}
				if r.URL.Query().Get("fixed") == "1" {
					w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				}
				_, _ = io.Copy(w, strings.NewReader(payload))
			})
			for _, fixed := range []bool{true, false} {
				var body io.Reader = strings.NewReader(payload)
				if !fixed {
					body = io.NopCloser(body)
				}
				req, _ := http.NewRequest("POST", origin+"/upload", body)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				result, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || string(result) != strconv.Itoa(len(payload)) {
					t.Fatalf("upload fixed=%v status=%d result=%s error=%v", fixed, resp.StatusCode, result, err)
				}
				resp, err = client.Get(origin + "/download?fixed=" + strconv.Itoa(map[bool]int{true: 1}[fixed]))
				if err != nil {
					t.Fatal(err)
				}
				result, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(result) != payload {
					t.Fatalf("download fixed=%v length=%d error=%v", fixed, len(result), err)
				}
				if mode == "h2" && resp.ProtoMajor != 2 {
					t.Fatalf("expected actual HTTP/2, got %s", resp.Proto)
				}
			}
			// Recording happens just after the final write, so wait for its store update.
			deadline := time.Now().Add(time.Second)
			for len(p.st.ListHTTPTx("")) < 4 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			for _, tx := range p.st.ListHTTPTx("") {
				if !tx.BodyTruncated || len(tx.ReqRaw)+len(tx.RespRaw) > 4096 {
					t.Fatalf("history capture not bounded: %+v", tx)
				}
			}
		})
	}
}

// The origin deliberately stays open until the client sees its first event.
// The old ReadAll-before-Write path deadlocked this handshake until timeout.
func TestRegressionStreamingResponse(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			p, client, origin := streamingFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: hello\n\n")
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
			// A header-only rule must not accidentally enable body buffering.
			mustAdd(t, p.rules, &Rule{Enabled: true, Target: "response", Where: "header", Header: "X-Review", Match: "^$", Replace: "streamed"})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", origin, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("response headers waited for EOF:", err)
			}
			defer resp.Body.Close()
			line, err := bufio.NewReader(resp.Body).ReadString('\n')
			if err != nil || line != "data: hello\n" || resp.Header.Get("X-Review") != "streamed" {
				t.Fatalf("first SSE event=%q error=%v", line, err)
			}
		})
	}
}

func TestRegressionProxyStreamingUpload(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			first := make(chan struct{})
			p, client, origin := streamingFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(r.Body, buf); err != nil {
					return
				}
				close(first)
				rest, _ := io.ReadAll(r.Body)
				fmt.Fprint(w, string(buf)+string(rest))
			})
			mustAdd(t, p.rules, &Rule{Enabled: true, Target: "request", Where: "header", Header: "X-Review", Match: "^$", Replace: "streamed"})
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			result := make(chan error, 1)
			go func() {
				resp, err := client.Post(origin, "application/octet-stream", pr)
				if err == nil {
					defer resp.Body.Close()
					body, e := io.ReadAll(resp.Body)
					if e != nil || string(body) != "firstlast" {
						err = fmt.Errorf("body=%q error=%v", body, e)
					}
				}
				result <- err
			}()
			if _, err := pw.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-first:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream did not receive first upload chunk before EOF")
			}
			pw.Write([]byte("last"))
			pw.Close()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegressionProxyNoBodyAndTrailersKeepAlive(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			_, client, origin := streamingFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/head":
					w.Header().Set("Content-Length", "123456789")
				case "/204":
					w.WriteHeader(204)
				case "/304":
					w.Header().Set("Content-Length", "42")
					w.WriteHeader(304)
				default:
					w.Header().Add("Trailer", "X-Digest")
					fmt.Fprint(w, "chunk")
					w.(http.Flusher).Flush()
					w.Header().Set("X-Digest", "complete")
				}
			})
			for i, path := range []string{"/head", "/204", "/304", "/trailers", "/trailers"} {
				method := "GET"
				if path == "/head" {
					method = "HEAD"
				}
				req, _ := http.NewRequest(method, origin+path, nil)
				var reused bool
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || (i > 0 && !reused) {
					t.Fatalf("%s reuse=%v error=%v", path, reused, err)
				}
				if path == "/trailers" {
					if string(body) != "chunk" || resp.Trailer.Get("X-Digest") != "complete" {
						t.Fatalf("chunk/trailer mismatch: %q %v", body, resp.Trailer)
					}
				} else if len(body) != 0 {
					t.Fatalf("%s unexpectedly had a body", path)
				}
				if path == "/head" && resp.ContentLength != 123456789 {
					t.Fatalf("HEAD lost representation length: %d", resp.ContentLength)
				}
			}
		})
	}
}

func TestRegressionProxyBodyEditingLimitIsExplicit(t *testing.T) {
	payload := strings.Repeat("x", maxEditableBody+1)
	for _, target := range []string{"request", "response", "event-stream"} {
		t.Run(target, func(t *testing.T) {
			var hits atomic.Int32
			p, client, origin := streamingFixture(t, "http", func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				if target == "event-stream" {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: first\n\n")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				io.Copy(w, strings.NewReader(payload))
			})
			ruleTarget := target
			if target == "event-stream" {
				ruleTarget = "response"
			}
			mustAdd(t, p.rules, &Rule{Enabled: true, Target: ruleTarget, Where: "body", Match: "not-present", Replace: "changed"})
			req, _ := http.NewRequest("POST", origin, strings.NewReader(payload))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := 502
			if target == "request" {
				want = 413
				if hits.Load() != 0 {
					t.Fatal("partial edited request reached origin")
				}
			}
			if resp.StatusCode != want || !strings.Contains(string(body), "disable body editing/interception") {
				t.Fatalf("expected explicit failure: status=%d body=%q", resp.StatusCode, body)
			}
		})
	}
}

func TestRegressionBufferEditableFailurePreservesUnreadSuffix(t *testing.T) {
	payload := strings.Repeat("x", maxEditableBody+4096)
	_, body, err := bufferEditableBody(io.NopCloser(strings.NewReader(payload)), -1)
	if err == nil {
		t.Fatal("oversized edit was not rejected")
	}
	got, err := io.ReadAll(body)
	if err != nil || string(got) != payload {
		t.Fatalf("failed edit discarded bytes: count=%d error=%v", len(got), err)
	}
}

type unchangedBodyMutator struct{}

func (unchangedBodyMutator) WantsRequest() bool  { return true }
func (unchangedBodyMutator) WantsResponse() bool { return true }
func (unchangedBodyMutator) MutateRequest(_, _, _ string, h map[string]string, b []byte) (map[string]string, []byte, bool) {
	return h, b, false
}
func (unchangedBodyMutator) MutateResponse(_ int, h map[string]string, b []byte) (map[string]string, []byte, bool) {
	return h, b, false
}

func TestRegressionNoOpScriptPreservesBodyAboveHistoryLimit(t *testing.T) {
	p := &Proxy{mutator: unchangedBodyMutator{}}
	payload := strings.Repeat("x", (2<<20)+1)
	req, _ := http.NewRequest("POST", "http://fixture.local", strings.NewReader(payload))
	if err := p.applyRequestMutator(req); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil || string(got) != payload || req.ContentLength != int64(len(payload)) {
		t.Fatal("no-op request script changed/truncated the body")
	}
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(payload)), ContentLength: int64(len(payload))}
	if err := p.applyResponseMutator(resp); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(resp.Body)
	if err != nil || string(got) != payload || resp.ContentLength != int64(len(payload)) {
		t.Fatal("no-op response script changed/truncated the body")
	}
}

func TestRegressionAllBodyEditingPathsRejectOversize(t *testing.T) {
	payload := strings.Repeat("x", maxEditableBody+1)
	for _, operation := range []string{"request-rule", "response-rule", "request-condition", "response-condition", "session", "request-script", "response-script", "request-intercept", "response-intercept"} {
		t.Run(operation, func(t *testing.T) {
			p := newTestProxy()
			p.session = newSessionEngine()
			p.mutator = unchangedBodyMutator{}
			req, _ := http.NewRequest("POST", "http://fixture.local", strings.NewReader(payload))
			resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(payload)), ContentLength: int64(len(payload))}
			var err error
			var body io.Reader = req.Body
			switch operation {
			case "request-rule", "response-rule", "request-condition", "response-condition":
				target := strings.Split(operation, "-")[0]
				rule := &Rule{Enabled: true, Target: target, Where: "body", Match: "not-present", Replace: "modified"}
				if strings.HasSuffix(operation, "condition") {
					rule.Where, rule.Header, rule.CondWhere, rule.CondMatch = "header", "X-Test", "body", "not-present"
				}
				mustAdd(t, p.rules, rule)
				if target == "request" {
					_, err = p.rules.applyRequest(req)
					body = req.Body
				} else {
					err = p.rules.applyResponse(resp)
					body = resp.Body
				}
			case "session":
				p.session.SetRules([]SessionRule{{Enabled: true, SubstBody: true}})
				_, err = p.session.applyToRequest(req)
				body = req.Body
			case "request-script":
				err = p.applyRequestMutator(req)
				body = req.Body
			case "response-script":
				err = p.applyResponseMutator(resp)
				body = resp.Body
			case "request-intercept":
				p.SetInterceptEnabled(true)
				_, _, _, err = p.interceptRequest("http", req, "")
				body = req.Body
			case "response-intercept":
				p.SetInterceptRespEnabled(true)
				_, err = p.interceptResponse("http", req.Host, resp)
				body = resp.Body
			}
			if err == nil || !strings.Contains(err.Error(), "editing limit exceeded") {
				t.Fatalf("expected explicit oversize error, got %v", err)
			}
			if n, err := io.Copy(io.Discard, body); err != nil || n != int64(len(payload)) {
				t.Fatalf("failed edit lost original bytes: count=%d error=%v", n, err)
			}
		})
	}
}

func TestRegressionProxyClientCancellationClosesUpstream(t *testing.T) {
	for _, mode := range []string{"http", "h2"} {
		t.Run(mode, func(t *testing.T) {
			closed := make(chan struct{})
			_, client, origin := streamingFixture(t, mode, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: hello\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(closed)
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", origin, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = bufio.NewReader(resp.Body).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			resp.Body.Close()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("downstream cancellation left upstream body open")
			}
		})
	}
}
