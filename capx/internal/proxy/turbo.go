package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// turboMaxRequests caps a single Turbo run so a runaway config can't open an
// unbounded number of sockets.
const turboMaxRequests = 1000

// TurboConfig drives the Turbo engine: a high-concurrency / race-condition
// sender modelled on Burp's Turbo Intruder. It sends the same raw request many
// times (optionally substituting a single §...§ with a payload list),
// either as a fast worker pool or as a synchronized "gate" that withholds the
// final byte of every request and releases them together (last-byte sync) to
// squeeze many requests into the same race window.
type TurboConfig struct {
	Scheme      string   `json:"scheme"`
	Host        string   `json:"host"`
	Raw         string   `json:"raw"`         // raw request template (§...§ optional)
	Payloads    []string `json:"payloads"`    // optional: one request per payload (replaces first §...§)
	Count       int      `json:"count"`       // requests to send when Payloads is empty
	Concurrency int      `json:"concurrency"` // parallel workers (non-gate mode)
	Gate        bool     `json:"gate"`        // last-byte synchronization race mode
	DelayMs     int      `json:"delay_ms"`    // gate: settle time before release (default 60ms)
}

// TurboResult is one sent request's outcome.
type TurboResult struct {
	Index   int    `json:"index"`
	Payload string `json:"payload,omitempty"`
	Status  int    `json:"status"`
	Length  int    `json:"length"`
	Millis  int64  `json:"millis"`
	RespRaw string `json:"resp_raw,omitempty"`
	Error   string `json:"error,omitempty"`
}

// turboApplyMarker replaces the first §...§ span in base with payload. If no
// ker is present base is returned unchanged.
func turboApplyMarker(base, payload string) string {
	const m = "§"
	i := strings.Index(base, m)
	if i < 0 {
		return base
	}
	rest := base[i+len(m):]
	j := strings.Index(rest, m)
	if j < 0 {
		return base
	}
	return base[:i] + payload + rest[j+len(m):]
}

// turboNormalize converts line endings to CRLF and guarantees a header
// terminator so the request is byte-complete on the wire.
func turboNormalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	if !strings.Contains(s, "\r\n\r\n") {
		s += "\r\n\r\n"
	}
	return s
}

func turboDial(scheme, addr, host string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	if scheme == "https" {
		config, err := upstreamTLSConfig(host)
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(d, "tcp", addr, config)
	}
	return d.Dial("tcp", addr)
}

// RunTurbo executes a Turbo run and returns one result per request.
func RunTurbo(cfg TurboConfig) ([]TurboResult, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := cfg.Host
	if host == "" {
		return nil, fmt.Errorf("缺少目标主机 host")
	}
	base := turboNormalize(cfg.Raw)
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("缺少请求模板 raw")
	}

	// Build the per-request byte slices.
	type job struct {
		payload string
		raw     []byte
	}
	var jobsList []job
	if len(cfg.Payloads) > 0 {
		for _, p := range cfg.Payloads {
			jobsList = append(jobsList, job{p, []byte(turboApplyMarker(base, p))})
		}
	} else {
		n := cfg.Count
		if n < 1 {
			n = 1
		}
		for i := 0; i < n; i++ {
			jobsList = append(jobsList, job{"", []byte(base)})
		}
	}
	if len(jobsList) > turboMaxRequests {
		return nil, fmt.Errorf("请求数 %d 超过上限 %d", len(jobsList), turboMaxRequests)
	}

	addr := ensurePort(host, defPort(scheme))
	results := make([]TurboResult, len(jobsList))

	if cfg.Gate {
		// Last-byte synchronization: every worker connects and writes its
		// request except the final byte, then blocks. Once all are staged we
		// close the release channel so the final bytes go out near-simultaneously.
		release := make(chan struct{})
		var ready, done sync.WaitGroup
		ready.Add(len(jobsList))
		for i := range jobsList {
			done.Add(1)
			go func(i int) {
				defer done.Done()
				r := TurboResult{Index: i, Payload: jobsList[i].payload}
				conn, err := turboDial(scheme, addr, host)
				if err != nil {
					r.Error = "连接失败: " + err.Error()
					results[i] = r
					ready.Done()
					<-release
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				body := jobsList[i].raw
				if len(body) > 1 {
					if _, err := conn.Write(body[:len(body)-1]); err != nil {
						r.Error = "发送失败: " + err.Error()
						results[i] = r
						ready.Done()
						<-release
						return
					}
				}
				ready.Done()
				<-release // barrier: all workers fire the last byte together
				st := time.Now()
				if _, err := conn.Write(body[len(body)-1:]); err != nil {
					r.Error = "发送失败: " + err.Error()
					results[i] = r
					return
				}
				resp, err := readRawResponse(conn)
				if err != nil {
					r.Error = "读取响应失败: " + err.Error()
					results[i] = r
					return
				}
				respRaw, n := dumpResponseText(resp)
				_ = resp.Body.Close()
				r.Status, r.Length, r.Millis = resp.StatusCode, n, time.Since(st).Milliseconds()
				r.RespRaw = capStr(respRaw, 16<<10)
				results[i] = r
			}(i)
		}
		ready.Wait()
		settle := cfg.DelayMs
		if settle <= 0 {
			settle = 60
		}
		time.Sleep(time.Duration(settle) * time.Millisecond)
		close(release)
		done.Wait()
		return results, nil
	}

	// High-throughput worker pool (non-gate).
	conc := cfg.Concurrency
	if conc < 1 {
		conc = 20
	}
	if conc > 200 {
		conc = 200
	}
	jobsCh := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobsCh {
				res := SendRawOpts(scheme, host, string(jobsList[i].raw), false)
				results[i] = TurboResult{
					Index: i, Payload: jobsList[i].payload,
					Status: res.Status, Length: res.RespLen, Millis: res.Millis,
					Error: res.Error, RespRaw: capStr(res.RespRaw, 16<<10),
				}
			}
		}()
	}
	for i := range jobsList {
		jobsCh <- i
	}
	close(jobsCh)
	wg.Wait()
	return results, nil
}

// readRawResponse reads a single HTTP response from a raw connection.
func readRawResponse(conn net.Conn) (*http.Response, error) {
	return http.ReadResponse(bufio.NewReader(conn), nil)
}
