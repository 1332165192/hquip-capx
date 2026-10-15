package wxcdp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	WebSocket string `json:"webSocketDebuggerUrl"`
}

// Discover uses the provider's standard /json/list endpoint. Selection remains
// explicit: a browser endpoint is not silently substituted for a page target.
func Discover(ctx context.Context, raw string) ([]Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/" && u.Path != "/json/list") {
		return nil, errors.New("CDP discovery requires http://127.0.0.1:port")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("CDP discovery must use an explicit loopback port")
	}
	u.Host = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	u.Path = "/json/list"
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid CDP discovery request")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("CDP discovery redirects are not supported")
	}}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("无法连接本机 CDP 服务，请先启动调试提供方")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("CDP 服务未提供 /json/list")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("CDP discovery response exceeds limit")
	}
	var targets []Target
	if json.Unmarshal(data, &targets) != nil || len(targets) > 2048 {
		return nil, errors.New("CDP 目标列表无效")
	}
	out := []Target{}
	for _, target := range targets {
		endpoint, err := normalizeEndpoint(target.WebSocket)
		if err != nil {
			continue
		}
		parsed, _ := url.Parse(endpoint)
		// Provider responses cannot redirect selection to another debug service.
		if parsed.Host != u.Host {
			continue
		}
		target.WebSocket = endpoint
		out = append(out, target)
	}
	return out, nil
}
