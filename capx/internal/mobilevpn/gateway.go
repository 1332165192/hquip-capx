// Package mobilevpn provides a user-started WireGuard ingress using an
// in-memory IP stack. It never opens a system TUN or edits OS routing.
package mobilevpn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hquip/capx/internal/model"
	"golang.zx2c4.com/wireguard/device"
)

const clientIP = "10.77.0.2"
const clientIPv6 = "fd77:ca70::2"

type Options struct {
	ListenAddr    string   `json:"listen_addr"`
	Endpoint      string   `json:"endpoint,omitempty"`
	Routes        []string `json:"routes"`
	Packages      []string `json:"packages,omitempty"`
	DNS           []string `json:"dns,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	InterceptHTTP bool     `json:"intercept_http"`
	HTTPPorts     []uint16 `json:"http_ports,omitempty"`
}

type Status struct {
	Available     bool     `json:"available"`
	Running       bool     `json:"running"`
	Stopping      bool     `json:"stopping"`
	Mode          string   `json:"mode"`
	ListenAddr    string   `json:"listen_addr,omitempty"`
	Endpoint      string   `json:"endpoint,omitempty"`
	ClientIP      string   `json:"client_ip,omitempty"`
	Routes        []string `json:"routes,omitempty"`
	Packages      []string `json:"packages,omitempty"`
	DNS           []string `json:"dns,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	InterceptHTTP bool     `json:"intercept_http"`
	HTTPPorts     []uint16 `json:"http_ports,omitempty"`
	Persistent    bool     `json:"persistent"`
	LastHandshake int64    `json:"last_handshake"`
	PeerEndpoint  string   `json:"peer_endpoint,omitempty"`
	RxBytes       uint64   `json:"rx_bytes"`
	TxBytes       uint64   `json:"tx_bytes"`
	Connections   int      `json:"connections"`
	ForwardErrors uint64   `json:"forward_errors"`
	Note          string   `json:"note"`
}

type HTTPHandler func(context.Context, net.Conn, string)
type Gateway struct {
	mu            sync.Mutex
	dir           string
	keys          privateKeys
	handleHTTP    HTTPHandler
	outboundGuard atomic.Pointer[outboundPolicy]
	session       *vpnSession
	last          Status
	settingsError string
}

func New(stateDir string, handleHTTP HTTPHandler) *Gateway {
	g := &Gateway{dir: stateDir, handleHTTP: handleHTTP}
	opts, err := readSettings(stateDir)
	if err != nil {
		g.settingsError = err.Error()
	} else if len(opts.Routes) > 0 {
		g.last = statusOptions(opts)
	}
	return g
}

// SetOutboundGuard installs the host's routing boundary. It never changes
// mobile routes. Call before Start; HTTP capture uses its dedicated handler.
type outboundPolicy struct{ check func(string, string) error }

func (g *Gateway) SetOutboundGuard(guard func(string, string) error) {
	g.outboundGuard.Store(&outboundPolicy{check: guard})
}
func (g *Gateway) SetStateDir(dir string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session != nil {
		return errors.New("stop VPN before switching private state directory")
	}
	opts, err := readSettings(dir)
	if err != nil {
		return err
	}
	g.dir = dir
	g.keys = privateKeys{}
	g.settingsError = ""
	g.last = statusOptions(opts)
	return nil
}

var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func normalizeOptions(opts Options) (Options, netip.AddrPort, []netip.Prefix, error) {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}
	listen, err := netip.ParseAddrPort(opts.ListenAddr)
	if err != nil {
		return opts, listen, nil, errors.New("listen_addr must be an explicit IP:port (default loopback)")
	}
	opts.ListenAddr = listen.String()
	if opts.Endpoint != "" {
		endpoint, err := netip.ParseAddrPort(opts.Endpoint)
		if err != nil || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
			return opts, listen, nil, errors.New("endpoint must be a concrete reachable IP:port")
		}
		opts.Endpoint = endpoint.String()
	} else if listen.Addr().IsUnspecified() {
		return opts, listen, nil, errors.New("wildcard bind requires an explicit reachable endpoint for the phone")
	}
	if len(opts.Routes) == 0 || len(opts.Routes) > 128 {
		return opts, listen, nil, errors.New("select at least one explicit client route; full routing requires 0.0.0.0/0 and/or ::/0")
	}
	var routes []netip.Prefix
	seen := map[string]bool{}
	normalized := []string{}
	for _, raw := range opts.Routes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return opts, listen, nil, errors.New("invalid client route prefix")
		}
		p = p.Masked()
		if !seen[p.String()] {
			seen[p.String()] = true
			routes = append(routes, p)
			normalized = append(normalized, p.String())
		}
	}
	opts.Routes = normalized
	if len(opts.Packages) > 128 {
		return opts, listen, nil, errors.New("too many included applications")
	}
	seen = map[string]bool{}
	packages := []string{}
	for _, raw := range opts.Packages {
		pkg := strings.TrimSpace(raw)
		if !packageName.MatchString(pkg) || len(pkg) > 255 {
			return opts, listen, nil, errors.New("invalid Android package name")
		}
		if !seen[pkg] {
			seen[pkg] = true
			packages = append(packages, pkg)
		}
	}
	opts.Packages = packages
	if len(opts.DNS) > 8 {
		return opts, listen, nil, errors.New("too many DNS addresses")
	}
	dns := []string{}
	for _, raw := range opts.DNS {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
			return opts, listen, nil, errors.New("DNS must be an IP address")
		}
		dns = append(dns, ip.String())
	}
	opts.DNS = dns
	if opts.MTU == 0 {
		opts.MTU = 1280
	}
	if opts.MTU < 1280 || opts.MTU > 1420 {
		return opts, listen, nil, errors.New("MTU must be between 1280 and 1420")
	}
	if len(opts.HTTPPorts) == 0 {
		opts.HTTPPorts = []uint16{80, 443}
	}
	if len(opts.HTTPPorts) > 32 {
		return opts, listen, nil, errors.New("too many HTTP capture ports")
	}
	for _, p := range opts.HTTPPorts {
		if p == 0 {
			return opts, listen, nil, errors.New("HTTP capture port cannot be zero")
		}
	}
	return opts, listen, routes, nil
}

func (g *Gateway) Start(opts Options) (Status, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session != nil {
		return g.statusLocked(), errors.New("VPN is already started or cleaning up; stop it before changing configuration")
	}
	opts, listen, routes, err := normalizeOptions(opts)
	if err != nil {
		return g.statusLocked(), err
	}
	if opts.InterceptHTTP && g.handleHTTP == nil {
		return g.statusLocked(), errors.New("HTTP capture unavailable; disable interception to use forwarding only")
	}
	keys := g.keys
	if keys.Version == 0 {
		keys, err = loadKeys(g.dir)
		if err != nil {
			return g.statusLocked(), err
		}
	}
	if err = saveSettings(g.dir, opts); err != nil {
		return g.statusLocked(), err
	}
	g.last = statusOptions(opts)
	g.settingsError = ""
	ctx, cancel := context.WithCancel(context.Background())
	publicPeer := keys.Client.public()
	peerHash := sha256.Sum256(publicPeer[:])
	ctx = model.WithCaptureTransport(ctx, model.CaptureTransportInfo{Mode: "mobile-vpn", PeerID: fmt.Sprintf("wg-%x", peerHash[:8])})
	s := &vpnSession{ctx: ctx, cancel: cancel, opts: opts, routes: routes, handleHTTP: g.handleHTTP, outboundGuard: func(network, address string) error {
		if policy := g.outboundGuard.Load(); policy != nil && policy.check != nil {
			return policy.check(network, address)
		}
		return nil
	}, conns: map[net.Conn]struct{}{}, slots: make(chan struct{}, 512)}
	stackTun, err := newStackTun(ctx, opts.MTU, s)
	if err != nil {
		cancel()
		return g.statusLocked(), errors.New("cannot initialize user-space VPN stack: " + err.Error())
	}
	s.stackTun = stackTun
	bind := &explicitBind{ip: listen.Addr()}
	bind.onOpen = func(liveAddr netip.AddrPort) {
		endpoint := liveAddr
		if opts.Endpoint != "" {
			endpoint, _ = netip.ParseAddrPort(opts.Endpoint)
			if endpoint.Port() == 0 {
				endpoint = netip.AddrPortFrom(endpoint.Addr(), liveAddr.Port())
			}
		}
		s.opts.ListenAddr = liveAddr.String()
		s.opts.Endpoint = endpoint.String()
	}
	s.device = device.NewDevice(stackTun, bind, device.NewLogger(device.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\nallowed_ip=%s/128\n", keys.Server.hex(), listen.Port(), keys.Client.public().hex(), clientIP, clientIPv6)
	if err = s.device.IpcSet(uapi); err == nil {
		err = s.device.Up()
	}
	if err != nil {
		s.shutdown()
		return g.statusLocked(), errors.New("cannot start user-space WireGuard listener")
	}
	g.keys = keys
	g.settingsError = ""
	g.session = s
	return g.statusLocked(), nil
}

func (g *Gateway) Stop() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session == nil {
		return nil
	}
	g.last = g.statusLocked()
	s := g.session
	s.shutdown()
	done := make(chan struct{})
	go func() { s.handlers.Wait(); close(done) }()
	select {
	case <-done:
		g.session = nil
		g.last.Running = false
		g.last.Stopping = false
		g.last.Connections = 0
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("VPN stopped receiving traffic; connection cleanup is still pending")
	}
}
func (g *Gateway) Status() Status { g.mu.Lock(); defer g.mu.Unlock(); return g.statusLocked() }
func (g *Gateway) statusLocked() Status {
	status := g.last
	status.Available = true
	status.Mode = "wireguard-userspace"
	status.Persistent = g.dir != ""
	status.Note = "请在 Android WireGuard 中导入配置并手动启用；改包名后需重新导入。HTTP/TLS 抓包需手机信任 CA；其它 TCP/UDP 普通转发，不经过 HTTP 二级代理。来源只标记 VPN 通道，不推测逐 App 归属。停止服务后需手机停用隧道。"
	if g.settingsError != "" {
		status.Note = g.settingsError + ". " + status.Note
	}
	if s := g.session; s != nil {
		status.Running = !s.closed.Load()
		status.Stopping = s.closed.Load()
		status.ListenAddr = s.opts.ListenAddr
		status.Endpoint = s.opts.Endpoint
		status.ClientIP = clientIP
		status.Routes = append([]string(nil), s.opts.Routes...)
		status.Packages = append([]string(nil), s.opts.Packages...)
		status.DNS = append([]string(nil), s.opts.DNS...)
		status.MTU = s.opts.MTU
		status.InterceptHTTP = s.opts.InterceptHTTP
		status.HTTPPorts = append([]uint16(nil), s.opts.HTTPPorts...)
		status.ForwardErrors = s.forwardErrors.Load()
		s.connMu.Lock()
		status.Connections = len(s.conns)
		s.connMu.Unlock()
		if data, err := s.device.IpcGet(); err == nil {
			for _, line := range strings.Split(data, "\n") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				switch parts[0] {
				case "last_handshake_time_sec":
					status.LastHandshake, _ = strconv.ParseInt(parts[1], 10, 64)
				case "rx_bytes":
					status.RxBytes, _ = strconv.ParseUint(parts[1], 10, 64)
				case "tx_bytes":
					status.TxBytes, _ = strconv.ParseUint(parts[1], 10, 64)
				case "endpoint":
					status.PeerEndpoint = parts[1]
				}
			}
		}
	}
	return status
}

func (g *Gateway) AndroidConfig() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session == nil || g.session.closed.Load() {
		return "", errors.New("start VPN before exporting its phone configuration")
	}
	opts := g.session.opts
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nMTU = %d\n", g.keys.Client.base64(), clientIP, clientIPv6, opts.MTU)
	if len(opts.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(opts.DNS, ", "))
	}
	if len(opts.Packages) > 0 {
		fmt.Fprintf(&b, "IncludedApplications = %s\n", strings.Join(opts.Packages, ", "))
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", g.keys.Server.public().base64(), opts.Endpoint, strings.Join(opts.Routes, ", "))
	return b.String(), nil
}

type vpnSession struct {
	ctx           context.Context
	cancel        context.CancelFunc
	opts          Options
	routes        []netip.Prefix
	handleHTTP    HTTPHandler
	outboundGuard func(string, string) error
	device        *device.Device
	stackTun      *stackTun
	closed        atomic.Bool
	shutdownOnce  sync.Once
	connMu        sync.Mutex
	conns         map[net.Conn]struct{}
	slots         chan struct{}
	handlers      sync.WaitGroup
	forwardErrors atomic.Uint64
}

func (s *vpnSession) shutdown() {
	s.shutdownOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		s.connMu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.connMu.Unlock()
		if s.device != nil {
			s.device.Close()
		} else if s.stackTun != nil {
			s.stackTun.Close()
		}
	})
}
func (s *vpnSession) begin() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed.Load() {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		s.handlers.Add(1)
		return true
	default:
		return false
	}
}
func (s *vpnSession) end() { <-s.slots; s.handlers.Done() }
func (s *vpnSession) track(c net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed.Load() {
		c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}
func (s *vpnSession) untrack(c net.Conn) {
	c.Close()
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
}
func (s *vpnSession) allowed(dst netip.AddrPort) bool {
	ip := dst.Addr()
	if dst.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() || ip.String() == clientIP || ip.String() == clientIPv6 {
		return false
	}
	if own, err := netip.ParseAddrPort(s.opts.ListenAddr); err == nil && dst == own {
		return false
	}
	for _, prefix := range s.routes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (s *vpnSession) capturePort(port uint16) bool {
	if !s.opts.InterceptHTTP {
		return false
	}
	for _, p := range s.opts.HTTPPorts {
		if p == port {
			return true
		}
	}
	return false
}
