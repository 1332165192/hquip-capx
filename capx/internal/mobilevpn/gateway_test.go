package mobilevpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/store"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Both UDP ingress peers bind loopback. The client's IP stack is in memory;
// all forwarded targets are local fixtures, never a real device or public site.
type peerNetwork struct{ stack *stack.Stack }

func (n *peerNetwork) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	protocol := ipv4.ProtocolNumber
	if addr.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()), Port: addr.Port()}, protocol)
}
func (n *peerNetwork) DialUDPAddrPort(_ netip.AddrPort, addr netip.AddrPort) (net.Conn, error) {
	protocol := ipv4.ProtocolNumber
	if addr.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	return gonet.DialUDP(n.stack, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()), Port: addr.Port()}, protocol)
}
func loopbackPeer(t *testing.T, g *Gateway) *peerNetwork {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clientSession := &vpnSession{ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}, slots: make(chan struct{}, 512)}
	tun, err := newStackTun(ctx, 1280, clientSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{clientIP, clientIPv6} {
		ip := netip.MustParseAddr(raw)
		protocol := ipv4.ProtocolNumber
		if ip.Is6() {
			protocol = ipv6.ProtocolNumber
		}
		if err := tun.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err.String())
		}
	}
	peer := device.NewDevice(tun, &explicitBind{ip: netip.MustParseAddr("127.0.0.1")}, device.NewLogger(device.LogLevelSilent, ""))
	configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", g.keys.Client.hex(), g.keys.Server.public().hex(), g.Status().Endpoint)
	if err = peer.IpcSet(configuration); err == nil {
		err = peer.Up()
	}
	if err != nil {
		peer.Close()
		t.Fatal("cannot start loopback peer")
	}
	t.Cleanup(peer.Close)
	return &peerNetwork{stack: tun.stack}
}
func tunneledClient(t *testing.T, network *peerNetwork, ca []byte) *http.Client {
	t.Helper()
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		address, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		return network.DialContextTCPAddrPort(ctx, address)
	}, ForceAttemptHTTP2: true}
	if ca != nil {
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca)
		tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}
func waitPeerStats(t *testing.T, g *Gateway) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := g.Status()
		if status.LastHandshake > 0 && status.RxBytes > 0 && status.TxBytes > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("real peer handshake/data counters missing")
}

func TestVPNEncryptedPeerForwardsTCPUDPAndStops(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "through-tunnel") }))
	defer origin.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFromUDP(b)
			if err != nil {
				return
			}
			udp.WriteToUDP(append([]byte("echo:"), b[:n]...), addr)
		}
	}()
	g := New(t.TempDir(), nil)
	status, err := g.Start(Options{Routes: []string{"127.0.0.0/8"}, Packages: []string{"com.example.fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Stop(); err != nil {
			t.Error(err)
		}
	})
	if !strings.HasPrefix(status.ListenAddr, "127.0.0.1:") || !status.Running {
		t.Fatal("default ingress was not loopback")
	}
	network := loopbackPeer(t, g)
	client := tunneledClient(t, network, nil)
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "through-tunnel" {
		t.Fatalf("bad TCP forwarding %q", body)
	}
	address := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	dgram, err := network.DialUDPAddrPort(netip.AddrPort{}, address)
	if err != nil {
		t.Fatal(err)
	}
	defer dgram.Close()
	for i := 0; i < 5; i++ {
		dgram.SetDeadline(time.Now().Add(5 * time.Second))
		msg := fmt.Sprintf("datagram-%d", i)
		if _, err = dgram.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 128)
		n, err := dgram.Read(b)
		if err != nil || string(b[:n]) != "echo:"+msg {
			t.Fatalf("UDP forwarding failed: %q %v", b[:n], err)
		}
	}
	waitPeerStats(t, g)
	config, err := g.AndroidConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "IncludedApplications = com.example.fixture") || !strings.Contains(config, "AllowedIPs = 127.0.0.0/8") || !strings.Contains(config, "Endpoint = "+status.Endpoint) {
		t.Fatal("Android config missing selected settings")
	}
	b, _ := json.Marshal(g.Status())
	if strings.Contains(string(b), g.keys.Client.base64()) || strings.Contains(string(b), g.keys.Server.hex()) {
		t.Fatal("status exposed secret keys")
	}
	if err = g.Stop(); err != nil {
		t.Fatal(err)
	}
	reopened := New(g.dir, nil)
	if saved := reopened.Status(); saved.Running || len(saved.Packages) != 1 || saved.Packages[0] != "com.example.fixture" || len(saved.Routes) != 1 {
		t.Fatal("saved preferences did not restore without starting VPN")
	}
	if s := g.Status(); s.Running || s.Connections != 0 {
		t.Fatal("stop left active connections")
	}
	if _, err = g.AndroidConfig(); err == nil {
		t.Fatal("stopped VPN still exported stale config")
	}
	if _, err = g.Start(Options{Routes: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal("restart failed: ", err)
	}
}

func TestVPNHTTPAndTLSUseCapturePipeline(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			t.Setenv("CAPX_DATA_DIR", t.TempDir())
			captured := store.New(100)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				fmt.Fprint(w, string(body)+":captured")
			}))
			if scheme == "https" {
				origin.StartTLS()
			} else {
				origin.Start()
			}
			defer origin.Close()
			if scheme == "https" {
				caPath := filepath.Join(t.TempDir(), "origin.pem")
				if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("CAPX_UPSTREAM_CA_FILE", caPath)
			}
			px, err := proxy.New(captured)
			if err != nil {
				t.Fatal(err)
			}
			px.SetHTTP2Enabled(true)
			u, _ := url.Parse(origin.URL)
			_, port, _ := net.SplitHostPort(u.Host)
			pn, _ := strconv.Atoi(port)
			g := New("", px.ServeVPNConn)
			if _, err = g.Start(Options{Routes: []string{"127.0.0.0/8"}, Packages: []string{"com.example.one", "com.example.two"}, InterceptHTTP: true, HTTPPorts: []uint16{uint16(pn)}}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { g.Stop() })
			network := loopbackPeer(t, g)
			client := tunneledClient(t, network, px.CA().CertPEM())
			req, _ := http.NewRequest("POST", origin.URL+"/capture", strings.NewReader("fixture"))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Capture-Mode", "forged-web")
			req.Header.Set("X-Client-Addr", "forged-device")
			req.Header.Set("X-Capture-Peer", "forged-peer")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "fixture:captured" {
				t.Fatalf("bad intercepted reply %q", body)
			}
			if scheme == "https" && resp.ProtoMajor != 2 {
				t.Fatal("test did not negotiate downstream HTTP/2")
			}
			waitPeerStats(t, g)
			deadline := time.Now().Add(time.Second)
			for len(captured.ListHTTPTx("")) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			txs := captured.ListHTTPTx("")
			if len(txs) != 1 || txs[0].CaptureMode != "mobile-vpn" || !strings.HasPrefix(txs[0].ClientAddr, clientIP+":") || !strings.HasPrefix(txs[0].CapturePeer, "wg-") {
				t.Fatalf("transport-owned provenance missing: %#v", txs)
			}
			metadata, _ := json.Marshal(txs[0])
			if strings.Contains(string(metadata), `"source_package"`) || strings.Contains(string(metadata), `"package_name"`) || strings.Contains(string(metadata), g.keys.Client.base64()) {
				t.Fatal("multi-App traffic attributed to an App or secret exposed")
			}
		})
	}
}

func TestVPNTLSDoesNotBypassUntrustedCA(t *testing.T) {
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	px, err := proxy.New(store.New(10))
	if err != nil {
		t.Fatal(err)
	}
	var originHits atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originHits.Add(1) }))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	pn, _ := strconv.Atoi(port)
	g := New("", px.ServeVPNConn)
	if _, err = g.Start(Options{Routes: []string{"127.0.0.0/8"}, InterceptHTTP: true, HTTPPorts: []uint16{uint16(pn)}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Stop() })
	client := tunneledClient(t, loopbackPeer(t, g), nil)
	if _, err = client.Get(origin.URL); err == nil || originHits.Load() != 0 {
		t.Fatal("TLS trust was bypassed")
	}
}

func TestVPNValidationAndPrivatePersistence(t *testing.T) {
	for _, opts := range []Options{{}, {ListenAddr: "0.0.0.0:0", Routes: []string{"0.0.0.0/0"}}, {ListenAddr: "host.invalid:51820", Routes: []string{"127.0.0.0/8"}}, {Routes: []string{"garbage"}}, {Routes: []string{"127.0.0.0/8"}, Packages: []string{"com.example\nPrivateKey = secret"}}, {Routes: []string{"127.0.0.0/8"}, MTU: 999}} {
		g := New("", nil)
		if _, err := g.Start(opts); err == nil {
			g.Stop()
			t.Fatal("invalid VPN config accepted")
		}
		if g.Status().Running {
			t.Fatal("failed validation started VPN")
		}
	}
	dir := t.TempDir()
	first, err := loadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadKeys(dir)
	if err != nil || first != again {
		t.Fatal("private tunnel identity not persisted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "keys.v1"))
	if runtime.GOOS == "windows" && strings.HasPrefix(string(b), "{") {
		t.Fatal("Windows tunnel secrets not DPAPI-protected")
	}
	if err = os.WriteFile(filepath.Join(dir, "keys.v1"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadKeys(dir); err == nil {
		t.Fatal("corrupt private key file was silently replaced")
	}
}

func TestVPNStopCancelsHeldCaptureWithoutSending(t *testing.T) {
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	px, err := proxy.New(store.New(10))
	if err != nil {
		t.Fatal(err)
	}
	px.SetInterceptEnabled(true)
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	pn, _ := strconv.Atoi(port)
	g := New("", px.ServeVPNConn)
	if _, err = g.Start(Options{Routes: []string{"127.0.0.0/8"}, InterceptHTTP: true, HTTPPorts: []uint16{uint16(pn)}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Stop() })
	client := tunneledClient(t, loopbackPeer(t, g), nil)
	finished := make(chan struct{})
	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	go func() {
		req, _ := http.NewRequestWithContext(clientCtx, "GET", origin.URL+"/held", nil)
		resp, _ := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		close(finished)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for len(px.Intercept().Queue()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(px.Intercept().Queue()) != 1 {
		t.Fatal("capture did not reach actual interception queue")
	}
	if err = g.Stop(); err != nil {
		t.Fatal(err)
	}
	// Stopping the server removes the tunnel; the remote device must disable
	// its VPN or cancel outstanding requests. Backend holds are already gone.
	cancelClient()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("held capture did not cancel with VPN")
	}
	if hits.Load() != 0 || len(px.Intercept().Queue()) != 0 {
		t.Fatal("canceled capture was sent or left pending")
	}
}

func TestVPNRejectsOutOfRouteTarget(t *testing.T) {
	g := New("", nil)
	if _, err := g.Start(Options{Routes: []string{"127.0.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Stop() })
	network := loopbackPeer(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// This is a documentation-only virtual IP inside the in-memory peer stack.
	// The gateway rejects it before any native OS socket is opened.
	if c, err := network.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("198.51.100.1:443")); err == nil {
		c.Close()
		t.Fatal("out-of-route destination accepted")
	}
	if g.Status().Connections != 0 {
		t.Fatal("rejected destination opened forwarding connection")
	}
}

func TestVPNOutboundRouteGuardBlocksRawTCPUDPWithoutVisitingTargets(t *testing.T) {
	var httpHits, udpHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { httpHits.Add(1); fmt.Fprint(w, "must-not-bypass") }))
	defer origin.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 128)
		if _, _, err := udp.ReadFromUDP(buffer); err == nil {
			udpHits.Add(1)
		}
	}()
	gateway := New(t.TempDir(), nil)
	gateway.SetOutboundGuard(func(network, address string) error { return fmt.Errorf("selected HTTP proxy blocks raw %s", network) })
	if _, err = gateway.Start(Options{Routes: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	defer gateway.Stop()
	peer := loopbackPeer(t, gateway)
	client := tunneledClient(t, peer, nil)
	client.Timeout = time.Second
	if response, err := client.Get(origin.URL); err == nil {
		response.Body.Close()
		t.Fatal("blocked raw TCP was forwarded")
	}
	datagram, err := peer.DialUDPAddrPort(netip.AddrPort{}, udp.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer datagram.Close()
	datagram.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = datagram.Write([]byte("must-not-bypass"))
	buffer := make([]byte, 128)
	if _, err = datagram.Read(buffer); err == nil {
		t.Fatal("blocked UDP responded")
	}
	deadline := time.Now().Add(time.Second)
	for gateway.Status().ForwardErrors < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if httpHits.Load() != 0 || udpHits.Load() != 0 || gateway.Status().ForwardErrors < 2 {
		t.Fatalf("routing boundary bypassed: HTTP=%d UDP=%d errors=%d", httpHits.Load(), udpHits.Load(), gateway.Status().ForwardErrors)
	}
}
