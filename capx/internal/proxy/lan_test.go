package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestLANUsesCurrentMITMAndUpstreamWithoutChangingUSB(t *testing.T) {
	upstream := newFakeBridgeUpstream(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "phone-fixture") }))
	defer origin.Close()
	p := newBridgeProxy(t)
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	_, usbAddress := p.Status()
	if err := p.SetUpstream(UpstreamConfig{Enabled: true, URL: upstream.server.URL}); err != nil {
		t.Fatal(err)
	}
	_, subnet, _ := net.ParseCIDR("127.0.0.0/8")
	if err := p.startLAN("127.0.0.1", 0, subnet, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	_, lanAddress := p.LANStatus()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CA().CertPEM())
	proxyURL, _ := url.Parse("http://" + lanAddress)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(origin.URL + "/lan-fixture")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "phone-fixture" || response.StatusCode != 200 || upstream.connects.Load() != 1 {
		t.Fatalf("LAN failed to use actual upstream: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
	waitBridgeHistory(t, p, 1)
	if tx := p.st.ListHTTPTx("")[0]; !tx.Decrypted || tx.Status != 200 {
		t.Fatalf("LAN did not feed current decrypted history: %#v", tx)
	}
	if err := p.StopLAN(); err != nil {
		t.Fatal(err)
	}
	if running, address := p.Status(); !running || address != usbAddress {
		t.Fatal("closing Wi-Fi broke the USB/desktop listener")
	}
	conn, err := net.DialTimeout("tcp", lanAddress, time.Second)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("LAN listener survived stop")
	}
}

func TestLANRejectsUnselectedSourceAndInvalidHost(t *testing.T) {
	p := newBridgeProxy(t)
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "::1", "example.com", "203.0.113.5"} {
		if err := p.StartLAN(host, 18080); err == nil {
			t.Fatalf("accepted invalid phone LAN host %q", host)
		}
	}
	_, otherNetwork, _ := net.ParseCIDR("192.0.2.0/24")
	if err := p.startLAN("127.0.0.1", 0, otherNetwork, []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	defer p.StopLAN()
	_, address := p.LANStatus()
	u, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(u)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://127.0.0.1:1/no-upstream")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || len(p.st.ListHTTPTx("")) != 0 {
		t.Fatal("unselected LAN client reached capture pipeline")
	}
}

func TestLANRequiresExplicitClientsAndRejectsOtherSubnetPeers(t *testing.T) {
	p := newBridgeProxy(t)
	_, subnet, _ := net.ParseCIDR("127.0.0.0/8")
	for _, clients := range [][]string{nil, {"not-an-ip"}, {"192.0.2.1"}} {
		if err := p.startLAN("127.0.0.1", 0, subnet, clients); err == nil {
			t.Fatal("accepted invalid client list", clients)
		}
	}
	if err := p.startLAN("127.0.0.1", 0, subnet, []string{"127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	defer p.StopLAN()
	_, address := p.LANStatus()
	u, _ := url.Parse("http://" + address)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: time.Second}).Get("http://127.0.0.1:1/must-be-blocked")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("non-listed peer in same subnet accepted", response.StatusCode)
	}
}
