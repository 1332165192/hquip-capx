package proxy

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LANAddress identifies a computer interface usable by a phone on the same LAN.
type LANAddress struct {
	Host      string `json:"host"`
	Interface string `json:"interface"`
	Subnet    string `json:"subnet"`
}

func LANAddresses() ([]LANAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []LANAddress{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, subnet, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !ip.IsPrivate() || ip.IsLoopback() {
				continue
			}
			result = append(result, LANAddress{Host: ip.String(), Interface: iface.Name, Subnet: subnet.String()})
		}
	}
	priority := func(name string) int {
		name = strings.ToLower(name)
		if strings.Contains(name, "wlan") || strings.Contains(name, "wi-fi") || strings.Contains(name, "wireless") || strings.HasPrefix(name, "wl") {
			return 0
		}
		if strings.Contains(name, "vethernet") || strings.Contains(name, "virtual") || strings.Contains(name, "vmnet") || strings.Contains(name, "vbox") || strings.Contains(name, "docker") {
			return 2
		}
		return 1
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := priority(result[i].Interface), priority(result[j].Interface)
		if left != right {
			return left < right
		}
		return result[i].Host < result[j].Host
	})
	return result, nil
}

type lanProxy struct {
	server  *http.Server
	addr    string
	mu      sync.Mutex
	conns   map[*lanConn]struct{}
	closed  bool
	clients []string
}

type lanListener struct {
	net.Listener
	owner *lanProxy
}

func (l *lanListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &lanConn{Conn: conn, owner: l.owner}
	l.owner.mu.Lock()
	if l.owner.closed {
		l.owner.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	l.owner.conns[wrapped] = struct{}{}
	l.owner.mu.Unlock()
	return wrapped, nil
}

type lanConn struct {
	net.Conn
	owner *lanProxy
}

func (c *lanConn) Close() error {
	c.owner.mu.Lock()
	delete(c.owner.conns, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}

func (p *Proxy) LANStatus() (bool, string) {
	p.lanMu.Lock()
	defer p.lanMu.Unlock()
	if p.lan == nil {
		return false, ""
	}
	return true, p.lan.addr
}

// StartLAN exposes the same MITM pipeline on one explicit private interface.
// It leaves the API and the existing USB/desktop listener on their own addresses.
func (p *Proxy) StartLAN(host string, port int) error {
	return p.StartLANWithClients(host, port, nil)
}

func (p *Proxy) LANClients() []string {
	p.lanMu.Lock()
	defer p.lanMu.Unlock()
	if p.lan == nil {
		return []string{}
	}
	return append([]string(nil), p.lan.clients...)
}

func (p *Proxy) StartLANWithClients(host string, port int, clients []string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid LAN proxy port")
	}
	host = strings.TrimSpace(host)
	addresses, err := LANAddresses()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if address.Host == host {
			_, subnet, _ := net.ParseCIDR(address.Subnet)
			return p.startLAN(host, port, subnet, clients)
		}
	}
	return fmt.Errorf("请选择电脑当前网卡的局域网 IPv4 地址，不能填写 127.0.0.1、0.0.0.0 或公网 IP")
}

func (p *Proxy) startLAN(host string, port int, subnet *net.IPNet, clients []string) error {
	if len(clients) == 0 || len(clients) > 16 {
		return fmt.Errorf("请明确填写允许连接的手机 IP（最多16个），不能放行整个子网")
	}
	allowed := map[string]bool{}
	for _, client := range clients {
		ip := net.ParseIP(strings.TrimSpace(client))
		if ip == nil || ip.To4() == nil || !subnet.Contains(ip) {
			return fmt.Errorf("允许的手机 IP 必须属于所选电脑网卡的子网")
		}
		allowed[ip.String()] = true
	}
	p.lanMu.Lock()
	defer p.lanMu.Unlock()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if p.lan != nil {
		matching := len(p.lan.clients) == len(allowed)
		for _, client := range p.lan.clients {
			matching = matching && allowed[client]
		}
		if p.lan.addr == addr && matching {
			return nil
		}
		return fmt.Errorf("Wi-Fi proxy is already running on %s; stop before changing its address", p.lan.addr)
	}
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	entry := &lanProxy{addr: listener.Addr().String(), conns: map[*lanConn]struct{}{}}
	for client := range allowed {
		entry.clients = append(entry.clients, client)
	}
	sort.Strings(entry.clients)
	entry.server = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !subnet.Contains(net.ParseIP(remote)) || !allowed[remote] {
			http.Error(w, "client IP is not authorized for this phone proxy", http.StatusForbidden)
			return
		}
		p.serve(w, r)
	})}
	p.lan = entry
	go func() {
		_ = entry.server.Serve(&lanListener{Listener: listener, owner: entry})
		p.lanMu.Lock()
		if p.lan == entry {
			p.lan = nil
		}
		p.lanMu.Unlock()
	}()
	return nil
}

func (p *Proxy) StopLAN() error {
	p.lanMu.Lock()
	entry := p.lan
	p.lan = nil
	p.lanMu.Unlock()
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	entry.closed = true
	connections := make([]*lanConn, 0, len(entry.conns))
	for conn := range entry.conns {
		connections = append(connections, conn)
	}
	entry.mu.Unlock()
	err := entry.server.Close()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return err
}
