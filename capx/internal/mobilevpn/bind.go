package mobilevpn

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// The stock WireGuard Bind opens wildcard sockets. This implementation binds
// exactly the address the user selected; default loopback never exposes LAN.
type explicitBind struct {
	mu     sync.Mutex
	ip     netip.Addr
	udp    *net.UDPConn
	onOpen func(netip.AddrPort)
}

func (b *explicitBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	network := "udp4"
	if b.ip.Is6() {
		network = "udp6"
	}
	u, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.ip, port)))
	if err != nil {
		return nil, 0, err
	}
	b.udp = u
	if b.onOpen != nil {
		b.onOpen(u.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, from, err := u.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		endpoints[0] = &vpnEndpoint{address: from}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(u.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *explicitBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp == nil {
		return nil
	}
	err := b.udp.Close()
	b.udp = nil
	return err
}
func (b *explicitBind) SetMark(uint32) error { return nil }
func (b *explicitBind) BatchSize() int       { return 1 }
func (b *explicitBind) ParseEndpoint(raw string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(raw)
	if err != nil {
		return nil, err
	}
	return &vpnEndpoint{address: address}, nil
}
func (b *explicitBind) Send(packets [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	u := b.udp
	b.mu.Unlock()
	if u == nil {
		return net.ErrClosed
	}
	endpoint, ok := ep.(*vpnEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, p := range packets {
		if _, err := u.WriteToUDPAddrPort(p, endpoint.address); err != nil {
			return err
		}
	}
	return nil
}

type vpnEndpoint struct{ address netip.AddrPort }

func (*vpnEndpoint) ClearSrc()             {}
func (*vpnEndpoint) SrcToString() string   { return "" }
func (e *vpnEndpoint) DstToString() string { return e.address.String() }
func (e *vpnEndpoint) DstToBytes() []byte  { b, _ := e.address.MarshalBinary(); return b }
func (e *vpnEndpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (*vpnEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
