package mobilevpn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type stackTun struct {
	ctx    context.Context
	cancel context.CancelFunc
	stack  *stack.Stack
	link   *channel.Endpoint
	events chan tun.Event
	mtu    int
	once   sync.Once
	udpMu  sync.Mutex
}

func newStackTun(ctx context.Context, mtu int, session *vpnSession) (*stackTun, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &stackTun{ctx: ctx, cancel: cancel, mtu: mtu, events: make(chan tun.Event, 1), link: channel.New(1024, uint32(mtu), "")}
	s.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}), ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true})}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}, HandleLocal: false})
	if err := s.stack.CreateNIC(1, s.link); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	if err := s.stack.SetPromiscuousMode(1, true); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	if err := s.stack.SetSpoofing(1, true); err != nil {
		s.Close()
		return nil, errors.New(err.String())
	}
	s.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	tcpForwarder := tcp.NewForwarder(s.stack, 0, 128, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := endpointDestination(id)
		if !session.allowed(dst) || !session.begin() {
			r.Complete(true)
			return
		}
		go func() {
			defer session.end()
			var queue waiter.Queue
			ep, err := r.CreateEndpoint(&queue)
			r.Complete(err != nil)
			if err != nil {
				session.forwardErrors.Add(1)
				return
			}
			client := gonet.NewTCPConn(&queue, ep)
			if !session.track(client) {
				return
			}
			defer session.untrack(client)
			if session.capturePort(dst.Port()) {
				session.handleHTTP(session.ctx, client, dst.String())
				return
			}
			if session.outboundGuard != nil {
				if err := session.outboundGuard("tcp", dst.String()); err != nil {
					session.forwardErrors.Add(1)
					return
				}
			}
			up, errNative := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(session.ctx, "tcp", dst.String())
			if errNative != nil {
				session.forwardErrors.Add(1)
				return
			}
			if !session.track(up) {
				return
			}
			defer session.untrack(up)
			relayTCP(client, up)
		}()
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	// Create a normal connected UDP endpoint synchronously, then deliver the
	// first datagram. This avoids retaining an extra PacketBuffer per UDP flow.
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		s.udpMu.Lock()
		defer s.udpMu.Unlock()
		dst := endpointDestination(id)
		if !session.allowed(dst) || !session.begin() {
			return true
		}
		var queue waiter.Queue
		ep, err := s.stack.NewEndpoint(udp.ProtocolNumber, pkt.NetworkProtocolNumber, &queue)
		if err != nil {
			session.end()
			session.forwardErrors.Add(1)
			return true
		}
		ep.SocketOptions().SetReuseAddress(true)
		ep.SocketOptions().SetReusePort(true)
		err = ep.Bind(tcpip.FullAddress{NIC: 1, Addr: id.LocalAddress, Port: id.LocalPort})
		if err == nil {
			err = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: id.RemoteAddress, Port: id.RemotePort})
		}
		if err != nil {
			ep.Close()
			session.end()
			session.forwardErrors.Add(1)
			return true
		}
		ep.(interface {
			HandlePacket(stack.TransportEndpointID, *stack.PacketBuffer)
		}).HandlePacket(id, pkt)
		client := gonet.NewUDPConn(&queue, ep)
		if !session.track(client) {
			session.end()
			return true
		}
		go func() {
			defer session.end()
			defer session.untrack(client)
			if session.outboundGuard != nil {
				if err := session.outboundGuard("udp", dst.String()); err != nil {
					session.forwardErrors.Add(1)
					return
				}
			}
			up, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(session.ctx, "udp", dst.String())
			if err != nil {
				session.forwardErrors.Add(1)
				return
			}
			if !session.track(up) {
				return
			}
			defer session.untrack(up)
			relayUDP(client, up)
		}()
		return true
	})
	s.events <- tun.EventUp
	return s, nil
}

func endpointDestination(id stack.TransportEndpointID) netip.AddrPort {
	ip, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, id.LocalPort)
}
func (s *stackTun) Name() (string, error)    { return "capx-mobile-userspace", nil }
func (*stackTun) File() *os.File             { return nil }
func (s *stackTun) Events() <-chan tun.Event { return s.events }
func (s *stackTun) MTU() (int, error)        { return s.mtu, nil }
func (*stackTun) BatchSize() int             { return 1 }
func (s *stackTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := s.link.ReadContext(s.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) || len(bufs[0])-offset < view.Size() {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], view.AsSlice())
	return 1, nil
}
func (s *stackTun) Write(bufs [][]byte, offset int) (int, error) {
	if s.ctx.Err() != nil {
		return 0, os.ErrClosed
	}
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			return i, io.ErrShortBuffer
		}
		packet := b[offset:]
		var protocol tcpip.NetworkProtocolNumber
		switch packet[0] >> 4 {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			return i, errors.New("unsupported VPN IP version")
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		s.link.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}
func (s *stackTun) Close() error {
	s.once.Do(func() { s.cancel(); s.stack.Close(); s.stack.RemoveNIC(1); s.link.Close(); close(s.events) })
	return nil
}

func relayTCP(client, up net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(up, client)
		if half, ok := up.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			up.Close()
		}
		close(done)
	}()
	io.Copy(client, up)
	client.Close()
	up.Close()
	<-done
}
func relayUDP(client, up net.Conn) {
	done := make(chan struct{}, 2)
	copyPackets := func(dst, src net.Conn) {
		b := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := src.Read(b)
			if err != nil {
				break
			}
			dst.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err = dst.Write(b[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyPackets(up, client)
	go copyPackets(client, up)
	<-done
	client.Close()
	up.Close()
	<-done
}
