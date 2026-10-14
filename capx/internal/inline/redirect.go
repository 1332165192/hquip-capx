package inline

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
)

// NATFlow is one redirected TCP or UDP conversation.
type NATFlow struct {
	OrigDst  net.IP
	OrigPort uint16
}

// Redirector rewrites local-app TCP/UDP 80/443 onto a transparent listener.
//
// WinDivert NETWORK packets from a process are outbound. To deliver them to a
// local listener we DNAT dest to the client's own address + listen port and
// re-inject as inbound. Replies from the listener (outbound, src=listen port)
// are SNAT'd back to the original server and re-injected as inbound so the
// client PCB still believes it talks to the real peer.
//
// IPv4 and IPv6 are both rewritten (addresses at IPv4 12:20 / IPv6 8:40).
type Redirector struct {
	mu    sync.Mutex
	flows map[string]*NATFlow

	listenPort uint16
	skipDst    uint16
	httpPorts  map[uint16]struct{}
	udpOnly    bool
}

func NewRedirector(listenPort, skipDstPort int, ports ...int) *Redirector {
	hp := map[uint16]struct{}{80: {}, 443: {}}
	if len(ports) > 0 {
		hp = map[uint16]struct{}{}
		for _, p := range ports {
			if p > 0 && p <= 65535 {
				hp[uint16(p)] = struct{}{}
			}
		}
	}
	return &Redirector{
		flows:      make(map[string]*NATFlow),
		listenPort: uint16(listenPort),
		skipDst:    uint16(skipDstPort),
		httpPorts:  hp,
	}
}

func flowKey(ip net.IP, port uint16) string {
	if ip == nil {
		return strconv.Itoa(int(port))
	}
	if v4 := ip.To4(); v4 != nil {
		return "4:" + v4.String() + ":" + strconv.Itoa(int(port))
	}
	return "6:" + ip.String() + ":" + strconv.Itoa(int(port))
}

func packetAddrs(pkt []byte) (src, dst net.IP, ver int, ok bool) {
	if len(pkt) < 20 {
		return nil, nil, 0, false
	}
	switch pkt[0] >> 4 {
	case 4:
		src = append(net.IP(nil), pkt[12:16]...)
		dst = append(net.IP(nil), pkt[16:20]...)
		return src, dst, 4, true
	case 6:
		if len(pkt) < 40 {
			return nil, nil, 0, false
		}
		src = append(net.IP(nil), pkt[8:24]...)
		dst = append(net.IP(nil), pkt[24:40]...)
		return src, dst, 6, true
	}
	return nil, nil, 0, false
}

func setPacketSrc(pkt []byte, ver int, ip net.IP) {
	switch ver {
	case 4:
		if v4 := ip.To4(); v4 != nil && len(pkt) >= 16 {
			copy(pkt[12:16], v4)
		}
	case 6:
		if v6 := ip.To16(); v6 != nil && len(pkt) >= 24 {
			copy(pkt[8:24], v6)
		}
	}
}

func setPacketDst(pkt []byte, ver int, ip net.IP) {
	switch ver {
	case 4:
		if v4 := ip.To4(); v4 != nil && len(pkt) >= 20 {
			copy(pkt[16:20], v4)
		}
	case 6:
		if v6 := ip.To16(); v6 != nil && len(pkt) >= 40 {
			copy(pkt[24:40], v6)
		}
	}
}

func tcpFlags(pkt []byte, l4off int) byte {
	if l4off+13 >= len(pkt) {
		return 0
	}
	return pkt[l4off+13]
}

// Apply rewrites pkt. flip is set when the WinDivert outbound bit must be
// inverted (outbound→inbound) so the packet is delivered locally.
func (r *Redirector) Apply(pkt []byte, outbound bool) (modified, flip bool) {
	if r == nil || !outbound {
		return false, false
	}
	srcIP, dstIP, ver, ok := packetAddrs(pkt)
	if !ok {
		return false, false
	}
	info := parseIP(pkt)
	if !info.OK || (info.Proto != "tcp" && info.Proto != "udp") {
		return false, false
	}
	srcPort := uint16(info.SrcPort)
	dstPort := uint16(info.DstPort)
	if r.udpOnly && info.Proto != "udp" {
		return false, false
	}
	if srcPort == r.listenPort {
		return r.snatReply(pkt, ver, dstIP, dstPort, info.L4Off, info.Proto)
	}
	if info.Proto == "udp" {
		return r.dnatRequest(pkt, ver, srcIP, dstIP, srcPort, dstPort, info.L4Off, true)
	}
	return r.dnatRequest(pkt, ver, srcIP, dstIP, srcPort, dstPort, info.L4Off, false)
}

func (r *Redirector) dnatRequest(pkt []byte, ver int, srcIP, dstIP net.IP, srcPort, dstPort uint16, l4off int, udp bool) (bool, bool) {
	if _, ok := r.httpPorts[dstPort]; !ok {
		return false, false
	}
	if r.skipDst != 0 && dstPort == r.skipDst {
		return false, false
	}
	if dstIP.IsLoopback() {
		return false, false
	}
	if dstPort == r.listenPort {
		return false, false
	}
	key := flowKey(srcIP, srcPort)

	r.mu.Lock()
	flow, ok := r.flows[key]
	if !ok {
		if !udp {
			flags := tcpFlags(pkt, l4off)
			if flags&tcpFlagSYN == 0 || flags&tcpFlagACK != 0 {
				r.mu.Unlock()
				return false, false
			}
		}
		flow = &NATFlow{OrigDst: append(net.IP(nil), dstIP...), OrigPort: dstPort}
		r.flows[key] = flow
	}
	if !udp {
		flags := tcpFlags(pkt, l4off)
		if flags&tcpFlagFIN != 0 || flags&tcpFlagRST != 0 {
			delete(r.flows, key)
		}
	}
	r.mu.Unlock()

	setPacketDst(pkt, ver, srcIP) // dest = this host, same address the client used
	if l4off+4 <= len(pkt) {
		binary.BigEndian.PutUint16(pkt[l4off+2:l4off+4], r.listenPort)
	}
	return true, true
}

func (r *Redirector) snatReply(pkt []byte, ver int, dstIP net.IP, dstPort uint16, l4off int, proto string) (bool, bool) {
	key := flowKey(dstIP, dstPort)
	r.mu.Lock()
	flow, ok := r.flows[key]
	if ok && proto == "tcp" {
		flags := tcpFlags(pkt, l4off)
		if flags&tcpFlagFIN != 0 || flags&tcpFlagRST != 0 {
			delete(r.flows, key)
		}
	}
	r.mu.Unlock()
	if !ok {
		return false, false
	}
	setPacketSrc(pkt, ver, flow.OrigDst)
	if l4off+2 <= len(pkt) {
		binary.BigEndian.PutUint16(pkt[l4off:l4off+2], flow.OrigPort)
	}
	return true, true
}

func (r *Redirector) Flows() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

func (r *Redirector) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.flows = make(map[string]*NATFlow)
	r.mu.Unlock()
}

func (r *Redirector) Lookup(srcIP net.IP, srcPort int) (dst string, ok bool) {
	if r == nil || srcIP == nil {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	flow := r.flows[flowKey(srcIP, uint16(srcPort))]
	if flow == nil {
		return "", false
	}
	return net.JoinHostPort(flow.OrigDst.String(), strconv.Itoa(int(flow.OrigPort))), true
}

func ParseHostPort(addr string) (ip net.IP, port int, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	ip = net.ParseIP(host)
	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return ip, 0, err
	}
	return ip, p, nil
}
