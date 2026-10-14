package inline

import "encoding/binary"

// L4Info describes the transport layer located inside a raw IP packet.
type L4Info struct {
	IPVer   int    // 4 or 6
	Proto   string // "tcp" | "udp" | "" (other/unknown)
	L4Off   int    // byte offset of the transport header within the packet
	SrcPort int
	DstPort int
	OK      bool
}

// IPv6 extension header next-header types that precede the real transport
// header and must be walked over to find TCP/UDP.
const (
	ipProtoHopByHop  = 0
	ipProtoTCP       = 6
	ipProtoUDP       = 17
	ipProtoRouting   = 43
	ipProtoFragment  = 44
	ipProtoAH        = 51
	ipProtoDstOpts   = 60
	ipProtoMobility  = 135
	ipProtoHIP       = 139
	ipProtoShim6     = 140
	ipProtoNoNextHdr = 59
)

// parseIP parses a raw IP packet (IPv4 or IPv6), walking IPv6 extension headers,
// and returns the transport protocol, its byte offset, and the ports. It is a
// best-effort parser: it returns OK=false when the packet is too short or the
// transport is not TCP/UDP.
func parseIP(pkt []byte) L4Info {
	if len(pkt) < 20 {
		return L4Info{}
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return L4Info{}
		}
		return finishL4(pkt, 4, pkt[9], ihl)
	case 6:
		if len(pkt) < 40 {
			return L4Info{}
		}
		next := pkt[6]
		off := 40
		// Walk extension headers up to a sane bound.
		for i := 0; i < 16; i++ {
			switch next {
			case ipProtoTCP, ipProtoUDP:
				return finishL4(pkt, 6, next, off)
			case ipProtoHopByHop, ipProtoRouting, ipProtoDstOpts, ipProtoMobility, ipProtoHIP, ipProtoShim6:
				if len(pkt) < off+2 {
					return L4Info{IPVer: 6}
				}
				hdrLen := (int(pkt[off+1]) + 1) * 8
				next = pkt[off]
				off += hdrLen
			case ipProtoAH:
				if len(pkt) < off+2 {
					return L4Info{IPVer: 6}
				}
				hdrLen := (int(pkt[off+1]) + 2) * 4
				next = pkt[off]
				off += hdrLen
			case ipProtoFragment:
				if len(pkt) < off+8 {
					return L4Info{IPVer: 6}
				}
				next = pkt[off]
				off += 8
			default:
				return L4Info{IPVer: 6} // unknown / no transport ports
			}
			if off >= len(pkt) {
				return L4Info{IPVer: 6}
			}
		}
		return L4Info{IPVer: 6}
	}
	return L4Info{}
}

func finishL4(pkt []byte, ipVer int, l4 byte, off int) L4Info {
	info := L4Info{IPVer: ipVer, L4Off: off}
	switch l4 {
	case ipProtoTCP:
		info.Proto = "tcp"
	case ipProtoUDP:
		info.Proto = "udp"
	default:
		return info // ports unknown for non TCP/UDP
	}
	if len(pkt) < off+4 {
		return info
	}
	info.SrcPort = int(binary.BigEndian.Uint16(pkt[off : off+2]))
	info.DstPort = int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
	info.OK = true
	return info
}

// fixLengthsAfterResize adjusts the IP (and UDP) length fields after a payload
// splice changed the total packet size by delta bytes. Checksums are left to
// the diversion backend (WinDivert's helper recomputes them). For TCP the
// caller is responsible for understanding that a length change desyncs the
// stream (seq/ack of later packets shift); UDP resizing is fully correct.
func fixLengthsAfterResize(pkt []byte, info L4Info, delta int) {
	if delta == 0 {
		return
	}
	switch info.IPVer {
	case 4:
		if len(pkt) >= 4 {
			total := int(binary.BigEndian.Uint16(pkt[2:4])) + delta
			if total < 0 {
				total = 0
			}
			binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
		}
	case 6:
		if len(pkt) >= 6 {
			pl := int(binary.BigEndian.Uint16(pkt[4:6])) + delta
			if pl < 0 {
				pl = 0
			}
			binary.BigEndian.PutUint16(pkt[4:6], uint16(pl))
		}
	}
	if info.Proto == "udp" && info.L4Off+6 <= len(pkt) {
		ul := int(binary.BigEndian.Uint16(pkt[info.L4Off+4:info.L4Off+6])) + delta
		if ul < 0 {
			ul = 0
		}
		binary.BigEndian.PutUint16(pkt[info.L4Off+4:info.L4Off+6], uint16(ul))
	}
}
