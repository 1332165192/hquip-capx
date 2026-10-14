package decode

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Layer is one decoded protocol layer in a packet, with ordered field pairs.
type Layer struct {
	Name   string      `json:"name"`
	Fields [][2]string `json:"fields"` // ordered [name, value] pairs
}

// DecodePacket parses an Ethernet frame (or raw IP packet) into a Wireshark-
// style layer tree: Ethernet -> IPv4/IPv6 -> TCP/UDP. It is best-effort and
// stops at the first layer it cannot parse, returning whatever it decoded.
func DecodePacket(b []byte) []Layer {
	var layers []Layer
	rest := b
	ethType, l3 := decodeEthernet(rest, &layers)
	if l3 == nil {
		// Maybe it's a raw IP packet (LINKTYPE_RAW) with no Ethernet header.
		if len(b) > 0 && (b[0]>>4 == 4 || b[0]>>4 == 6) {
			ethType, l3 = ipVersionEtherType(b), b
		} else {
			return layers
		}
	}
	var proto byte
	var l4 []byte
	switch ethType {
	case 0x0800:
		proto, l4 = decodeIPv4(l3, &layers)
	case 0x86DD:
		proto, l4 = decodeIPv6(l3, &layers)
	default:
		return layers
	}
	switch proto {
	case 6:
		decodeTCP(l4, &layers)
	case 17:
		decodeUDP(l4, &layers)
	}
	return layers
}

func ipVersionEtherType(b []byte) uint16 {
	if b[0]>>4 == 6 {
		return 0x86DD
	}
	return 0x0800
}

// decodeEthernet returns the ethertype and the L3 payload, or (0,nil) when the
// frame is too short / not Ethernet.
func decodeEthernet(b []byte, layers *[]Layer) (uint16, []byte) {
	if len(b) < 14 {
		return 0, nil
	}
	dst := net.HardwareAddr(b[0:6]).String()
	src := net.HardwareAddr(b[6:12]).String()
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	// Skip a single 802.1Q VLAN tag if present.
	if et == 0x8100 && len(b) >= 18 {
		et = binary.BigEndian.Uint16(b[16:18])
		off = 18
	}
	*layers = append(*layers, Layer{Name: "Ethernet", Fields: [][2]string{
		{"dst", dst}, {"src", src}, {"ethertype", fmt.Sprintf("0x%04x", et)},
	}})
	return et, b[off:]
}

func decodeIPv4(b []byte, layers *[]Layer) (byte, []byte) {
	if len(b) < 20 {
		return 0, nil
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return 0, nil
	}
	proto := b[9]
	*layers = append(*layers, Layer{Name: "IPv4", Fields: [][2]string{
		{"version", "4"},
		{"ihl", fmt.Sprintf("%d", ihl)},
		{"total_length", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[2:4]))},
		{"ttl", fmt.Sprintf("%d", b[8])},
		{"protocol", protoName(proto)},
		{"src", net.IP(b[12:16]).String()},
		{"dst", net.IP(b[16:20]).String()},
	}})
	return proto, b[ihl:]
}

func decodeIPv6(b []byte, layers *[]Layer) (byte, []byte) {
	if len(b) < 40 {
		return 0, nil
	}
	next := b[6]
	*layers = append(*layers, Layer{Name: "IPv6", Fields: [][2]string{
		{"version", "6"},
		{"payload_length", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[4:6]))},
		{"next_header", protoName(next)},
		{"hop_limit", fmt.Sprintf("%d", b[7])},
		{"src", net.IP(b[8:24]).String()},
		{"dst", net.IP(b[24:40]).String()},
	}})
	return next, b[40:]
}

func decodeTCP(b []byte, layers *[]Layer) {
	if len(b) < 20 {
		return
	}
	dataOff := int(b[12]>>4) * 4
	flags := b[13]
	*layers = append(*layers, Layer{Name: "TCP", Fields: [][2]string{
		{"src_port", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[0:2]))},
		{"dst_port", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[2:4]))},
		{"seq", fmt.Sprintf("%d", binary.BigEndian.Uint32(b[4:8]))},
		{"ack", fmt.Sprintf("%d", binary.BigEndian.Uint32(b[8:12]))},
		{"data_offset", fmt.Sprintf("%d", dataOff)},
		{"flags", tcpFlags(flags)},
		{"window", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[14:16]))},
	}})
}

func decodeUDP(b []byte, layers *[]Layer) {
	if len(b) < 8 {
		return
	}
	*layers = append(*layers, Layer{Name: "UDP", Fields: [][2]string{
		{"src_port", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[0:2]))},
		{"dst_port", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[2:4]))},
		{"length", fmt.Sprintf("%d", binary.BigEndian.Uint16(b[4:6]))},
	}})
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "ICMP (1)"
	case 6:
		return "TCP (6)"
	case 17:
		return "UDP (17)"
	case 58:
		return "ICMPv6 (58)"
	}
	return fmt.Sprintf("%d", p)
}

func tcpFlags(f byte) string {
	names := []struct {
		bit  byte
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"},
		{0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"},
	}
	var on []string
	for _, n := range names {
		if f&n.bit != 0 {
			on = append(on, n.name)
		}
	}
	if len(on) == 0 {
		return "-"
	}
	s := on[0]
	for _, x := range on[1:] {
		s += "," + x
	}
	return s
}
