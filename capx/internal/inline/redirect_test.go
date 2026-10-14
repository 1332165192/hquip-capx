package inline

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildRedirectTCPv4(srcIP, dstIP string, sport, dport int, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], net.ParseIP(srcIP).To4())
	copy(pkt[16:20], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(pkt[20:22], uint16(sport))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dport))
	pkt[32] = 0x50
	pkt[33] = flags
	return pkt
}

func TestRedirectorDnatAndSnat(t *testing.T) {
	r := NewRedirector(18081, 18080)
	out := buildRedirectTCPv4("192.168.1.10", "93.184.216.34", 54321, 443, tcpFlagSYN)
	mod, flip := r.Apply(out, true)
	if !mod || !flip {
		t.Fatalf("dnat mod=%v flip=%v", mod, flip)
	}
	if net.IP(out[16:20]).String() != "192.168.1.10" {
		t.Fatalf("dst ip = %v", net.IP(out[16:20]))
	}
	if binary.BigEndian.Uint16(out[22:24]) != 18081 {
		t.Fatalf("dst port = %d", binary.BigEndian.Uint16(out[22:24]))
	}

	reply := buildRedirectTCPv4("192.168.1.10", "192.168.1.10", 18081, 54321, tcpFlagSYN|tcpFlagACK)
	mod, flip = r.Apply(reply, true)
	if !mod || !flip {
		t.Fatalf("snat mod=%v flip=%v", mod, flip)
	}
	if net.IP(reply[12:16]).String() != "93.184.216.34" {
		t.Fatalf("src ip = %v", net.IP(reply[12:16]))
	}
	if binary.BigEndian.Uint16(reply[20:22]) != 443 {
		t.Fatalf("src port = %d", binary.BigEndian.Uint16(reply[20:22]))
	}
}

func TestRedirectorSkipsLoopbackAndNonHTTP(t *testing.T) {
	r := NewRedirector(18081, 18080)
	loop := buildRedirectTCPv4("192.168.1.10", "127.0.0.1", 1234, 443, tcpFlagSYN)
	if mod, _ := r.Apply(loop, true); mod {
		t.Fatal("must not rewrite loopback dest")
	}
	ssh := buildRedirectTCPv4("192.168.1.10", "1.1.1.1", 1234, 22, tcpFlagSYN)
	if mod, _ := r.Apply(ssh, true); mod {
		t.Fatal("must not rewrite non-80/443")
	}
	inbound := buildRedirectTCPv4("1.1.1.1", "192.168.1.10", 443, 1234, tcpFlagSYN|tcpFlagACK)
	if mod, _ := r.Apply(inbound, false); mod {
		t.Fatal("inbound packets are not rewritten by this path")
	}
}

func TestRedirectorExtraPort(t *testing.T) {
	r := NewRedirector(18081, 0, 8080)
	pkt := buildRedirectTCPv4("192.168.1.10", "1.1.1.1", 9, 8080, tcpFlagSYN)
	if mod, _ := r.Apply(pkt, true); !mod {
		t.Fatal("8080 should be redirected when listed")
	}
	if _, ok := r.Lookup(net.ParseIP("192.168.1.10"), 9); !ok {
		t.Fatal("orig dest lookup missed")
	}
}

func TestRedirectorIgnoresNonSYNWithoutFlow(t *testing.T) {
	r := NewRedirector(18081, 0)
	ack := buildRedirectTCPv4("192.168.1.10", "1.1.1.1", 9, 443, tcpFlagACK)
	if mod, _ := r.Apply(ack, true); mod {
		t.Fatal("data without a tracked flow must pass")
	}
}

func TestParseHostPort(t *testing.T) {
	ip, port, err := ParseHostPort("127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "127.0.0.1" || port != 18081 {
		t.Fatalf("%s %d", ip, port)
	}
}

func buildRedirectTCPv6(srcIP, dstIP string, sport, dport int, flags byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20)
	pkt[6] = 6
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP(srcIP).To16())
	copy(pkt[24:40], net.ParseIP(dstIP).To16())
	binary.BigEndian.PutUint16(pkt[40:42], uint16(sport))
	binary.BigEndian.PutUint16(pkt[42:44], uint16(dport))
	pkt[52] = 0x50
	pkt[53] = flags
	return pkt
}

func TestRedirectorDnatAndSnatIPv6(t *testing.T) {
	r := NewRedirector(18081, 18080)
	out := buildRedirectTCPv6("2001:db8::10", "2001:db8:1::1", 54321, 443, tcpFlagSYN)
	mod, flip := r.Apply(out, true)
	if !mod || !flip {
		t.Fatalf("dnat mod=%v flip=%v", mod, flip)
	}
	if net.IP(out[24:40]).String() != "2001:db8::10" {
		t.Fatalf("dst ip = %v", net.IP(out[24:40]))
	}
	if binary.BigEndian.Uint16(out[42:44]) != 18081 {
		t.Fatalf("dst port = %d", binary.BigEndian.Uint16(out[42:44]))
	}
	dst, ok := r.Lookup(net.ParseIP("2001:db8::10"), 54321)
	if !ok || dst != "[2001:db8:1::1]:443" {
		t.Fatalf("lookup = %q ok=%v", dst, ok)
	}

	reply := buildRedirectTCPv6("2001:db8::10", "2001:db8::10", 18081, 54321, tcpFlagSYN|tcpFlagACK)
	mod, flip = r.Apply(reply, true)
	if !mod || !flip {
		t.Fatalf("snat mod=%v flip=%v", mod, flip)
	}
	if net.IP(reply[8:24]).String() != "2001:db8:1::1" {
		t.Fatalf("src ip = %v", net.IP(reply[8:24]))
	}
	if binary.BigEndian.Uint16(reply[40:42]) != 443 {
		t.Fatalf("src port = %d", binary.BigEndian.Uint16(reply[40:42]))
	}
}

func TestRedirectorSkipsIPv6Loopback(t *testing.T) {
	r := NewRedirector(18081, 18080)
	loop := buildRedirectTCPv6("2001:db8::10", "::1", 1234, 443, tcpFlagSYN)
	if mod, _ := r.Apply(loop, true); mod {
		t.Fatal("must not rewrite IPv6 loopback dest")
	}
}

func buildRedirectUDPv4(srcIP, dstIP string, sport, dport int) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], net.ParseIP(srcIP).To4())
	copy(pkt[16:20], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(pkt[20:22], uint16(sport))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dport))
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	return pkt
}

func TestRedirectorUDPv4HTTP3(t *testing.T) {
	r := NewRedirector(18081, 0)
	pkt := buildRedirectUDPv4("192.168.1.10", "1.1.1.1", 55555, 443)
	mod, flip := r.Apply(pkt, true)
	if !mod || !flip {
		t.Fatalf("udp dnat mod=%v flip=%v", mod, flip)
	}
	if binary.BigEndian.Uint16(pkt[22:24]) != 18081 {
		t.Fatalf("dst port = %d", binary.BigEndian.Uint16(pkt[22:24]))
	}
	dst, ok := r.Lookup(net.ParseIP("192.168.1.10"), 55555)
	if !ok || dst != "1.1.1.1:443" {
		t.Fatalf("lookup = %q ok=%v", dst, ok)
	}
}
