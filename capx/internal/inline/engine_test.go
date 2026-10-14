package inline

import (
	"bytes"
	"testing"
)

func TestReplaceEqualLength(t *testing.T) {
	e := NewEngine()
	if _, err := e.Add(&PacketRule{Enabled: true, Proto: "any", Match: "de ad be ef", Replace: "ca fe ba be", Action: "replace"}); err != nil {
		t.Fatal(err)
	}
	pkt := []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0x11}
	out, drop, hit, _ := e.Apply(pkt, "tcp", 1234, 80)
	if drop || !hit {
		t.Fatalf("drop=%v hit=%v", drop, hit)
	}
	if !bytes.Equal(out, []byte{0x00, 0xca, 0xfe, 0xba, 0xbe, 0x11}) {
		t.Fatalf("out = % x", out)
	}
}

// buildUDPv4 builds a minimal IPv4+UDP packet with the given payload.
func buildUDPv4(payload []byte) []byte {
	pkt := make([]byte, 28+len(payload))
	pkt[0] = 0x45 // ver 4, ihl 5
	total := 28 + len(payload)
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[9] = 17 // UDP
	// src/dst ports
	pkt[20], pkt[21] = 0x30, 0x39 // 12345
	pkt[22], pkt[23] = 0x00, 0x35 // 53
	udpLen := 8 + len(payload)
	pkt[24] = byte(udpLen >> 8)
	pkt[25] = byte(udpLen)
	copy(pkt[28:], payload)
	return pkt
}

func TestParseIPv4UDP(t *testing.T) {
	pkt := buildUDPv4([]byte("hello"))
	info := parseIP(pkt)
	if !info.OK || info.Proto != "udp" || info.IPVer != 4 || info.L4Off != 20 {
		t.Fatalf("info = %+v", info)
	}
	if info.SrcPort != 12345 || info.DstPort != 53 {
		t.Fatalf("ports = %d/%d", info.SrcPort, info.DstPort)
	}
}

func TestParseIPv6WithExtensionHeaders(t *testing.T) {
	// IPv6 base (40) + Hop-by-Hop ext (8) + UDP (8) + payload.
	payload := []byte("xy")
	pkt := make([]byte, 40+8+8+len(payload))
	pkt[0] = 0x60            // version 6
	pkt[6] = ipProtoHopByHop // next header = hop-by-hop
	// hop-by-hop ext header at offset 40: next=UDP, hdrExtLen=0 => 8 bytes
	pkt[40] = ipProtoUDP
	pkt[41] = 0
	// UDP at offset 48
	off := 48
	pkt[off], pkt[off+1] = 0x12, 0x34   // src 4660
	pkt[off+2], pkt[off+3] = 0x00, 0x50 // dst 80
	copy(pkt[off+8:], payload)
	info := parseIP(pkt)
	if !info.OK || info.Proto != "udp" || info.IPVer != 6 || info.L4Off != 48 {
		t.Fatalf("info = %+v", info)
	}
	if info.DstPort != 80 {
		t.Fatalf("dst port = %d, want 80", info.DstPort)
	}
}

func TestVariableLengthUDPRewrite(t *testing.T) {
	e := NewEngine()
	// Replace "AAAA" payload with a longer "BBBBBB"; allow_resize fixes lengths.
	if _, err := e.Add(&PacketRule{Enabled: true, Proto: "udp", Match: "41 41 41 41",
		Replace: "42 42 42 42 42 42", Action: "replace", AllowResize: true}); err != nil {
		t.Fatal(err)
	}
	pkt := buildUDPv4([]byte("AAAA"))
	origLen := len(pkt)
	out, drop, hit, _ := e.Apply(pkt, "udp", 12345, 53)
	if drop || !hit {
		t.Fatalf("drop=%v hit=%v", drop, hit)
	}
	if len(out) != origLen+2 {
		t.Fatalf("out len = %d, want %d", len(out), origLen+2)
	}
	// IPv4 total length must reflect the +2 delta.
	total := int(out[2])<<8 | int(out[3])
	if total != origLen+2 {
		t.Fatalf("ip total = %d, want %d", total, origLen+2)
	}
	// UDP length field (offset 24) must reflect +2 too.
	udpLen := int(out[24])<<8 | int(out[25])
	if udpLen != 8+6 {
		t.Fatalf("udp len = %d, want %d", udpLen, 8+6)
	}
	if !bytes.Contains(out, []byte("BBBBBB")) {
		t.Fatalf("payload not replaced: % x", out)
	}
}

func TestVariableLengthRejectedWithoutFlag(t *testing.T) {
	e := NewEngine()
	_, err := e.Add(&PacketRule{Enabled: true, Proto: "udp", Match: "41 41", Replace: "42 42 42", Action: "replace"})
	if err == nil {
		t.Fatal("expected error for unequal length without allow_resize")
	}
}

func TestWildcardMatch(t *testing.T) {
	e := NewEngine()
	e.Add(&PacketRule{Enabled: true, Proto: "any", Match: "48 ?? C0", Replace: "90 90 90", Action: "replace"})
	pkt := []byte{0x48, 0x8b, 0xc0}
	out, _, hit, _ := e.Apply(pkt, "tcp", 0, 0)
	if !hit || !bytes.Equal(out, []byte{0x90, 0x90, 0x90}) {
		t.Fatalf("hit=%v out=% x", hit, out)
	}
}

func TestDropAction(t *testing.T) {
	e := NewEngine()
	e.Add(&PacketRule{Enabled: true, Proto: "udp", Match: "ff ff", Action: "drop"})
	_, drop, hit, _ := e.Apply([]byte{0x00, 0xff, 0xff}, "udp", 53, 1000)
	if !drop || !hit {
		t.Fatalf("drop=%v hit=%v", drop, hit)
	}
	// wrong proto -> no match
	_, drop2, _, _ := e.Apply([]byte{0x00, 0xff, 0xff}, "tcp", 53, 1000)
	if drop2 {
		t.Fatal("tcp packet should not match udp rule")
	}
}

func TestPortFilter(t *testing.T) {
	e := NewEngine()
	e.Add(&PacketRule{Enabled: true, Proto: "tcp", Port: 443, Match: "aa", Action: "drop"})
	if _, drop, _, _ := e.Apply([]byte{0xaa}, "tcp", 12345, 443); !drop {
		t.Fatal("should match dst port 443")
	}
	if _, drop, _, _ := e.Apply([]byte{0xaa}, "tcp", 12345, 80); drop {
		t.Fatal("should not match port 80")
	}
}

func TestReplaceLengthValidation(t *testing.T) {
	e := NewEngine()
	if _, err := e.Add(&PacketRule{Enabled: true, Match: "de ad", Replace: "ca", Action: "replace"}); err == nil {
		t.Fatal("expected length-mismatch error")
	}
	if _, err := e.Add(&PacketRule{Enabled: true, Match: "zz", Action: "drop"}); err == nil {
		t.Fatal("expected bad-pattern error")
	}
	if _, err := e.Add(&PacketRule{Enabled: true, Proto: "icmp", Match: "aa", Action: "drop"}); err == nil {
		t.Fatal("expected bad-proto error")
	}
}

func TestContiguousHex(t *testing.T) {
	pat, mask, err := parseAOB("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pat, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("pat = % x", pat)
	}
	for _, m := range mask {
		if m != 1 {
			t.Fatal("contiguous hex should have all-significant mask")
		}
	}
}

func TestDeleteAndList(t *testing.T) {
	e := NewEngine()
	r, _ := e.Add(&PacketRule{Enabled: true, Match: "aa", Action: "drop"})
	if len(e.List()) != 1 {
		t.Fatal("expected 1 rule")
	}
	if !e.Delete(r.ID) || e.Delete(r.ID) {
		t.Fatal("delete semantics wrong")
	}
}
