package inline

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTCPv4 builds a minimal IPv4+TCP packet.
func buildTCPv4(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x45
	total := 40 + len(payload)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50 // data offset = 5 (20 bytes)
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 0xffff)
	copy(pkt[40:], payload)
	return pkt
}

func tcpSeq(pkt []byte) uint32 { return binary.BigEndian.Uint32(pkt[24:28]) }
func tcpAck(pkt []byte) uint32 { return binary.BigEndian.Uint32(pkt[28:32]) }

// tcpChecksumValid sums the pseudo-header + TCP segment; a valid checksum makes
// the one's-complement sum equal 0xffff.
func tcpChecksumValid(pkt []byte) bool {
	off := 20
	tcpLen := len(pkt) - off
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	sum += uint32(6) + uint32(tcpLen)
	for i := off; i+1 < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return sum == 0xffff
}

// TestTCPVariableLengthResync drives a full bidirectional exchange through a
// rule that lengthens the client's payload, and verifies that later SEQ numbers
// (forward) and ACK numbers (reverse) are rewritten to keep both endpoints in
// sync — the case the old engine could not handle.
func TestTCPVariableLengthResync(t *testing.T) {
	e := NewEngine()
	if _, err := e.Add(&PacketRule{Enabled: true, Proto: "tcp", Match: "41 41 41 41",
		Replace: "42 42 42 42 42 42", Action: "replace", AllowResize: true}); err != nil {
		t.Fatal(err)
	}

	cli := [4]byte{10, 0, 0, 1}
	srv := [4]byte{10, 0, 0, 2}
	const cport, sport = 1000, 80

	apply := func(pkt []byte, sp, dp int) ([]byte, bool) {
		out, drop, _, modified := e.Apply(pkt, "tcp", sp, dp)
		if drop {
			t.Fatalf("unexpected drop")
		}
		return out, modified
	}

	// 1) Handshake establishes the ISNs.
	apply(buildTCPv4(cli, srv, cport, sport, 1000, 0, tcpFlagSYN, nil), cport, sport)
	apply(buildTCPv4(srv, cli, sport, cport, 5000, 1001, tcpFlagSYN|tcpFlagACK, nil), sport, cport)
	apply(buildTCPv4(cli, srv, cport, sport, 1001, 5001, tcpFlagACK, nil), cport, sport)

	// 2) Client sends 8 bytes containing AAAA; the rule grows it to 10 bytes.
	d1, mod := apply(buildTCPv4(cli, srv, cport, sport, 1001, 5001, tcpFlagACK, []byte("xxAAAAyy")), cport, sport)
	if !mod {
		t.Fatal("data segment should be modified")
	}
	if len(d1) != 40+10 {
		t.Fatalf("payload not resized: len=%d", len(d1))
	}
	if tcpSeq(d1) != 1001 {
		t.Errorf("first data seq = %d, want 1001 (unchanged)", tcpSeq(d1))
	}
	if !bytes.Contains(d1, []byte("xxBBBBBByy")) {
		t.Errorf("payload = %q", d1[40:])
	}
	if !tcpChecksumValid(d1) {
		t.Error("TCP checksum invalid after resize")
	}

	// 3) Server ACKs the modified data (modified space: 1001+10 = 1011). capx must
	//    map the ACK back to the client's original space: 1001+8 = 1009.
	a1, mod := apply(buildTCPv4(srv, cli, sport, cport, 5001, 1011, tcpFlagACK, nil), sport, cport)
	if !mod {
		t.Fatal("reverse ACK should be rewritten")
	}
	if tcpAck(a1) != 1009 {
		t.Errorf("server ACK mapped to %d, want 1009", tcpAck(a1))
	}
	if !tcpChecksumValid(a1) {
		t.Error("TCP checksum invalid after ACK rewrite")
	}

	// 4) Client's next segment (original seq 1009) must be bumped by +2 to 1011.
	d2, mod := apply(buildTCPv4(cli, srv, cport, sport, 1009, 5001, tcpFlagACK, []byte("more")), cport, sport)
	if !mod {
		t.Fatal("steady-state forward segment should have its seq fixed")
	}
	if tcpSeq(d2) != 1011 {
		t.Errorf("second data seq = %d, want 1011", tcpSeq(d2))
	}
	if !tcpChecksumValid(d2) {
		t.Error("TCP checksum invalid on steady-state segment")
	}

	// 5) Server ACKs everything (modified 1011+4 = 1015) -> original 1001+12 = 1013.
	a2, _ := apply(buildTCPv4(srv, cli, sport, cport, 5001, 1015, tcpFlagACK, nil), sport, cport)
	if tcpAck(a2) != 1013 {
		t.Errorf("final server ACK mapped to %d, want 1013", tcpAck(a2))
	}
}

// TestTCPFixupIdempotentRetransmit checks that re-processing the same forward
// segment (a retransmission) maps it identically rather than double-counting.
func TestTCPFixupIdempotentRetransmit(t *testing.T) {
	e := NewEngine()
	e.Add(&PacketRule{Enabled: true, Proto: "tcp", Match: "41 41 41 41",
		Replace: "42 42 42 42 42 42", Action: "replace", AllowResize: true})
	cli := [4]byte{10, 0, 0, 1}
	srv := [4]byte{10, 0, 0, 2}

	e.Apply(buildTCPv4(cli, srv, 1000, 80, 1000, 0, tcpFlagSYN, nil), "tcp", 1000, 80)

	mk := func() []byte {
		return buildTCPv4(cli, srv, 1000, 80, 1001, 5001, tcpFlagACK, []byte("xxAAAAyy"))
	}
	out1, _, _, _ := e.Apply(mk(), "tcp", 1000, 80)
	out2, _, _, _ := e.Apply(mk(), "tcp", 1000, 80)
	if tcpSeq(out1) != tcpSeq(out2) {
		t.Errorf("retransmit seq differs: %d vs %d", tcpSeq(out1), tcpSeq(out2))
	}

	// A following segment must still be bumped by exactly +2 (not +4).
	out3, _, _, _ := e.Apply(buildTCPv4(cli, srv, 1000, 80, 1009, 5001, tcpFlagACK, []byte("z")), "tcp", 1000, 80)
	if tcpSeq(out3) != 1011 {
		t.Errorf("post-retransmit seq = %d, want 1011", tcpSeq(out3))
	}
}
