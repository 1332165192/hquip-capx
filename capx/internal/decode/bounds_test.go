package decode

// Regression tests for the length/offset bounds checks in the decoders. Every
// case here is a hostile input whose attacker-controlled length field used to
// slip past a signed bounds check (or walk an offset past the buffer) and panic
// the caller — the sniffer runs these decoders on raw packets off the wire, so a
// panic there takes the capture daemon down.

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// A length-delimited field whose varint length is 2^64-1: int(ln) is -1, so a
// signed "i+int(ln) > len(b)" check passes and the slice panics.
func TestDecodeProtobufHugeLength(t *testing.T) {
	b := []byte{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	if _, err := DecodeProtobuf(b); err == nil {
		t.Fatal("expected error for a 2^64-1 length-delimited field")
	}
}

// The same overflow reached through a nested message.
func TestDecodeProtobufHugeLengthNested(t *testing.T) {
	inner := []byte{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	outer := append([]byte{0x0a, byte(len(inner))}, inner...)
	// The outer message parses; the inner one must be rejected, not panic.
	if _, err := DecodeProtobuf(outer); err != nil {
		t.Fatalf("outer message should decode: %v", err)
	}
}

// A gRPC frame declaring a 4 GiB payload (truncates to a negative int on 32-bit).
func TestDecodeGRPCHugeLength(t *testing.T) {
	frame := make([]byte, 8)
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], 0xffffffff)
	if _, err := DecodeGRPC(frame); err == nil {
		t.Fatal("expected error for an oversized gRPC frame length")
	}
}

// quicInitialHeader builds a minimal QUIC v1 Initial header: long-header first
// byte, version 1, empty DCID/SCID, then the caller's token-length and length
// varint bytes, padded out to 40 bytes.
func quicInitialHeader(tail ...byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0xc0 // long header, Initial
	binary.BigEndian.PutUint32(pkt[1:5], 1)
	pkt[5] = 0 // DCID length
	pkt[6] = 0 // SCID length
	copy(pkt[7:], tail)
	return pkt
}

// A token length of 255 in a 40-byte packet: the offset used to jump past the
// buffer and panic on the next varint read.
func TestDecryptQUICInitialOversizedToken(t *testing.T) {
	pkt := quicInitialHeader(0x40, 0xff) // 2-byte varint = 255
	if _, err := DecryptQUICInitial(pkt); err == nil {
		t.Fatal("expected error for a token length past the packet")
	}
}

// A Length field of 1: the ciphertext slice pkt[pnOffset+pnLen:end] then has
// high < low whenever the unmasked packet-number length exceeds it.
func TestDecryptQUICInitialTinyLength(t *testing.T) {
	pkt := quicInitialHeader(0x00, 0x01) // token length 0, length 1
	if _, err := DecryptQUICInitial(pkt); err == nil {
		t.Fatal("expected error for a length too small to hold a protected payload")
	}
}

// dcid_len comes from the API request, not the packet: a negative value used to
// index the header buffer out of range.
func TestDecryptQUICShortHeaderBadDCIDLen(t *testing.T) {
	secret := "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
	kl := ParseQUICKeylog([]string{"CLIENT_TRAFFIC_SECRET_0 " + dummyClientRandom + " " + secret})
	pkt, _ := hex.DecodeString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	for _, dcidLen := range []int{-5, -1, 21, 1 << 20} {
		if _, err := DecryptQUIC(pkt, kl, dcidLen, 0, nil); err == nil {
			t.Errorf("dcid_len=%d: expected an error", dcidLen)
		}
	}
}

// An ACK frame claiming 2^30-1 ranges with no range data behind it: the range
// loop must stop at the end of the buffer instead of spinning once the varint
// reads no longer advance.
func TestWalkQUICFramesHugeACKRangeCount(t *testing.T) {
	// type 0x02, largest=0, delay=0, range_count=2^30-1 (4-byte varint), first=0.
	b := []byte{0x02, 0x00, 0x00, 0xbf, 0xff, 0xff, 0xff, 0x00}
	frames, _, _ := walkQUICFrames(b)
	if len(frames) != 0 {
		t.Fatalf("expected the truncated ACK to stop the walk, got %v", frames)
	}
}
