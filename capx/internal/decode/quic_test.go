package decode

import (
	"encoding/binary"
	"testing"
)

func quicLong(version uint32, typ byte) []byte {
	b := make([]byte, 8)
	b[0] = 0xC0 | (typ << 4) // long header + fixed bit + packet type
	binary.BigEndian.PutUint32(b[1:5], version)
	return b
}

func TestDetectQUIC(t *testing.T) {
	if info, ok := DetectQUIC(quicLong(1, 0)); !ok || !info.LongHeader || info.Type != "Initial" {
		t.Fatalf("v1 initial = %+v ok=%v", info, ok)
	}
	if info, ok := DetectQUIC(quicLong(1, 2)); !ok || info.Type != "Handshake" {
		t.Fatalf("v1 handshake = %+v", info)
	}
	if info, ok := DetectQUIC(quicLong(0x6b3343cf, 0)); !ok || info.Version != 0x6b3343cf {
		t.Fatalf("v2 = %+v", info)
	}
	// Short header (top bit clear) must not be claimed.
	if _, ok := DetectQUIC([]byte{0x40, 1, 2, 3, 4, 5}); ok {
		t.Fatal("short header should not be detected")
	}
	// Unknown version must not be claimed.
	if _, ok := DetectQUIC([]byte{0xC0, 0xDE, 0xAD, 0xBE, 0xEF}); ok {
		t.Fatal("unknown version should not be detected")
	}
	// Too short.
	if _, ok := DetectQUIC([]byte{0xC0}); ok {
		t.Fatal("short buffer should not be detected")
	}
}
