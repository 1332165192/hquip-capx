package export

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

func TestWritePCAP(t *testing.T) {
	packets := []model.Packet{
		{FlowID: "f1", TS: time.Unix(1000, 0), Length: 4, Raw: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{FlowID: "f2", TS: time.Unix(1001, 0), Length: 2, Raw: []byte{0xCA, 0xFE}},
		{FlowID: "f3", TS: time.Unix(1002, 0), Length: 100}, // no raw, should be skipped
	}
	var buf bytes.Buffer
	if err := WritePCAP(&buf, packets, LinkEthernet); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	// Check magic number.
	if binary.LittleEndian.Uint32(data[0:4]) != pcapMagic {
		t.Fatal("bad magic")
	}
	// Check link type was written.
	if binary.LittleEndian.Uint32(data[20:24]) != LinkEthernet {
		t.Fatalf("link type = %d, want %d", binary.LittleEndian.Uint32(data[20:24]), LinkEthernet)
	}
	// Should have global header (24) + 2 packet records.
	// Packet 1: 16 header + 4 data = 20
	// Packet 2: 16 header + 2 data = 18
	expected := 24 + 20 + 18
	if len(data) != expected {
		t.Fatalf("expected %d bytes, got %d", expected, len(data))
	}
}

func TestWritePCAPNG(t *testing.T) {
	packets := []model.Packet{
		{FlowID: "f1", TS: time.Unix(2000, 0), Length: 4, Raw: []byte{0x01, 0x02, 0x03, 0x04}},
	}
	var buf bytes.Buffer
	if err := WritePCAPNG(&buf, packets, LinkEthernet); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	// SHB magic check.
	if binary.LittleEndian.Uint32(data[0:4]) != pcapngSHBType {
		t.Fatal("bad SHB type")
	}
	// Should have SHB (28) + IDB (20) + EPB (header 28 + 4 data + 0 pad + 4 trailer = 36).
	expected := 28 + 20 + 36
	if len(data) != expected {
		t.Fatalf("expected %d bytes, got %d", expected, len(data))
	}
}
