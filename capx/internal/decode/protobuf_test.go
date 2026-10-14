package decode

import (
	"encoding/binary"
	"testing"
)

// buildMsg encodes a couple of fields by hand to a protobuf message:
//
//	field 1 varint = 150
//	field 2 string = "hi"
func sampleMsg() []byte {
	var b []byte
	// field 1, wire 0 (varint): tag = 1<<3|0 = 0x08, value 150 = 0x96 0x01
	b = append(b, 0x08, 0x96, 0x01)
	// field 2, wire 2 (len): tag = 2<<3|2 = 0x12, len 2, "hi"
	b = append(b, 0x12, 0x02, 'h', 'i')
	return b
}

func TestDecodeProtobufBasic(t *testing.T) {
	fields, err := DecodeProtobuf(sampleMsg())
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}
	if fields[0].Num != 1 || fields[0].Wire != "varint" || fields[0].Val.(uint64) != 150 {
		t.Fatalf("field1 = %+v", fields[0])
	}
	if fields[1].Num != 2 || fields[1].Wire != "string" || fields[1].Val.(string) != "hi" {
		t.Fatalf("field2 = %+v", fields[1])
	}
}

func TestDecodeProtobufNested(t *testing.T) {
	inner := sampleMsg()
	// Outer field 3, wire 2, containing the inner message.
	outer := append([]byte{0x1a, byte(len(inner))}, inner...)
	fields, err := DecodeProtobuf(outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].Wire != "message" {
		t.Fatalf("expected nested message, got %+v", fields)
	}
	nested := fields[0].Val.([]Field)
	if len(nested) != 2 {
		t.Fatalf("nested fields = %d, want 2", len(nested))
	}
}

func TestDecodeProtobufErrors(t *testing.T) {
	if _, err := DecodeProtobuf([]byte{0x08}); err == nil { // varint tag with no value
		t.Fatal("expected error for truncated varint")
	}
	if _, err := DecodeProtobuf([]byte{0x12, 0x05, 'a'}); err == nil { // len 5 but 1 byte
		t.Fatal("expected error for overrun length")
	}
}

func TestDecodeGRPC(t *testing.T) {
	payload := sampleMsg()
	frame := make([]byte, 5+len(payload))
	frame[0] = 0 // uncompressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	// Two frames back to back.
	body := append(append([]byte{}, frame...), frame...)

	msgs, err := DecodeGRPC(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Compressed || len(msgs[0].Fields) != 2 {
		t.Fatalf("msg0 = %+v", msgs[0])
	}
}

func TestDecodeGRPCCompressedFlag(t *testing.T) {
	payload := []byte{0xde, 0xad}
	frame := make([]byte, 5+len(payload))
	frame[0] = 1 // compressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	msgs, err := DecodeGRPC(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !msgs[0].Compressed || msgs[0].Raw == "" {
		t.Fatalf("expected compressed frame with raw hex, got %+v", msgs[0])
	}
}
