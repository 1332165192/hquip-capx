// Package decode provides schema-less decoders for binary application payloads
// capx captures but cannot otherwise render: protobuf wire format and gRPC
// length-prefixed framing. No .proto is required — fields are shown by number
// and wire type (protobuf-inspector style), recursively decoding length-
// delimited fields that themselves parse as messages.
package decode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"unicode/utf8"
)

// Field is one decoded protobuf field.
type Field struct {
	Num   int      `json:"field"`
	Wire  string   `json:"wire"`            // "varint" | "i64" | "i32" | "message" | "string" | "bytes"
	Val   any      `json:"value"`           // number, string, hex, or []Field for nested
	Int   *int64   `json:"int,omitempty"`   // signed interpretation for varints/fixed
	Float *float64 `json:"float,omitempty"` // float interpretation for i32/i64
}

// DecodeProtobuf parses raw protobuf wire bytes into fields. It errors if the
// bytes are not a clean, fully-consumed protobuf message.
func DecodeProtobuf(b []byte) ([]Field, error) {
	var out []Field
	i := 0
	for i < len(b) {
		tag, n := uvarint(b[i:])
		if n <= 0 {
			return nil, fmt.Errorf("bad tag at %d", i)
		}
		i += n
		fieldNum := int(tag >> 3)
		wt := int(tag & 7)
		if fieldNum == 0 {
			return nil, fmt.Errorf("zero field number")
		}
		switch wt {
		case 0: // varint
			v, m := uvarint(b[i:])
			if m <= 0 {
				return nil, fmt.Errorf("bad varint at %d", i)
			}
			i += m
			sv := int64(v)
			out = append(out, Field{Num: fieldNum, Wire: "varint", Val: v, Int: &sv})
		case 1: // 64-bit
			if i+8 > len(b) {
				return nil, fmt.Errorf("short i64 at %d", i)
			}
			u := binary.LittleEndian.Uint64(b[i:])
			i += 8
			f := math.Float64frombits(u)
			sv := int64(u)
			out = append(out, Field{Num: fieldNum, Wire: "i64", Val: u, Int: &sv, Float: &f})
		case 5: // 32-bit
			if i+4 > len(b) {
				return nil, fmt.Errorf("short i32 at %d", i)
			}
			u := binary.LittleEndian.Uint32(b[i:])
			i += 4
			f := float64(math.Float32frombits(u))
			sv := int64(int32(u))
			out = append(out, Field{Num: fieldNum, Wire: "i32", Val: u, Int: &sv, Float: &f})
		case 2: // length-delimited
			ln, m := uvarint(b[i:])
			if m <= 0 {
				return nil, fmt.Errorf("bad length at %d", i)
			}
			i += m
			// Compare unsigned against the bytes left: ln is a wire varint up to
			// 2^64-1, and int(ln) would go negative for anything >= 2^63, which
			// would slip past a signed bounds check and panic on the slice below.
			if ln > uint64(len(b)-i) {
				return nil, fmt.Errorf("length-delimited overruns at %d", i)
			}
			data := b[i : i+int(ln)]
			i += int(ln)
			out = append(out, decodeLengthDelim(fieldNum, data))
		default:
			return nil, fmt.Errorf("unsupported wire type %d (field %d)", wt, fieldNum)
		}
	}
	return out, nil
}

// decodeLengthDelim renders a length-delimited field. Printable UTF-8 is shown
// as a string (most string fields are short ASCII that would also "parse" as
// protobuf, so string wins to avoid false-positive nesting); otherwise binary
// that parses cleanly as protobuf is shown as a nested message; else as hex.
func decodeLengthDelim(field int, data []byte) Field {
	if len(data) > 0 && utf8.Valid(data) && printable(data) {
		return Field{Num: field, Wire: "string", Val: string(data)}
	}
	if len(data) > 0 {
		if nested, err := DecodeProtobuf(data); err == nil && len(nested) > 0 {
			return Field{Num: field, Wire: "message", Val: nested}
		}
	}
	if len(data) == 0 {
		return Field{Num: field, Wire: "string", Val: ""}
	}
	return Field{Num: field, Wire: "bytes", Val: hex.EncodeToString(data)}
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			bad++
		}
	}
	return bad*20 < len(b) // <5% control bytes
}

// uvarint reads a base-128 varint, returning the value and bytes consumed (0 on
// error / truncation).
func uvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if i > 9 || (i == 9 && c > 1) {
			return 0, -1 // overflow
		}
		x |= uint64(c&0x7f) << s
		if c < 0x80 {
			return x, i + 1
		}
		s += 7
	}
	return 0, 0 // truncated
}

// GRPCMessage is one gRPC length-prefixed message and its decoded fields.
type GRPCMessage struct {
	Compressed bool    `json:"compressed"`
	Length     int     `json:"length"`
	Fields     []Field `json:"fields,omitempty"`
	Raw        string  `json:"raw,omitempty"` // hex when fields couldn't be decoded
	Error      string  `json:"error,omitempty"`
}

// DecodeGRPC splits a gRPC body into its length-prefixed frames (1-byte
// compressed flag + 4-byte big-endian length + payload) and decodes each
// payload as protobuf. Compressed frames are reported but not inflated here.
func DecodeGRPC(b []byte) ([]GRPCMessage, error) {
	var out []GRPCMessage
	i := 0
	for i+5 <= len(b) {
		compressed := b[i] != 0
		// Unsigned compare: a 4-byte length up to 4 GiB truncates to a negative
		// int on 32-bit builds, which would pass a signed check and then panic.
		ln := uint64(binary.BigEndian.Uint32(b[i+1 : i+5]))
		i += 5
		if ln > uint64(len(b)-i) {
			return out, fmt.Errorf("gRPC frame overruns (have %d, need %d)", len(b)-i, ln)
		}
		payload := b[i : i+int(ln)]
		i += int(ln)
		msg := GRPCMessage{Compressed: compressed, Length: int(ln)}
		if compressed {
			msg.Raw = hex.EncodeToString(payload)
			msg.Error = "compressed frame (inflate with the negotiated codec to decode)"
		} else if fields, err := DecodeProtobuf(payload); err == nil {
			msg.Fields = fields
		} else {
			msg.Raw = hex.EncodeToString(payload)
			msg.Error = err.Error()
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no complete gRPC frames")
	}
	return out, nil
}
