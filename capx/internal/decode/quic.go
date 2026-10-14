package decode

import "encoding/binary"

// QUICInfo describes a recognised QUIC packet.
type QUICInfo struct {
	LongHeader bool   `json:"long_header"`
	Version    uint32 `json:"version"`
	Type       string `json:"type,omitempty"` // Initial/0-RTT/Handshake/Retry for v1 long headers
}

// DetectQUIC classifies a UDP payload as QUIC. It reliably recognises QUIC v1/v2
// long-header packets (the handshake, where Header Form + Fixed bits are set and
// a known version follows). Short-header (1-RTT) packets are intentionally not
// claimed — they are indistinguishable from arbitrary UDP without connection
// state. ok is false when the payload is not recognisably QUIC.
func DetectQUIC(b []byte) (QUICInfo, bool) {
	if len(b) < 5 {
		return QUICInfo{}, false
	}
	// Long header: most-significant bit (Header Form) = 1; QUIC also sets the
	// Fixed bit (0x40) in v1. Together the top two bits are 0b11.
	if b[0]&0x80 == 0 {
		return QUICInfo{}, false // short header / not long-header QUIC
	}
	version := binary.BigEndian.Uint32(b[1:5])
	known := version == 0x00000001 || // QUIC v1 (RFC 9000)
		version == 0x6b3343cf || // QUIC v2 (RFC 9369)
		(version&0x0f0f0f0f) == 0x0a0a0a0a // forced version-negotiation ("greasing")
	if !known {
		return QUICInfo{}, false
	}
	info := QUICInfo{LongHeader: true, Version: version}
	if version == 0x00000001 {
		switch (b[0] >> 4) & 0x03 {
		case 0:
			info.Type = "Initial"
		case 1:
			info.Type = "0-RTT"
		case 2:
			info.Type = "Handshake"
		case 3:
			info.Type = "Retry"
		}
	}
	return info, true
}
