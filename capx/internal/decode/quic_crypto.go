package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// QUIC v1 Initial-packet decryption. Initial packets are protected with keys
// derived from a fixed salt and the client's Destination Connection ID — no TLS
// secrets are needed — so capx can decrypt the handshake's first flight (the
// ClientHello / ServerHello, including SNI and ALPN) straight from the captured
// bytes. Handshake / 1-RTT packets need the TLS traffic secrets (from the key
// log) and a fuller TLS state machine, which is out of scope here.

// quicV1InitialSalt is the RFC 9001 §5.2 salt for QUIC v1.
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// QUICInitial is the decrypted contents of a QUIC v1 Initial packet.
type QUICInitial struct {
	Role         string   `json:"role"` // "client" | "server"
	Version      uint32   `json:"version"`
	PacketNumber uint64   `json:"packet_number"`
	Frames       []string `json:"frames"`
	SNI          string   `json:"sni,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	CryptoBytes  int      `json:"crypto_bytes"`
}

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(secret []byte, label string, ctx []byte, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(ctx))
	info = append(info, byte(n>>8), byte(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(ctx)))
	info = append(info, ctx...)
	return hkdfExpand(secret, info, n)
}

// initialKeys are the AEAD key, IV and header-protection key for one role.
type initialKeys struct {
	key, iv, hp []byte
}

// deriveInitialKeys derives the Initial keys for the given DCID and role.
func deriveInitialKeys(dcid []byte, client bool) initialKeys {
	is := hkdfExtract(quicV1InitialSalt, dcid)
	label := "client in"
	if !client {
		label = "server in"
	}
	sec := hkdfExpandLabel(is, label, nil, 32)
	return initialKeys{
		key: hkdfExpandLabel(sec, "quic key", nil, 16),
		iv:  hkdfExpandLabel(sec, "quic iv", nil, 12),
		hp:  hkdfExpandLabel(sec, "quic hp", nil, 16),
	}
}

// qvarint reads a QUIC variable-length integer, returning value + bytes used.
func qvarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

// DecryptQUICInitial decrypts a QUIC v1 Initial packet, trying client then
// server keys, and returns the decoded frames + extracted ClientHello SNI/ALPN.
func DecryptQUICInitial(pkt []byte) (*QUICInitial, error) {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil, errors.New("not a long-header packet")
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	if version != 0x00000001 {
		return nil, fmt.Errorf("unsupported QUIC version 0x%08x (only v1 Initial)", version)
	}
	pos := 5
	if pos >= len(pkt) {
		return nil, errors.New("truncated")
	}
	dcil := int(pkt[pos])
	pos++
	if pos+dcil > len(pkt) {
		return nil, errors.New("truncated DCID")
	}
	dcid := pkt[pos : pos+dcil]
	pos += dcil
	if pos >= len(pkt) {
		return nil, errors.New("truncated")
	}
	scil := int(pkt[pos])
	pos++
	pos += scil
	if pos > len(pkt) {
		return nil, errors.New("truncated SCID")
	}
	tokenLen, n := qvarint(pkt[pos:])
	if n == 0 {
		return nil, errors.New("bad token length")
	}
	pos += n
	// tokenLen and length below are attacker-controlled varints (up to 2^62-1):
	// compare them unsigned against the bytes actually left, so a huge value can
	// neither walk pos past the packet nor turn negative in an int conversion.
	if tokenLen > uint64(len(pkt)-pos) {
		return nil, errors.New("token overruns packet")
	}
	pos += int(tokenLen)
	length, n := qvarint(pkt[pos:])
	if n == 0 {
		return nil, errors.New("bad length")
	}
	pos += n
	pnOffset := pos
	if length > uint64(len(pkt)-pnOffset) || pnOffset+4+16 > len(pkt) {
		return nil, errors.New("length field overruns packet")
	}
	// The header-protection sample is 4 bytes of packet number + 16 bytes of
	// ciphertext (RFC 9001 §5.4.2), so a protected payload cannot be shorter
	// than that; enforcing it keeps pnOffset+pnLen <= end below.
	if length < 4+16 {
		return nil, errors.New("length too small for a protected payload")
	}
	end := pnOffset + int(length)

	for _, client := range []bool{true, false} {
		k := deriveInitialKeys(dcid, client)
		sample := pkt[pnOffset+4 : pnOffset+4+16]
		mask := aesECBBlock(k.hp, sample)

		hdr := make([]byte, end)
		copy(hdr, pkt[:end])
		hdr[0] ^= mask[0] & 0x0f
		pnLen := int(hdr[0]&0x03) + 1
		var pn uint64
		for i := 0; i < pnLen; i++ {
			hdr[pnOffset+i] ^= mask[1+i]
			pn = pn<<8 | uint64(hdr[pnOffset+i])
		}
		nonce := make([]byte, 12)
		copy(nonce, k.iv)
		for i := 0; i < 8; i++ {
			nonce[11-i] ^= byte(pn >> (8 * i))
		}
		aad := hdr[:pnOffset+pnLen]
		ct := pkt[pnOffset+pnLen : end]

		block, err := aes.NewCipher(k.key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		pt, err := aead.Open(nil, nonce, ct, aad)
		if err != nil {
			continue // wrong role; try the other key set
		}
		role := "server"
		if client {
			role = "client"
		}
		out := &QUICInitial{Role: role, Version: version, PacketNumber: pn}
		crypto := parseQUICFrames(pt, out)
		out.CryptoBytes = len(crypto)
		out.SNI, out.ALPN = parseClientHello(crypto)
		return out, nil
	}
	return nil, errors.New("decryption failed (not a v1 Initial or unexpected keys)")
}

// aesECBBlock encrypts a single 16-byte block with AES (the header-protection
// mask generator for AES-based cipher suites).
func aesECBBlock(key, in []byte) []byte {
	b, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	out := make([]byte, 16)
	b.Encrypt(out, in)
	return out
}

// parseQUICFrames records a summary of the decrypted frames in out.Frames and
// returns the reassembled CRYPTO stream. The walk itself is walkQUICFrames
// (quic_protect.go) — one bounds-checked implementation covering every frame
// type, rather than a second partial parser for Initial packets.
func parseQUICFrames(b []byte, out *QUICInitial) []byte {
	frames, crypto, _ := walkQUICFrames(b)
	out.Frames = frames
	return crypto
}

// cryptoChunk is one CRYPTO frame's data at a stream offset.
type cryptoChunk struct {
	off  uint64
	data []byte
}

func joinChunks(chunks []cryptoChunk) []byte {
	// Order by offset and concatenate (contiguous for the first flight).
	for a := 1; a < len(chunks); a++ {
		for b := a; b > 0 && chunks[b].off < chunks[b-1].off; b-- {
			chunks[b], chunks[b-1] = chunks[b-1], chunks[b]
		}
	}
	var out []byte
	for _, c := range chunks {
		out = append(out, c.data...)
	}
	return out
}

// parseClientHello extracts the SNI host and ALPN protocols from a TLS
// ClientHello (or the SNI/ALPN-less fields of a ServerHello). Best-effort with
// bounds checks; returns ("", nil) when not found.
func parseClientHello(b []byte) (string, []string) {
	if len(b) < 4 || b[0] != 0x01 { // 0x01 = ClientHello
		return "", nil
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	body := b[4:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}
	p := 0
	if len(body) < 2+32 {
		return "", nil
	}
	p += 2 + 32 // legacy_version + random
	if p >= len(body) {
		return "", nil
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	if p+2 > len(body) {
		return "", nil
	}
	csLen := int(body[p])<<8 | int(body[p+1])
	p += 2 + csLen
	if p >= len(body) {
		return "", nil
	}
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		return "", nil
	}
	extTotal := int(body[p])<<8 | int(body[p+1])
	p += 2
	end := p + extTotal
	if end > len(body) {
		end = len(body)
	}
	var sni string
	var alpn []string
	for p+4 <= end {
		et := int(body[p])<<8 | int(body[p+1])
		el := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		if p+el > len(body) {
			break
		}
		ext := body[p : p+el]
		p += el
		switch et {
		case 0x0000: // server_name
			sni = parseSNIExt(ext)
		case 0x0010: // ALPN
			alpn = parseALPNExt(ext)
		}
	}
	return sni, alpn
}

func parseSNIExt(ext []byte) string {
	if len(ext) < 5 {
		return ""
	}
	// server_name_list: list_len(2), then entries name_type(1)+name_len(2)+name
	p := 2
	if p+3 > len(ext) {
		return ""
	}
	nameLen := int(ext[p+1])<<8 | int(ext[p+2])
	p += 3
	if p+nameLen > len(ext) {
		return ""
	}
	return string(ext[p : p+nameLen])
}

func parseALPNExt(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	p := 2 // ALPN protocol list length
	var out []string
	for p < len(ext) {
		l := int(ext[p])
		p++
		if p+l > len(ext) {
			break
		}
		out = append(out, string(ext[p:p+l]))
		p += l
	}
	return out
}
