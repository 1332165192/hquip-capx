package decode

// QUIC Handshake / 0-RTT / 1-RTT packet protection (RFC 9001 §5). Initial
// packets are handled by quic_crypto.go (keys derive from the DCID, no secrets
// needed). The packets after the first flight are protected with keys derived
// from the TLS 1.3 traffic secrets, which capx already collects in its key-log
// store (SSLKEYLOGFILE lines, or dumped by the Frida TLS hook). Given those
// secrets this file derives the QUIC packet-protection keys ("quic key"/"quic
// iv"/"quic hp"), removes header protection, reconstructs the packet number and
// AEAD-opens the payload — covering AES-128-GCM, AES-256-GCM and
// ChaCha20-Poly1305 with the matching header-protection function.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// --- generalized HKDF (parameterized over the TLS 1.3 cipher suite hash) ---

func hkdfExpandH(newHash func() hash.Hash, prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		hm := hmac.New(newHash, prk)
		hm.Write(t)
		hm.Write(info)
		hm.Write([]byte{i})
		t = hm.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func hkdfExpandLabelH(newHash func() hash.Hash, secret []byte, label string, ctx []byte, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(ctx))
	info = append(info, byte(n>>8), byte(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(ctx)))
	info = append(info, ctx...)
	return hkdfExpandH(newHash, secret, info, n)
}

// --- cipher suites ---

// quicSuite captures the parameters that differ between the AEADs QUIC uses.
type quicSuite struct {
	name    string
	newHash func() hash.Hash
	keyLen  int    // AEAD + header-protection key length
	hpKind  string // "aes" | "chacha"
}

func (s quicSuite) keys(secret []byte) (key, iv, hp []byte) {
	key = hkdfExpandLabelH(s.newHash, secret, "quic key", nil, s.keyLen)
	iv = hkdfExpandLabelH(s.newHash, secret, "quic iv", nil, 12)
	hp = hkdfExpandLabelH(s.newHash, secret, "quic hp", nil, s.keyLen)
	return
}

func (s quicSuite) aead(key []byte) (cipher.AEAD, error) {
	if s.hpKind == "chacha" {
		return chacha20poly1305.New(key)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// hpMask produces the 5-byte header-protection mask from a 16-byte sample
// (RFC 9001 §5.4.3 for AES, §5.4.4 for ChaCha20).
func (s quicSuite) hpMask(hpKey, sample []byte) []byte {
	if len(sample) < 16 {
		return make([]byte, 5)
	}
	if s.hpKind == "chacha" {
		ctr := binary.LittleEndian.Uint32(sample[0:4])
		c, err := chacha20.NewUnauthenticatedCipher(hpKey, sample[4:16])
		if err != nil {
			return make([]byte, 5)
		}
		c.SetCounter(ctr)
		out := make([]byte, 5)
		c.XORKeyStream(out, out)
		return out
	}
	blk, err := aes.NewCipher(hpKey)
	if err != nil {
		return make([]byte, 5)
	}
	out := make([]byte, 16)
	blk.Encrypt(out, sample[:16])
	return out[:5]
}

// candidateSuites returns the suites worth trying for a secret of the given
// length. A 48-byte secret means SHA-384 (AES-256-GCM); a 32-byte secret means
// SHA-256, which is shared by AES-128-GCM and ChaCha20-Poly1305 — the key log
// does not record which, so both are tried and the AEAD tag disambiguates.
func candidateSuites(secretLen int) []quicSuite {
	switch secretLen {
	case 48:
		return []quicSuite{{"AEAD_AES_256_GCM", sha512.New384, 32, "aes"}}
	case 32:
		return []quicSuite{
			{"AEAD_AES_128_GCM", sha256.New, 16, "aes"},
			{"AEAD_CHACHA20_POLY1305", sha256.New, 32, "chacha"},
		}
	}
	return nil
}

// --- packet-number reconstruction (RFC 9000 Appendix A.3) ---

func decodePacketNumber(largest, truncated uint64, pnLen int) uint64 {
	pnBits := uint(pnLen * 8)
	pnWin := uint64(1) << pnBits
	pnHwin := pnWin / 2
	pnMask := pnWin - 1
	expected := largest + 1
	candidate := (expected &^ pnMask) | truncated
	if candidate+pnHwin <= expected && candidate < (uint64(1)<<62)-pnWin {
		return candidate + pnWin
	}
	if candidate > expected+pnHwin && candidate >= pnWin {
		return candidate - pnWin
	}
	return candidate
}

// --- key-log secrets ---

// QUICKeylog holds TLS secrets parsed from SSLKEYLOGFILE lines, indexed by NSS
// label. The same store capx already keeps for TLS decryption feeds QUIC here.
type QUICKeylog struct {
	entries map[string][]quicSecret
}

type quicSecret struct {
	clientRandom []byte
	secret       []byte
}

// ParseQUICKeylog parses NSS key-log lines ("<LABEL> <client_random> <secret>").
func ParseQUICKeylog(lines []string) *QUICKeylog {
	kl := &QUICKeylog{entries: map[string][]quicSecret{}}
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) != 3 {
			continue
		}
		cr, e1 := hex.DecodeString(f[1])
		sec, e2 := hex.DecodeString(f[2])
		if e1 != nil || e2 != nil {
			continue
		}
		kl.entries[f[0]] = append(kl.entries[f[0]], quicSecret{clientRandom: cr, secret: sec})
	}
	return kl
}

func (kl *QUICKeylog) secretsFor(clientRandom []byte, labels ...string) [][]byte {
	if kl == nil {
		return nil
	}
	var out [][]byte
	for _, lab := range labels {
		for _, e := range kl.entries[lab] {
			if len(clientRandom) > 0 && !bytes.Equal(clientRandom, e.clientRandom) {
				continue
			}
			out = append(out, e.secret)
		}
	}
	return out
}

// --- public decryption surface ---

// QUICStream is one STREAM frame's metadata (and a hex preview of its data).
type QUICStream struct {
	ID     uint64 `json:"id"`
	Offset uint64 `json:"offset"`
	Fin    bool   `json:"fin"`
	Len    int    `json:"len"`
	Data   string `json:"data_hex,omitempty"`
}

// QUICDecrypted is the result of decrypting any QUIC packet.
type QUICDecrypted struct {
	HeaderForm   string       `json:"header_form"` // "long" | "short"
	Type         string       `json:"type"`        // Initial/Handshake/0-RTT/1-RTT/Retry
	Level        string       `json:"level"`       // initial/handshake/0-rtt/1-rtt
	Suite        string       `json:"suite,omitempty"`
	Version      uint32       `json:"version,omitempty"`
	PacketNumber uint64       `json:"packet_number"`
	Frames       []string     `json:"frames,omitempty"`
	CryptoBytes  int          `json:"crypto_bytes,omitempty"`
	SNI          string       `json:"sni,omitempty"`
	ALPN         []string     `json:"alpn,omitempty"`
	Streams      []QUICStream `json:"streams,omitempty"`
}

// DecryptQUIC decrypts any QUIC v1 packet. Initial packets need no secrets
// (handled via the DCID). Handshake/0-RTT/1-RTT packets are decrypted with the
// matching TLS secret from kl. For short-header (1-RTT) packets the connection's
// Destination Connection ID length (dcidLen) is required because it is not
// carried in the packet; pass 0 for an empty/unknown DCID. largestPN is the
// largest packet number already seen in that packet-number space (0 if unknown —
// the full number is then recovered by a bounded search). clientRandom, when
// provided, restricts which key-log secrets are tried.
func DecryptQUIC(pkt []byte, kl *QUICKeylog, dcidLen int, largestPN uint64, clientRandom []byte) (*QUICDecrypted, error) {
	if len(pkt) < 5 {
		return nil, errors.New("packet too short")
	}
	if pkt[0]&0x80 == 0 {
		return decryptShortHeader(pkt, kl, dcidLen, largestPN, clientRandom)
	}
	return decryptLongHeader(pkt, kl, largestPN, clientRandom)
}

func decryptLongHeader(pkt []byte, kl *QUICKeylog, largestPN uint64, clientRandom []byte) (*QUICDecrypted, error) {
	version := binary.BigEndian.Uint32(pkt[1:5])
	if version != 0x00000001 {
		return nil, fmt.Errorf("unsupported QUIC version 0x%08x (only v1)", version)
	}
	typ := (pkt[0] >> 4) & 0x03
	switch typ {
	case 0: // Initial — reuse the DCID-based path, then enrich.
		init, err := DecryptQUICInitial(pkt)
		if err != nil {
			return nil, err
		}
		return &QUICDecrypted{
			HeaderForm: "long", Type: "Initial", Level: "initial", Version: version,
			PacketNumber: init.PacketNumber, Frames: init.Frames,
			CryptoBytes: init.CryptoBytes, SNI: init.SNI, ALPN: init.ALPN,
		}, nil
	case 3: // Retry — no encrypted payload.
		return &QUICDecrypted{HeaderForm: "long", Type: "Retry", Level: "n/a", Version: version}, nil
	}

	// Handshake (2) and 0-RTT (1): parse the long header to find the payload.
	pos := 5
	if pos >= len(pkt) {
		return nil, errors.New("truncated")
	}
	dcil := int(pkt[pos])
	pos += 1 + dcil
	if pos >= len(pkt) {
		return nil, errors.New("truncated DCID")
	}
	scil := int(pkt[pos])
	pos += 1 + scil
	if pos >= len(pkt) {
		return nil, errors.New("truncated SCID")
	}
	length, n := qvarint(pkt[pos:])
	if n == 0 {
		return nil, errors.New("bad length")
	}
	pos += n
	pnOffset := pos
	end := pnOffset + int(length)
	if end > len(pkt) {
		return nil, errors.New("length field overruns packet")
	}

	var labels []string
	level, typeName := "handshake", "Handshake"
	if typ == 2 {
		labels = []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"}
	} else {
		level, typeName = "0-rtt", "0-RTT"
		labels = []string{"CLIENT_EARLY_TRAFFIC_SECRET"}
	}
	secrets := kl.secretsFor(clientRandom, labels...)
	if len(secrets) == 0 {
		return nil, fmt.Errorf("no %s secret in key log (need %s)", typeName, strings.Join(labels, " or "))
	}

	pn, pt, suite, err := tryDecrypt(pkt, pnOffset, end, true, secrets, largestPN)
	if err != nil {
		return nil, err
	}
	out := &QUICDecrypted{
		HeaderForm: "long", Type: typeName, Level: level, Version: version,
		Suite: suite, PacketNumber: pn,
	}
	fillFrames(out, pt)
	return out, nil
}

func decryptShortHeader(pkt []byte, kl *QUICKeylog, dcidLen int, largestPN uint64, clientRandom []byte) (*QUICDecrypted, error) {
	// dcidLen is supplied by the caller (an API field), not the packet: reject
	// out-of-range values so pnOffset cannot go negative. RFC 9000 §17.2 caps
	// connection IDs at 20 bytes.
	if dcidLen < 0 || dcidLen > 20 {
		return nil, errors.New("dcid_len must be 0..20")
	}
	pnOffset := 1 + dcidLen
	end := len(pkt)
	if pnOffset+4+16 > end {
		return nil, errors.New("packet too short for a 1-RTT sample (check dcid_len)")
	}
	secrets := kl.secretsFor(clientRandom, "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")
	if len(secrets) == 0 {
		return nil, errors.New("no 1-RTT secret in key log (need CLIENT/SERVER_TRAFFIC_SECRET_0)")
	}
	pn, pt, suite, err := tryDecrypt(pkt, pnOffset, end, false, secrets, largestPN)
	if err != nil {
		return nil, err
	}
	out := &QUICDecrypted{
		HeaderForm: "short", Type: "1-RTT", Level: "1-rtt",
		Suite: suite, PacketNumber: pn,
	}
	fillFrames(out, pt)
	return out, nil
}

// tryDecrypt walks every (secret, suite) combination and returns the first that
// authenticates. pnOffset..end delimits the protected region; longHeader picks
// the 4- vs 5-bit first-byte mask.
func tryDecrypt(pkt []byte, pnOffset, end int, longHeader bool, secrets [][]byte, largestPN uint64) (uint64, []byte, string, error) {
	if pnOffset+4+16 > end {
		return 0, nil, "", errors.New("packet too short for HP sample")
	}
	for _, secret := range secrets {
		for _, s := range candidateSuites(len(secret)) {
			pn, pt, ok := openWithSuite(pkt, pnOffset, end, longHeader, s, secret, largestPN)
			if ok {
				return pn, pt, s.name, nil
			}
		}
	}
	return 0, nil, "", errors.New("decryption failed: no key-log secret matched this packet")
}

func openWithSuite(pkt []byte, pnOffset, end int, longHeader bool, s quicSuite, secret []byte, largestPN uint64) (uint64, []byte, bool) {
	key, iv, hp := s.keys(secret)
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	mask := s.hpMask(hp, sample)

	hdr := make([]byte, end)
	copy(hdr, pkt[:end])
	if longHeader {
		hdr[0] ^= mask[0] & 0x0f
	} else {
		hdr[0] ^= mask[0] & 0x1f
	}
	pnLen := int(hdr[0]&0x03) + 1
	var truncated uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(hdr[pnOffset+i])
	}

	aead, err := s.aead(key)
	if err != nil {
		return 0, nil, false
	}
	aad := hdr[:pnOffset+pnLen]
	ct := pkt[pnOffset+pnLen : end]

	open := func(fullPN uint64) ([]byte, bool) {
		nonce := make([]byte, 12)
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[11-i] ^= byte(fullPN >> (8 * i))
		}
		pt, err := aead.Open(nil, nonce, ct, aad)
		return pt, err == nil
	}

	// With a largest-PN hint (connection tracking) the full number is exact.
	if largestPN > 0 {
		if pt, ok := open(decodePacketNumber(largestPN, truncated, pnLen)); ok {
			return decodePacketNumber(largestPN, truncated, pnLen), pt, true
		}
	}
	// Otherwise recover the high bits by a bounded search; the AEAD tag confirms
	// the right value. The matching secret resolves within a few iterations for
	// real traffic (the truncation window already tracks the largest-acked PN).
	step := uint64(1) << uint(pnLen*8)
	base := truncated & (step - 1)
	const maxWindows = 1 << 14
	for k := uint64(0); k < maxWindows; k++ {
		full := base + k*step
		if pt, ok := open(full); ok {
			return full, pt, true
		}
	}
	return 0, nil, false
}

func fillFrames(out *QUICDecrypted, pt []byte) {
	frames, crypto, streams := walkQUICFrames(pt)
	out.Frames = frames
	out.Streams = streams
	if len(crypto) > 0 {
		out.CryptoBytes = len(crypto)
		out.SNI, out.ALPN = parseClientHello(crypto)
	}
}

// walkQUICFrames decodes the full RFC 9000 §19 frame set from a decrypted QUIC
// payload, returning a human-readable summary, the reassembled CRYPTO stream and
// any STREAM frames. It is bounds-safe: on a malformed/unknown frame it stops
// and returns what it has so far (QUIC payloads are PADDING-terminated).
func walkQUICFrames(b []byte) (frames []string, crypto []byte, streams []QUICStream) {
	var chunks []cryptoChunk
	i := 0
	// rv reads a varint at i, advancing it; ok=false on overrun.
	rv := func() (uint64, bool) {
		v, n := qvarint(b[i:])
		if n == 0 {
			return 0, false
		}
		i += n
		return v, true
	}
	for i < len(b) {
		ft := b[i]
		i++
		switch {
		case ft == 0x00: // PADDING
			for i < len(b) && b[i] == 0x00 {
				i++
			}
			frames = append(frames, "PADDING")
		case ft == 0x01:
			frames = append(frames, "PING")
		case ft == 0x02 || ft == 0x03: // ACK
			largest, ok1 := rv()
			_, ok2 := rv() // ack delay
			rangeCount, ok3 := rv()
			_, ok4 := rv() // first ack range
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return frames, joinChunks(chunks), streams
			}
			for r := uint64(0); r < rangeCount; r++ {
				if _, ok := rv(); !ok {
					return frames, joinChunks(chunks), streams
				}
				if _, ok := rv(); !ok {
					return frames, joinChunks(chunks), streams
				}
			}
			if ft == 0x03 {
				for e := 0; e < 3; e++ {
					if _, ok := rv(); !ok {
						return frames, joinChunks(chunks), streams
					}
				}
			}
			frames = append(frames, fmt.Sprintf("ACK(largest=%d)", largest))
		case ft == 0x04: // RESET_STREAM
			sid, ok1 := rv()
			ec, ok2 := rv()
			_, ok3 := rv()
			if !ok1 || !ok2 || !ok3 {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, fmt.Sprintf("RESET_STREAM(id=%d,err=%d)", sid, ec))
		case ft == 0x05: // STOP_SENDING
			sid, ok1 := rv()
			ec, ok2 := rv()
			if !ok1 || !ok2 {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, fmt.Sprintf("STOP_SENDING(id=%d,err=%d)", sid, ec))
		case ft == 0x06: // CRYPTO
			off, ok1 := rv()
			ln, ok2 := rv()
			if !ok1 || !ok2 || i+int(ln) > len(b) {
				return frames, joinChunks(chunks), streams
			}
			chunks = append(chunks, cryptoChunk{off: off, data: append([]byte(nil), b[i:i+int(ln)]...)})
			i += int(ln)
			frames = append(frames, fmt.Sprintf("CRYPTO(off=%d,len=%d)", off, ln))
		case ft == 0x07: // NEW_TOKEN
			ln, ok := rv()
			if !ok || i+int(ln) > len(b) {
				return frames, joinChunks(chunks), streams
			}
			i += int(ln)
			frames = append(frames, fmt.Sprintf("NEW_TOKEN(len=%d)", ln))
		case ft >= 0x08 && ft <= 0x0f: // STREAM
			sid, ok := rv()
			if !ok {
				return frames, joinChunks(chunks), streams
			}
			var off uint64
			if ft&0x04 != 0 {
				if off, ok = rv(); !ok {
					return frames, joinChunks(chunks), streams
				}
			}
			ln := uint64(len(b) - i)
			if ft&0x02 != 0 {
				if ln, ok = rv(); !ok {
					return frames, joinChunks(chunks), streams
				}
			}
			if i+int(ln) > len(b) {
				return frames, joinChunks(chunks), streams
			}
			data := b[i : i+int(ln)]
			i += int(ln)
			fin := ft&0x01 != 0
			preview := data
			if len(preview) > 64 {
				preview = preview[:64]
			}
			streams = append(streams, QUICStream{ID: sid, Offset: off, Fin: fin, Len: len(data), Data: hex.EncodeToString(preview)})
			frames = append(frames, fmt.Sprintf("STREAM(id=%d,off=%d,len=%d,fin=%v)", sid, off, len(data), fin))
		case ft == 0x10: // MAX_DATA
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "MAX_DATA")
		case ft == 0x11: // MAX_STREAM_DATA
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "MAX_STREAM_DATA")
		case ft == 0x12 || ft == 0x13: // MAX_STREAMS
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "MAX_STREAMS")
		case ft == 0x14: // DATA_BLOCKED
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "DATA_BLOCKED")
		case ft == 0x15: // STREAM_DATA_BLOCKED
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "STREAM_DATA_BLOCKED")
		case ft == 0x16 || ft == 0x17: // STREAMS_BLOCKED
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "STREAMS_BLOCKED")
		case ft == 0x18: // NEW_CONNECTION_ID
			if _, ok := rv(); !ok { // seq
				return frames, joinChunks(chunks), streams
			}
			if _, ok := rv(); !ok { // retire prior to
				return frames, joinChunks(chunks), streams
			}
			if i >= len(b) {
				return frames, joinChunks(chunks), streams
			}
			cidLen := int(b[i])
			i++
			if i+cidLen+16 > len(b) {
				return frames, joinChunks(chunks), streams
			}
			i += cidLen + 16
			frames = append(frames, "NEW_CONNECTION_ID")
		case ft == 0x19: // RETIRE_CONNECTION_ID
			if _, ok := rv(); !ok {
				return frames, joinChunks(chunks), streams
			}
			frames = append(frames, "RETIRE_CONNECTION_ID")
		case ft == 0x1a || ft == 0x1b: // PATH_CHALLENGE / PATH_RESPONSE
			if i+8 > len(b) {
				return frames, joinChunks(chunks), streams
			}
			i += 8
			if ft == 0x1a {
				frames = append(frames, "PATH_CHALLENGE")
			} else {
				frames = append(frames, "PATH_RESPONSE")
			}
		case ft == 0x1c || ft == 0x1d: // CONNECTION_CLOSE
			if _, ok := rv(); !ok { // error code
				return frames, joinChunks(chunks), streams
			}
			if ft == 0x1c {
				if _, ok := rv(); !ok { // frame type
					return frames, joinChunks(chunks), streams
				}
			}
			rl, ok := rv()
			if !ok || i+int(rl) > len(b) {
				return frames, joinChunks(chunks), streams
			}
			reason := string(b[i : i+int(rl)])
			i += int(rl)
			frames = append(frames, fmt.Sprintf("CONNECTION_CLOSE(%q)", reason))
			return frames, joinChunks(chunks), streams
		case ft == 0x1e: // HANDSHAKE_DONE
			frames = append(frames, "HANDSHAKE_DONE")
		case ft == 0x30 || ft == 0x31: // DATAGRAM (RFC 9221)
			ln := uint64(len(b) - i)
			if ft == 0x31 {
				var ok bool
				if ln, ok = rv(); !ok {
					return frames, joinChunks(chunks), streams
				}
			}
			if i+int(ln) > len(b) {
				return frames, joinChunks(chunks), streams
			}
			i += int(ln)
			frames = append(frames, fmt.Sprintf("DATAGRAM(len=%d)", ln))
		default:
			frames = append(frames, fmt.Sprintf("UNKNOWN(0x%02x)", ft))
			return frames, joinChunks(chunks), streams
		}
	}
	return frames, joinChunks(chunks), streams
}
