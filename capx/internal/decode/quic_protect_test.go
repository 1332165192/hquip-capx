package decode

import (
	"encoding/hex"
	"testing"
)

// TestChaCha20KeyDerivation checks the "quic key"/"quic iv"/"quic hp" expansion
// against the RFC 9001 Appendix A.5 ChaCha20-Poly1305 known-answer vectors.
func TestChaCha20KeyDerivation(t *testing.T) {
	secret, _ := hex.DecodeString("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	s := candidateSuites(len(secret))[1] // ChaCha20-Poly1305 (32-byte, SHA-256)
	if s.hpKind != "chacha" {
		t.Fatalf("expected chacha suite, got %s", s.name)
	}
	key, iv, hp := s.keys(secret)
	checks := map[string]struct{ got, want string }{
		"key": {hex.EncodeToString(key), "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"},
		"iv":  {hex.EncodeToString(iv), "e0459b3474bdd0e44a41c144"},
		"hp":  {hex.EncodeToString(hp), "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", name, c.got, c.want)
		}
	}
}

// TestDecryptChaCha20ShortHeader decrypts the RFC 9001 Appendix A.5 protected
// 1-RTT (short-header) packet. The DCID is empty (dcid_len=0); the full packet
// number (654360564) is recovered by the bounded search with no hint.
func TestDecryptChaCha20ShortHeader(t *testing.T) {
	secret := "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
	kl := ParseQUICKeylog([]string{"CLIENT_TRAFFIC_SECRET_0 " + dummyClientRandom + " " + secret})

	pkt, _ := hex.DecodeString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	out, err := DecryptQUIC(pkt, kl, 0 /*dcid_len*/, 0 /*largest_pn*/, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out.Type != "1-RTT" {
		t.Errorf("type = %s, want 1-RTT", out.Type)
	}
	if out.Suite != "AEAD_CHACHA20_POLY1305" {
		t.Errorf("suite = %s, want AEAD_CHACHA20_POLY1305", out.Suite)
	}
	if out.PacketNumber != 654360564 {
		t.Errorf("packet number = %d, want 654360564", out.PacketNumber)
	}
	if len(out.Frames) != 1 || out.Frames[0] != "PING" {
		t.Errorf("frames = %v, want [PING]", out.Frames)
	}
}

// TestDecryptChaCha20WithHint exercises the largest-PN hint path (the one used
// when a connection tracker knows the packet-number space).
func TestDecryptChaCha20WithHint(t *testing.T) {
	secret := "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
	kl := ParseQUICKeylog([]string{"SERVER_TRAFFIC_SECRET_0 " + dummyClientRandom + " " + secret})
	pkt, _ := hex.DecodeString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	out, err := DecryptQUIC(pkt, kl, 0, 654360563 /*largest_pn*/, nil)
	if err != nil {
		t.Fatalf("decrypt with hint: %v", err)
	}
	if out.PacketNumber != 654360564 {
		t.Errorf("packet number = %d, want 654360564", out.PacketNumber)
	}
}

// TestDecodePacketNumber covers the RFC 9000 Appendix A.3 reconstruction.
func TestDecodePacketNumber(t *testing.T) {
	// Example from RFC 9000 A.3: largest=0xa82f30ea, truncated=0x9b32, len=2.
	if got := decodePacketNumber(0xa82f30ea, 0x9b32, 2); got != 0xa82f9b32 {
		t.Errorf("decodePacketNumber = 0x%x, want 0xa82f9b32", got)
	}
}

const dummyClientRandom = "0000000000000000000000000000000000000000000000000000000000000000"
