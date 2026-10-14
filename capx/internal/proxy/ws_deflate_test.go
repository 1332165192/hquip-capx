package proxy

import (
	"bytes"
	"testing"
)

func TestStripPMDExtensions(t *testing.T) {
	got := stripPMDExtensions("permessage-deflate; client_max_window_bits")
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	got = stripPMDExtensions("permessage-deflate, mux")
	if got != "mux" {
		t.Fatalf("got %q", got)
	}
}

func TestInflateDeflatePMDRoundTrip(t *testing.T) {
	plain := []byte(`{"act":"ping","n":1}`)
	enc, err := deflatePMD(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("deflate produced identity")
	}
	got, err := inflatePMD(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip %q vs %q", got, plain)
	}
}

func TestStripWSExtensionsBlock(t *testing.T) {
	in := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n")
	out := stripWSExtensionsBlock(in)
	if bytes.Contains(bytes.ToLower(out), []byte("permessage-deflate")) {
		t.Fatalf("pmd still present: %s", out)
	}
	if !bytes.Contains(out, []byte("Upgrade: websocket")) {
		t.Fatalf("lost upgrade: %s", out)
	}
}

func TestBuildWSFrameFlagsSetsRSV1(t *testing.T) {
	frame := buildWSFrameFlags(0x1, []byte("hi"), false, true)
	if frame[0]&0x40 == 0 {
		t.Fatalf("RSV1 not set: %#x", frame[0])
	}
	if frame[0]&0x80 == 0 {
		t.Fatalf("FIN not set: %#x", frame[0])
	}
}
