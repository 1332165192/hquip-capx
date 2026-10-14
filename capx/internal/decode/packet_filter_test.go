package decode

import (
	"encoding/binary"
	"testing"
)

func buildEthIPv4TCP() []byte {
	pkt := make([]byte, 14+20+20)
	// Ethernet
	copy(pkt[0:6], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(pkt[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	// IPv4
	ip := pkt[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64 // ttl
	ip[9] = 6  // TCP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	// TCP
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50 // data offset 5*4=20
	tcp[13] = 0x02 // SYN
	return pkt
}

func TestDecodePacketTree(t *testing.T) {
	layers := DecodePacket(buildEthIPv4TCP())
	if len(layers) != 3 {
		t.Fatalf("got %d layers, want 3: %+v", len(layers), layers)
	}
	if layers[0].Name != "Ethernet" || layers[1].Name != "IPv4" || layers[2].Name != "TCP" {
		t.Fatalf("layer names = %s/%s/%s", layers[0].Name, layers[1].Name, layers[2].Name)
	}
	// IPv4 dst should be the well-known address.
	var dst string
	for _, f := range layers[1].Fields {
		if f[0] == "dst" {
			dst = f[1]
		}
	}
	if dst != "93.184.216.34" {
		t.Fatalf("ipv4 dst = %q", dst)
	}
	// TCP flags should include SYN.
	var flags string
	for _, f := range layers[2].Fields {
		if f[0] == "flags" {
			flags = f[1]
		}
	}
	if flags != "SYN" {
		t.Fatalf("tcp flags = %q, want SYN", flags)
	}
}

func TestDisplayFilter(t *testing.T) {
	ff := FilterFields{Host: "api.example.com", Method: "POST", URL: "https://api.example.com/admin", MIME: "application/json", Scheme: "https", Status: 403}
	cases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"host == api.example.com", true},
		{"host == other.com", false},
		{"status >= 400", true},
		{"status < 400", false},
		{`url contains "/admin"`, true},
		{"method == POST and status == 403", true},
		{"method == GET or mime contains json", true},
		{"not status == 200", true},
		{"(host == x or host == api.example.com) and status >= 400", true},
	}
	for _, c := range cases {
		f, err := CompileFilter(c.expr)
		if err != nil {
			t.Fatalf("compile %q: %v", c.expr, err)
		}
		if got := f.Match(ff); got != c.want {
			t.Errorf("%q => %v, want %v", c.expr, got, c.want)
		}
	}
	if _, err := CompileFilter("bogus == 1"); err == nil {
		t.Error("expected error for unknown field")
	}
}
