package wxapkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReconstruct(t *testing.T) {
	appConfig := []byte(`{"pages":["pages/index/index"],"window":{"navigationBarTitleText":"App"},"page":{"pages/index/index.html":{"window":{"navigationBarTitleText":"Home"},"usingComponents":{}}}}`)
	service := []byte(`define("pages/index/index.js", function(require, module, exports){ var api="https://api.x.com/login"; });`)
	wxss := []byte("setCssToHead([\".a{color:red;width:\",[0,750],\"}\"], undefined, {path:\"./pages/index/index.wxss\"})")
	files := []File{{Name: "/app-config.json", Data: appConfig}, {Name: "/app-service.js", Data: service}, {Name: "/page-frame.js", Data: wxss}}
	extra, _ := Reconstruct(files)
	m := map[string]string{}
	for _, f := range extra {
		m[f.Name] = string(f.Data)
	}
	if _, ok := m["/app.json"]; !ok {
		t.Fatal("missing app.json")
	}
	if _, ok := m["/pages/index/index.json"]; !ok {
		t.Fatal("missing page json")
	}
	if !strings.Contains(m["/pages/index/index.js"], "api.x.com/login") {
		t.Fatalf("page js wrong: %q", m["/pages/index/index.js"])
	}
	if !strings.Contains(m["/pages/index/index.wxss"], "color:red") || !strings.Contains(m["/pages/index/index.wxss"], "750rpx") {
		t.Fatalf("wxss wrong: %q", m["/pages/index/index.wxss"])
	}
}

// buildWxapkg crafts a standard (0xBE) wxapkg from members.
func buildWxapkg(files []File) []byte {
	entrySize := 0
	for _, f := range files {
		entrySize += 4 + len(f.Name) + 8
	}
	bodyStart := 18 + entrySize
	var body bytes.Buffer
	type ent struct {
		name      string
		off, size uint32
	}
	ents := make([]ent, 0, len(files))
	cur := bodyStart
	for _, f := range files {
		ents = append(ents, ent{f.Name, uint32(cur), uint32(len(f.Data))})
		body.Write(f.Data)
		cur += len(f.Data)
	}
	var out bytes.Buffer
	out.WriteByte(0xBE)
	binary.Write(&out, binary.BigEndian, uint32(0))
	binary.Write(&out, binary.BigEndian, uint32(entrySize))
	binary.Write(&out, binary.BigEndian, uint32(body.Len()))
	out.WriteByte(0xED)
	binary.Write(&out, binary.BigEndian, uint32(len(files)))
	for _, e := range ents {
		binary.Write(&out, binary.BigEndian, uint32(len(e.name)))
		out.WriteString(e.name)
		binary.Write(&out, binary.BigEndian, e.off)
		binary.Write(&out, binary.BigEndian, e.size)
	}
	out.Write(body.Bytes())
	return out.Bytes()
}

func encryptWx(appID string, plain []byte) []byte {
	key := pbkdf2SHA1([]byte(appID), []byte("saltiest"), 1000, 32)
	block, _ := aes.NewCipher(key)
	iv := []byte("the iv: 16 bytes")
	x := make([]byte, 1024)
	copy(x, plain[:1023])
	enc := make([]byte, 1024)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, x)
	xorKey := byte(0x66)
	if len(appID) >= 2 {
		xorKey = appID[len(appID)-2]
	}
	out := append([]byte(encMagic), enc...)
	for _, b := range plain[1023:] {
		out = append(out, b^xorKey)
	}
	return out
}

func TestUnpackPlain(t *testing.T) {
	files := []File{
		{Name: "/app-service.js", Data: []byte("var url='https://api.example.com/v1/login';var ak='LTAI5xxxxxxxxxxxxx';")},
		{Name: "/app.json", Data: []byte(`{"pages":["pages/index/index"]}`)},
	}
	got, err := Unpack(buildWxapkg(files))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 files got %d", len(got))
	}
	m := map[string]string{}
	for _, f := range got {
		m[f.Name] = string(f.Data)
	}
	if m["/app.json"] != `{"pages":["pages/index/index"]}` {
		t.Fatalf("app.json mismatch: %q", m["/app.json"])
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	big := make([]byte, 0, 4096)
	big = append(big, []byte("var token='secret_abcdefgh';")...)
	for len(big) < 2000 {
		big = append(big, 'x')
	}
	plain := buildWxapkg([]File{{Name: "/page-frame.js", Data: big}})
	appID := "wx1234567890abcdef"
	enc := encryptWx(appID, plain)
	if !IsEncrypted(enc) {
		t.Fatal("IsEncrypted false")
	}
	files, wasEnc, err := Process(appID, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !wasEnc {
		t.Fatal("expected encrypted")
	}
	if len(files) != 1 || files[0].Name != "/page-frame.js" {
		t.Fatalf("unpack after decrypt failed: %+v", files)
	}
	if !bytes.Equal(files[0].Data, big) {
		t.Fatalf("decrypted content mismatch (len %d vs %d)", len(files[0].Data), len(big))
	}
}
