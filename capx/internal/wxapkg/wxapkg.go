// Package wxapkg unpacks (and, for PC WeChat, decrypts) compiled WeChat
// mini-program packages (.wxapkg). The plaintext bundle (app-service.js,
// page-frame, app-config.json, assets) is where API endpoints, AK/SK and
// business logic live — feeding capx's secret/endpoint extraction (HaE).
//
// Two on-disk forms are handled automatically:
//   - Standard wxapkg: starts with 0xBE ... 0xED index, then file blobs.
//   - PC encrypted wxapkg: starts with ASCII "V1MMWX"; AES-256-CBC over the
//     first 1024 bytes + single-byte XOR over the rest, keyed by the appId.
package wxapkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

const encMagic = "V1MMWX"

// IsEncrypted reports whether data is a PC-encrypted wxapkg.
func IsEncrypted(data []byte) bool {
	return len(data) >= 6 && string(data[:6]) == encMagic
}

// pbkdf2SHA1 derives a key (RFC 2898, HMAC-SHA1) without external deps.
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha1.Size
	blocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	var ctr [4]byte
	for b := 1; b <= blocks; b++ {
		binary.BigEndian.PutUint32(ctr[:], uint32(b))
		mac := hmac.New(sha1.New, password)
		mac.Write(salt)
		mac.Write(ctr[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// Decrypt converts a PC-encrypted wxapkg into the standard (0xBE) bundle using
// the mini-program appId (e.g. "wx1234567890abcdef", usually the folder name).
func Decrypt(appID string, data []byte) ([]byte, error) {
	if !IsEncrypted(data) {
		return data, nil
	}
	if appID == "" {
		return nil, fmt.Errorf("加密 wxapkg 需要 appId（通常是所在文件夹名 wxXXXX）")
	}
	body := data[6:]
	if len(body) < 1024 {
		return nil, fmt.Errorf("加密包过短")
	}
	key := pbkdf2SHA1([]byte(appID), []byte("saltiest"), 1000, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := []byte("the iv: 16 bytes")
	head := make([]byte, 1024)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(head, body[:1024])

	xorKey := byte(0x66)
	if len(appID) >= 2 {
		xorKey = appID[len(appID)-2]
	}
	rest := body[1024:]
	out := make([]byte, 0, 1023+len(rest))
	out = append(out, head[:1023]...)
	for _, b := range rest {
		out = append(out, b^xorKey)
	}
	return out, nil
}

// File is one extracted member of a wxapkg.
type File struct {
	Name string
	Data []byte
}

// Unpack parses a standard (decrypted) wxapkg into its member files.
func Unpack(data []byte) ([]File, error) {
	if len(data) < 18 || data[0] != 0xBE {
		return nil, fmt.Errorf("不是有效 wxapkg（缺少 0xBE 头；若是 PC 包需先解密）")
	}
	if data[13] != 0xED {
		return nil, fmt.Errorf("wxapkg 头标记错误（0xED）")
	}
	count := binary.BigEndian.Uint32(data[14:18])
	if count > 1_000_000 {
		return nil, fmt.Errorf("文件数异常: %d", count)
	}
	off := 18
	files := make([]File, 0, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(data) {
			return nil, fmt.Errorf("索引越界")
		}
		nameLen := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if nameLen < 0 || off+nameLen+8 > len(data) {
			return nil, fmt.Errorf("索引越界(name)")
		}
		name := string(data[off : off+nameLen])
		off += nameLen
		foff := int(binary.BigEndian.Uint32(data[off : off+4]))
		fsize := int(binary.BigEndian.Uint32(data[off+4 : off+8]))
		off += 8
		if foff < 0 || fsize < 0 || foff+fsize > len(data) {
			continue
		}
		files = append(files, File{Name: name, Data: data[foff : foff+fsize]})
	}
	return files, nil
}

// Process auto-detects encryption, decrypts if needed, and unpacks.
func Process(appID string, data []byte) (files []File, encrypted bool, err error) {
	encrypted = IsEncrypted(data)
	if encrypted {
		data, err = Decrypt(appID, data)
		if err != nil {
			return nil, true, err
		}
	}
	files, err = Unpack(data)
	return files, encrypted, err
}
