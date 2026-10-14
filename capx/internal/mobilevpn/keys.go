package mobilevpn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

type keyPair [32]byte

func newKey() (keyPair, error) {
	var k keyPair
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}
func (k keyPair) hex() string    { return hex.EncodeToString(k[:]) }
func (k keyPair) base64() string { return base64.StdEncoding.EncodeToString(k[:]) }
func (k keyPair) public() keyPair {
	b, _ := curve25519.X25519(k[:], curve25519.Basepoint)
	var public keyPair
	copy(public[:], b)
	return public
}

type privateKeys struct {
	Version int     `json:"version"`
	Server  keyPair `json:"server"`
	Client  keyPair `json:"client"`
}

func loadKeys(dir string) (privateKeys, error) {
	var keys privateKeys
	if dir != "" {
		path := filepath.Join(dir, "keys.v1")
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 8192 {
				return keys, errors.New("VPN key file is not a regular private file")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return keys, errors.New("cannot read VPN key file")
			}
			b, err = unprotectSecret(b)
			if err != nil {
				return keys, errors.New("cannot unlock VPN key file for current user")
			}
			if err = json.Unmarshal(b, &keys); err != nil || keys.Version != 1 || keys.Server == (keyPair{}) || keys.Client == (keyPair{}) {
				return privateKeys{}, errors.New("invalid VPN key file")
			}
			if err = privatePermissions(path); err != nil {
				return privateKeys{}, errors.New("cannot secure VPN key file")
			}
			return keys, nil
		} else if !os.IsNotExist(err) {
			return keys, errors.New("cannot access VPN key file")
		}
	}
	var err error
	keys.Version = 1
	if keys.Server, err = newKey(); err != nil {
		return keys, err
	}
	if keys.Client, err = newKey(); err != nil {
		return keys, err
	}
	if dir == "" {
		return keys, nil
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return keys, errors.New("cannot create private VPN state directory")
	}
	b, _ := json.Marshal(keys)
	b, err = protectSecret(b)
	if err != nil {
		return keys, errors.New("cannot protect VPN keys for current user")
	}
	f, err := os.CreateTemp(dir, ".vpn-keys-*")
	if err != nil {
		return keys, errors.New("cannot create private VPN key file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = privatePermissions(tmp); err == nil {
		_, err = f.Write(b)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return keys, errors.New("cannot save private VPN key file")
	}
	if err = os.Rename(tmp, filepath.Join(dir, "keys.v1")); err != nil {
		return keys, errors.New("cannot install private VPN key file")
	}
	return keys, nil
}
