package mobilevpn

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func saveSettings(dir string, opts Options) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create private VPN settings directory")
	}
	b, err := json.Marshal(opts)
	if err == nil {
		b, err = protectSecret(b)
	}
	if err != nil {
		return errors.New("cannot protect VPN settings")
	}
	f, err := os.CreateTemp(dir, ".vpn-settings-*")
	if err != nil {
		return errors.New("cannot save private VPN settings")
	}
	path := f.Name()
	defer os.Remove(path)
	if err = privatePermissions(path); err == nil {
		_, err = f.Write(b)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot save private VPN settings")
	}
	if err = os.Rename(path, filepath.Join(dir, "settings.v1")); err != nil {
		return errors.New("cannot install private VPN settings")
	}
	return nil
}

func readSettings(dir string) (Options, error) {
	var opts Options
	if dir == "" {
		return opts, nil
	}
	path := filepath.Join(dir, "settings.v1")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return opts, nil
	}
	if err != nil {
		return opts, errors.New("cannot read saved VPN settings")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 65536 {
		return opts, errors.New("saved VPN settings are not a regular private file")
	}
	b, err := os.ReadFile(path)
	if err == nil {
		b, err = unprotectSecret(b)
	}
	if err != nil {
		return opts, errors.New("cannot unlock saved VPN settings for current user")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&opts); err != nil {
		return Options{}, errors.New("invalid saved VPN settings")
	}
	opts, _, _, err = normalizeOptions(opts)
	if err != nil {
		return Options{}, errors.New("invalid saved VPN settings")
	}
	if err = privatePermissions(path); err != nil {
		return Options{}, errors.New("cannot secure saved VPN settings")
	}
	return opts, nil
}

func statusOptions(opts Options) Status {
	return Status{ListenAddr: opts.ListenAddr, Endpoint: opts.Endpoint, ClientIP: clientIP, Routes: append([]string(nil), opts.Routes...), Packages: append([]string(nil), opts.Packages...), DNS: append([]string(nil), opts.DNS...), MTU: opts.MTU, InterceptHTTP: opts.InterceptHTTP, HTTPPorts: append([]uint16(nil), opts.HTTPPorts...)}
}
