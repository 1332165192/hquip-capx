//go:build !windows

package mobilevpn

import "os"

func protectSecret(b []byte) ([]byte, error)   { return b, nil }
func unprotectSecret(b []byte) ([]byte, error) { return b, nil }
func privatePermissions(path string) error     { return os.Chmod(path, 0600) }
