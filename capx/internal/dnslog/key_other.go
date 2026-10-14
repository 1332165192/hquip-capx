//go:build !windows

package dnslog

// Unix files use 0600 permissions; Windows additionally uses per-user DPAPI.
func protectKey(data []byte) ([]byte, error)   { return data, nil }
func unprotectKey(data []byte) ([]byte, error) { return data, nil }
