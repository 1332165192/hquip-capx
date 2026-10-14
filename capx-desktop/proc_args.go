package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// Darwin returns argc, an executable path, NUL padding, argv, then environment.
// Only the executable path and argc arguments are retained; environment data
// is never used as ownership evidence.
func decodeDarwinProcessArgs(raw []byte) (string, []string, error) {
	bad := errors.New("invalid Darwin process argument data")
	if len(raw) < 5 || len(raw) > 4<<20 {
		return "", nil, bad
	}
	argc := int(binary.NativeEndian.Uint32(raw[:4]))
	if argc < 1 || argc > 65536 {
		return "", nil, bad
	}
	raw = raw[4:]
	end := bytes.IndexByte(raw, 0)
	if end < 1 {
		return "", nil, bad
	}
	exe := string(raw[:end])
	raw = bytes.TrimLeft(raw[end+1:], "\x00")
	args := make([]string, 0, argc)
	for range argc {
		end = bytes.IndexByte(raw, 0)
		if end < 0 {
			return "", nil, bad
		}
		args = append(args, string(raw[:end]))
		raw = raw[end+1:]
	}
	return exe, args, nil
}

func backendIdentityMatchesArgs(rt desktopRuntime, exe string, args []string) bool {
	wanted := map[string]bool{"addr": true, "state-dir": true, "generation": true, "instance-id": true}
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			continue
		}
		name, value, equal := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if !wanted[name] {
			continue
		}
		if _, duplicate := values[name]; duplicate {
			return false
		}
		if !equal {
			if i+1 >= len(args) {
				return false
			}
			i++
			value = args[i]
		}
		values[name] = value
	}
	if len(values) != len(wanted) {
		return false
	}
	return backendIdentityMatchesValues(rt, exe, values)
}
