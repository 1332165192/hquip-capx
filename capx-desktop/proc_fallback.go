//go:build !windows && !linux && !darwin

package main

import "errors"

func backendProcessInfo(int) (string, []string, error) {
	return "", nil, errors.New("process identity lookup is unsupported on this platform")
}
