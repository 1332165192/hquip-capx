//go:build !linux && !windows && !darwin

package api

import "errors"

// listRegions is unsupported on this platform.
func listRegions(pid uint32) ([]memRegion, error) {
	return nil, errors.New("region enumeration not supported on this platform")
}
