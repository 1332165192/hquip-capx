//go:build !windows && !linux && !darwin

package api

import "errors"

// listModules is unsupported outside Windows/Linux for now.
func listModules(pid uint32) ([]memModule, error) {
	return nil, errors.New("module listing only supported on windows and linux")
}
