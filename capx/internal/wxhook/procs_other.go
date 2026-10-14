//go:build !windows

package wxhook

import "errors"

// listWeChatAppEx is Windows-only; other platforms report unsupported.
func listWeChatAppEx() ([]Process, error) {
	return nil, errors.New("wxhook: WeChat mini-program DevTools hook is Windows-only")
}
