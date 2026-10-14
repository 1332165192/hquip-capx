package proxy

import (
	_ "unsafe"

	_ "github.com/hquip/capx/internal/h2boot"
	_ "golang.org/x/net/http2"
)

// Enable RFC 8441 Extended CONNECT on golang.org/x/net/http2 so browsers can
// open WebSockets over HTTP/2. The public API only exposes this via
// GODEBUG=http2xconnect=1 (read in http2.init). After that init we flip the
// unexported flag so SETTINGS_ENABLE_CONNECT_PROTOCOL is advertised even if
// GODEBUG was not set in time.
//
//go:linkname http2DisableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var http2DisableExtendedConnectProtocol bool

func init() {
	http2DisableExtendedConnectProtocol = false
}
