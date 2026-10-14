// Package h2boot sets GODEBUG=http2xconnect=1 before golang.org/x/net/http2
// initializes, so SETTINGS_ENABLE_CONNECT_PROTOCOL is advertised and RFC 8441
// WebSockets can be intercepted. Import this package from a source file that
// sorts before any file importing http2 (see proxy/aa_h2boot.go).
package h2boot

import (
	"os"
	"strings"
)

func init() {
	g := os.Getenv("GODEBUG")
	if strings.Contains(g, "http2xconnect=1") {
		return
	}
	if g == "" {
		_ = os.Setenv("GODEBUG", "http2xconnect=1")
		return
	}
	_ = os.Setenv("GODEBUG", g+",http2xconnect=1")
}
