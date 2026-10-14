//go:build !grpc

package main

import (
	"context"
	"log"

	"github.com/hquip/capx/internal/daemon"
)

// maybeStartGRPC is a no-op in default builds. Rebuild with -tags grpc to enable
// the gRPC transport.
func maybeStartGRPC(_ context.Context, _ *daemon.Components, addr string) {
	if addr != "" {
		log.Printf("capx: -grpc %s ignored; rebuild with -tags grpc to enable the gRPC API", addr)
	}
}
