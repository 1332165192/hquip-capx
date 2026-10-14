//go:build grpc

package main

import (
	"context"
	"log"
	"net"

	"github.com/hquip/capx/internal/daemon"
	"github.com/hquip/capx/internal/grpcserver"
)

// maybeStartGRPC starts the capx gRPC API on addr (empty = disabled). It reuses
// the same store / sniffer / memory-scan engine as the REST API and the same
// token auth. Built only when the "grpc" tag is set.
func maybeStartGRPC(ctx context.Context, comp *daemon.Components, addr string) {
	if addr == "" {
		return
	}
	token := ""
	if comp.Server.AuthEnabled() {
		token = comp.Server.AuthToken()
	}
	gs, err := grpcserver.New(comp.Store, comp.Sniffer, comp.Scanner, token)
	if err != nil {
		log.Printf("capx: gRPC API disabled: %v", err)
		return
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("capx: gRPC listen on %s failed: %v", addr, err)
		return
	}
	log.Printf("capx: gRPC API listening on %s", addr)
	go func() {
		if err := gs.Serve(ctx, lis); err != nil {
			log.Printf("capx: gRPC server stopped: %v", err)
		}
	}()
}
