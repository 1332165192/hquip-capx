//go:build !pcap

package sniffer

import (
	"context"

	"github.com/hquip/capx/internal/store"
)

type stub struct{}

func newBackend() Sniffer { return stub{} }

func (stub) Backend() string { return "stub" }

func (stub) Run(ctx context.Context, captureID string, cfg Config, st *store.Store) error {
	return ErrNoPcap
}

func (stub) Interfaces() ([]Device, error) { return nil, ErrNoPcap }
