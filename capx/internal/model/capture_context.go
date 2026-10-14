package model

import "context"

type CaptureTransportInfo struct {
	Mode       string
	ClientAddr string
	PeerID     string
}
type captureTransportKey struct{}

// WithCaptureTransport is for authenticated in-process ingress adapters, not
// API payloads or request headers. It records channel provenance only.
func WithCaptureTransport(ctx context.Context, info CaptureTransportInfo) context.Context {
	return context.WithValue(ctx, captureTransportKey{}, info)
}
func CaptureTransport(ctx context.Context) CaptureTransportInfo {
	info, _ := ctx.Value(captureTransportKey{}).(CaptureTransportInfo)
	return info
}
