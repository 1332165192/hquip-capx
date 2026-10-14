//go:build grpc

package grpcserver

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/store"
)

func newTestServer(t *testing.T, token string) (*Server, *grpc.ClientConn) {
	t.Helper()
	s, err := New(store.New(100), sniffer.New(), memscan.New(), token)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx, lis) }()
	t.Cleanup(cancel)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return s, conn
}

func (s *Server) msg(method string, input bool) *dynamicpb.Message {
	md := s.svc.Methods().ByName(protoreflect.Name(method))
	if input {
		return dynamicpb.NewMessage(md.Input())
	}
	return dynamicpb.NewMessage(md.Output())
}

func (s *Server) invoke(t *testing.T, conn *grpc.ClientConn, method string, req *dynamicpb.Message) (*dynamicpb.Message, error) {
	t.Helper()
	resp := s.msg(method, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := conn.Invoke(ctx, "/capx.v1.Capx/"+method, req, resp)
	return resp, err
}

func TestGRPCStartCaptureAndListFlows(t *testing.T) {
	s, conn := newTestServer(t, "")

	// StartCapture returns a Capture echoing our inputs + the sniffer backend.
	req := s.msg("StartCapture", true)
	setStr(req, "iface", "eth0")
	setStr(req, "filter", "tcp or udp")
	cap, err := s.invoke(t, conn, "StartCapture", req)
	if err != nil {
		t.Fatalf("StartCapture: %v", err)
	}
	if getStr(cap, "id") == "" {
		t.Error("capture id empty")
	}
	if getStr(cap, "filter") != "tcp or udp" {
		t.Errorf("filter = %q", getStr(cap, "filter"))
	}
	if getStr(cap, "backend") == "" {
		t.Error("backend empty")
	}

	// ListFlows works (empty store -> empty list, no error).
	if _, err := s.invoke(t, conn, "ListFlows", s.msg("ListFlows", true)); err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
}

func TestGRPCMemOpenUnavailable(t *testing.T) {
	s, conn := newTestServer(t, "")
	req := s.msg("MemOpen", true)
	setUint(req, "pid", 1234)
	_, err := s.invoke(t, conn, "MemOpen", req)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("MemOpen without FFI engine: got %v, want Unimplemented", err)
	}
}

func TestGRPCAuth(t *testing.T) {
	s, conn := newTestServer(t, "s3cret")

	// No token -> Unauthenticated.
	if _, err := s.invoke(t, conn, "ListFlows", s.msg("ListFlows", true)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no-token call: got %v, want Unauthenticated", err)
	}

	// With token -> OK.
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer s3cret")
	resp := s.msg("ListFlows", false)
	if err := conn.Invoke(ctx, "/capx.v1.Capx/ListFlows", s.msg("ListFlows", true), resp); err != nil {
		t.Fatalf("token call: %v", err)
	}
}
