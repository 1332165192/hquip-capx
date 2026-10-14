//go:build grpc

// Package grpcserver serves the capx gRPC API described in
// capx/proto/capture.proto. capx ships without a protoc-generated stub, so the
// service is built dynamically: the .proto is parsed at runtime with
// bufbuild/protocompile, and each RPC is dispatched through dynamicpb messages
// onto the same store / sniffer / memory-scan engine the REST API uses. This
// keeps the gRPC and REST surfaces 1:1 without a codegen step, and is gated
// behind the "grpc" build tag so default builds stay dependency-light.
package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bufbuild/protocompile"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/store"
)

// Server implements the capx.v1.Capx gRPC service dynamically.
type Server struct {
	st      *store.Store
	snif    sniffer.Sniffer
	scanner memscan.Scanner
	token   string

	svc protoreflect.ServiceDescriptor

	mu       sync.Mutex
	seq      int
	captures map[string]context.CancelFunc
	memSeq   int
	memSess  map[string]memscan.Session
}

// New parses the embedded proto and returns a ready gRPC server. token (when
// non-empty) is required from clients as an "authorization: Bearer <token>" or
// "x-capx-token" metadata header, mirroring the REST auth.
func New(st *store.Store, snif sniffer.Sniffer, scanner memscan.Scanner, token string) (*Server, error) {
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			Accessor: protocompile.SourceAccessorFromMap(map[string]string{
				"capture.proto": protoSrc,
			}),
		}),
	}
	files, err := compiler.Compile(context.Background(), "capture.proto")
	if err != nil {
		return nil, fmt.Errorf("compile capture.proto: %w", err)
	}
	svc := files[0].Services().ByName("Capx")
	if svc == nil {
		return nil, fmt.Errorf("Capx service not found in proto")
	}
	return &Server{
		st: st, snif: snif, scanner: scanner, token: token, svc: svc,
		captures: map[string]context.CancelFunc{},
		memSess:  map[string]memscan.Session{},
	}, nil
}

// Serve registers the dynamic service on a new grpc.Server and serves on lis
// until the context is cancelled.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	g := grpc.NewServer(
		grpc.UnaryInterceptor(s.unaryAuth),
		grpc.StreamInterceptor(s.streamAuth),
	)
	s.register(g)
	go func() {
		<-ctx.Done()
		g.GracefulStop()
	}()
	return g.Serve(lis)
}

func (s *Server) register(g *grpc.Server) {
	sd := grpc.ServiceDesc{ServiceName: string(s.svc.FullName()), HandlerType: (*any)(nil)}
	methods := s.svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		name := string(md.Name())
		if md.IsStreamingServer() {
			sd.Streams = append(sd.Streams, grpc.StreamDesc{
				StreamName: name, ServerStreams: true, Handler: s.streamHandler(md),
			})
			continue
		}
		sd.Methods = append(sd.Methods, grpc.MethodDesc{MethodName: name, Handler: s.unaryHandler(md)})
	}
	g.RegisterService(&sd, s)
}

func (s *Server) unaryHandler(md protoreflect.MethodDescriptor) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := dynamicpb.NewMessage(md.Input())
		if err := dec(in); err != nil {
			return nil, err
		}
		invoke := func(ctx context.Context, req any) (any, error) {
			return s.dispatch(ctx, md, req.(*dynamicpb.Message))
		}
		if interceptor == nil {
			return invoke(ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + string(s.svc.FullName()) + "/" + string(md.Name())}
		return interceptor(ctx, in, info, invoke)
	}
}

func (s *Server) streamHandler(md protoreflect.MethodDescriptor) func(any, grpc.ServerStream) error {
	return func(srv any, stream grpc.ServerStream) error {
		in := dynamicpb.NewMessage(md.Input())
		if err := stream.RecvMsg(in); err != nil {
			return err
		}
		return s.streamEvents(stream, md)
	}
}

// --- auth interceptors ---

func (s *Server) authOK(ctx context.Context) bool {
	if s.token == "" {
		return true
	}
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		if v == "Bearer "+s.token || v == s.token {
			return true
		}
	}
	for _, v := range md.Get("x-capx-token") {
		if v == s.token {
			return true
		}
	}
	return false
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !s.authOK(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid capx token")
	}
	return handler(ctx, req)
}

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !s.authOK(ss.Context()) {
		return status.Error(codes.Unauthenticated, "missing or invalid capx token")
	}
	return handler(srv, ss)
}

// --- dispatch ---

func (s *Server) dispatch(ctx context.Context, md protoreflect.MethodDescriptor, in *dynamicpb.Message) (any, error) {
	out := dynamicpb.NewMessage(md.Output())
	switch string(md.Name()) {
	case "StartCapture":
		return s.startCapture(in, out)
	case "StopCapture":
		return s.stopCapture(in, out)
	case "ListFlows":
		return s.listFlows(in, out)
	case "MemOpen":
		return s.memOpen(in, out)
	case "MemFirstScan":
		return s.memFirstScan(in, out)
	case "MemNextScan":
		return s.memNextScan(in, out)
	case "MemAOBScan":
		return s.memAOBScan(in, out)
	case "MemResults":
		return s.memResults(in, out)
	case "MemClose":
		return s.memClose(in, out)
	}
	return nil, status.Errorf(codes.Unimplemented, "method %s", md.Name())
}

func (s *Server) startCapture(in, out *dynamicpb.Message) (any, error) {
	iface := getStr(in, "iface")
	filter := getStr(in, "filter")
	maxRaw := int(getInt(in, "max_raw"))
	mode := model.ModePassive
	if getEnum(in, "mode") == 1 {
		mode = model.ModeActive
	}

	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("gcap-%d", s.seq)
	s.mu.Unlock()

	c := &model.Capture{
		ID: id, Iface: iface, Filter: filter, Mode: mode,
		Started: time.Now().UTC(), Running: true, Backend: s.snif.Backend(),
	}
	s.st.PutCapture(c)

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.captures[id] = cancel
	s.mu.Unlock()

	go func() {
		err := s.snif.Run(ctx, id, sniffer.Config{Iface: iface, Filter: filter, MaxRaw: maxRaw}, s.st)
		now := time.Now().UTC()
		if cc, ok := s.st.GetCapture(id); ok {
			cc.Running = false
			cc.Stopped = &now
			s.st.PutCapture(cc)
		}
		kind, msg := "capture_stopped", ""
		if err != nil && ctx.Err() == nil {
			kind, msg = "capture_error", err.Error()
		}
		s.st.Publish(model.Event{Source: model.SourceSniffer, Kind: kind,
			Data: map[string]string{"capture": id, "error": msg}})
		s.mu.Lock()
		delete(s.captures, id)
		s.mu.Unlock()
	}()

	modeEnum := int32(0)
	if mode == model.ModeActive {
		modeEnum = 1
	}
	setStr(out, "id", id)
	setStr(out, "iface", iface)
	setStr(out, "filter", filter)
	setEnum(out, "mode", modeEnum)
	setBool(out, "running", true)
	setStr(out, "backend", s.snif.Backend())
	setTimestamp(out, "started", c.Started)
	return out, nil
}

func (s *Server) stopCapture(in, out *dynamicpb.Message) (any, error) {
	id := getStr(in, "id")
	s.mu.Lock()
	cancel, ok := s.captures[id]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "capture %s not found or already stopped", id)
	}
	cancel()
	return out, nil
}

func (s *Server) listFlows(in, out *dynamicpb.Message) (any, error) {
	flowsFD := out.Descriptor().Fields().ByName("flows")
	list := out.NewField(flowsFD).List()
	flowMsgDesc := flowsFD.Message()
	for _, f := range s.st.ListFlows() {
		fm := dynamicpb.NewMessage(flowMsgDesc)
		setStr(fm, "id", f.ID)
		l4 := int32(0)
		switch f.L4 {
		case model.TCP:
			l4 = 1
		case model.UDP:
			l4 = 2
		}
		setEnum(fm, "l4", l4)
		setStr(fm, "src_ip", f.SrcIP)
		setUint(fm, "src_port", uint64(f.SrcPort))
		setStr(fm, "dst_ip", f.DstIP)
		setUint(fm, "dst_port", uint64(f.DstPort))
		setUint(fm, "bytes", f.Bytes)
		setUint(fm, "packets", f.Packets)
		setBool(fm, "closed", f.Closed)
		list.Append(protoreflect.ValueOfMessage(fm))
	}
	out.Set(flowsFD, protoreflect.ValueOfList(list))
	return out, nil
}

func (s *Server) streamEvents(stream grpc.ServerStream, md protoreflect.MethodDescriptor) error {
	ch, unsub := s.st.Subscribe(512)
	defer unsub()
	evDesc := md.Output()
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			m := dynamicpb.NewMessage(evDesc)
			setUint(m, "id", ev.ID)
			setStr(m, "source", string(ev.Source))
			setStr(m, "corr_id", ev.CorrID)
			setStr(m, "kind", ev.Kind)
			setTimestamp(m, "ts", ev.TS)
			if ev.Data != nil {
				if b, err := json.Marshal(ev.Data); err == nil {
					setBytes(m, "data_json", b)
				}
			}
			if err := stream.SendMsg(m); err != nil {
				return err
			}
		}
	}
}

func (s *Server) memOpen(in, out *dynamicpb.Message) (any, error) {
	if !s.scanner.Available() {
		return nil, status.Error(codes.Unimplemented, "memscan engine not built in (rebuild with -tags memscan_ffi)")
	}
	pid := uint32(getUint(in, "pid"))
	sess, err := s.scanner.Open(pid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open pid %d: %v", pid, err)
	}
	s.mu.Lock()
	s.memSeq++
	id := fmt.Sprintf("gsess-%d", s.memSeq)
	s.memSess[id] = sess
	s.mu.Unlock()
	setStr(out, "session", id)
	return out, nil
}

func (s *Server) session(id string) (memscan.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.memSess[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session %s not found", id)
	}
	return sess, nil
}

func (s *Server) memFirstScan(in, out *dynamicpb.Message) (any, error) {
	sess, err := s.session(getStr(in, "session"))
	if err != nil {
		return nil, err
	}
	hits, err := sess.FirstScan(memscan.ValueType(getEnum(in, "type")), getBytes(in, "value"))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "first scan: %v", err)
	}
	setInt(out, "hits", int64(hits))
	return out, nil
}

func (s *Server) memNextScan(in, out *dynamicpb.Message) (any, error) {
	sess, err := s.session(getStr(in, "session"))
	if err != nil {
		return nil, err
	}
	hits, err := sess.NextScan(memscan.Op(getEnum(in, "op")), getBytes(in, "value"))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "next scan: %v", err)
	}
	setInt(out, "hits", int64(hits))
	return out, nil
}

func (s *Server) memAOBScan(in, out *dynamicpb.Message) (any, error) {
	sess, err := s.session(getStr(in, "session"))
	if err != nil {
		return nil, err
	}
	hits, err := sess.AOBScan(getStr(in, "pattern"))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "aob scan: %v", err)
	}
	setInt(out, "hits", int64(hits))
	return out, nil
}

func (s *Server) memResults(in, out *dynamicpb.Message) (any, error) {
	sess, err := s.session(getStr(in, "session"))
	if err != nil {
		return nil, err
	}
	addrs, err := sess.Results(int(getUint(in, "max")))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "results: %v", err)
	}
	fd := out.Descriptor().Fields().ByName("addrs")
	list := out.NewField(fd).List()
	for _, a := range addrs {
		list.Append(protoreflect.ValueOfUint64(a))
	}
	out.Set(fd, protoreflect.ValueOfList(list))
	return out, nil
}

func (s *Server) memClose(in, out *dynamicpb.Message) (any, error) {
	id := getStr(in, "session")
	s.mu.Lock()
	sess, ok := s.memSess[id]
	if ok {
		delete(s.memSess, id)
	}
	s.mu.Unlock()
	if ok {
		_ = sess.Close()
	}
	return out, nil
}
