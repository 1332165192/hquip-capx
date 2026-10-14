//go:build grpc

package grpcserver

// protoSrc is the capx gRPC service definition, parsed at runtime (capx ships
// no protoc-generated stub). It mirrors capx/proto/capture.proto; keep the two
// in sync.
const protoSrc = `
syntax = "proto3";
package capx.v1;
option go_package = "github.com/hquip/capx/gen/capxv1";
import "google/protobuf/timestamp.proto";

enum L4 {
  L4_UNSPECIFIED = 0;
  L4_TCP = 1;
  L4_UDP = 2;
}

enum CaptureMode {
  MODE_PASSIVE = 0;
  MODE_ACTIVE = 1;
}

message StartCaptureRequest {
  string iface = 1;
  string filter = 2;
  CaptureMode mode = 3;
  int32 max_raw = 4;
}

message Capture {
  string id = 1;
  string iface = 2;
  string filter = 3;
  CaptureMode mode = 4;
  google.protobuf.Timestamp started = 5;
  bool running = 6;
  uint64 packet_cnt = 7;
  uint64 flow_cnt = 8;
  string backend = 9;
}

message Flow {
  string id = 1;
  L4 l4 = 2;
  string src_ip = 3;
  uint32 src_port = 4;
  string dst_ip = 5;
  uint32 dst_port = 6;
  uint64 bytes = 7;
  uint64 packets = 8;
  bool closed = 9;
}

message Packet {
  string flow_id = 1;
  google.protobuf.Timestamp ts = 2;
  string dir = 3;
  int32 length = 4;
  repeated string layers = 5;
  bytes raw = 6;
}

message Event {
  uint64 id = 1;
  google.protobuf.Timestamp ts = 2;
  string source = 3;
  string corr_id = 4;
  string kind = 5;
  bytes data_json = 6;
}

message StopCaptureRequest { string id = 1; }
message StreamRequest { string capture_id = 1; }
message ListFlowsRequest { string capture_id = 1; }
message ListFlowsResponse { repeated Flow flows = 1; }
message Empty {}

enum ValueType {
  VT_I32 = 0;
  VT_I64 = 1;
  VT_F32 = 2;
  VT_F64 = 3;
  VT_U32 = 4;
  VT_U64 = 5;
}

enum ScanOp {
  OP_EQ = 0;
  OP_CHANGED = 1;
  OP_UNCHANGED = 2;
  OP_INCREASED = 3;
  OP_DECREASED = 4;
  OP_GT = 5;
  OP_LT = 6;
}

message MemOpenRequest { uint32 pid = 1; }
message MemSession { string session = 1; }
message FirstScanRequest { string session = 1; ValueType type = 2; bytes value = 3; }
message NextScanRequest { string session = 1; ScanOp op = 2; bytes value = 3; }
message AOBScanRequest { string session = 1; string pattern = 2; }
message ScanResult { int64 hits = 1; }
message ResultsRequest { string session = 1; uint32 max = 2; }
message ResultsResponse { repeated uint64 addrs = 1; }

service Capx {
  rpc StartCapture(StartCaptureRequest) returns (Capture);
  rpc StopCapture(StopCaptureRequest) returns (Empty);
  rpc StreamEvents(StreamRequest) returns (stream Event);
  rpc ListFlows(ListFlowsRequest) returns (ListFlowsResponse);

  rpc MemOpen(MemOpenRequest) returns (MemSession);
  rpc MemFirstScan(FirstScanRequest) returns (ScanResult);
  rpc MemNextScan(NextScanRequest) returns (ScanResult);
  rpc MemAOBScan(AOBScanRequest) returns (ScanResult);
  rpc MemResults(ResultsRequest) returns (ResultsResponse);
  rpc MemClose(MemSession) returns (Empty);
}
`
