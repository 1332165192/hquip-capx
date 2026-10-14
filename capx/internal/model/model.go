// Package model defines the unified data model shared across capx capture
// sources (sniffer, proxy, hook, memscan). A common Event envelope plus a
// correlation id (CorrID) lets the correlate engine line up the same logical
// session across layers: memory buffer <-> socket <-> TCP/UDP flow <-> HTTP tx.
package model

import (
	"fmt"
	"strconv"
	"time"
)

// Source identifies which capture layer produced an event.
type Source string

const (
	SourceSniffer Source = "sniffer" // L3/L4 raw packets
	SourceProxy   Source = "proxy"   // L7 HTTP/S MITM
	SourceHook    Source = "hook"    // in-process function hooks (Frida)
	SourceMem     Source = "mem"     // CE-style memory scanning
	SourceDNSLog  Source = "dnslog"  // out-of-band DNS/HTTP callbacks (DNSLog platform)
)

// Event is the common envelope streamed to clients over SSE.
type Event struct {
	Replayed          bool      `json:"replayed,omitempty"`
	HistoryGeneration uint64    `json:"history_generation"`
	ID                uint64    `json:"id"`
	TS                time.Time `json:"ts"`
	Source            Source    `json:"source"`
	CorrID            string    `json:"corr_id,omitempty"`
	Kind              string    `json:"kind"`           // e.g. "flow_new", "packet", "http_tx", "mem_hit"
	Data              any       `json:"data,omitempty"` // one of the payloads below
}

// L4 is the transport protocol of a flow.
type L4 string

const (
	TCP L4 = "tcp"
	UDP L4 = "udp"
)

// Flow is a transport-layer conversation (one TCP connection or UDP 5-tuple).
type Flow struct {
	ID      string    `json:"id"`
	L4      L4        `json:"l4"`
	SrcIP   string    `json:"src_ip"`
	SrcPort uint16    `json:"src_port"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Bytes   uint64    `json:"bytes"`
	Packets uint64    `json:"packets"`
	Started time.Time `json:"started"`
	Updated time.Time `json:"updated"`
	Closed  bool      `json:"closed"`

	// Reassembled application-layer payload (populated by TCP reassembly).
	// ClientPayload holds data sent by the connection initiator (src->dst);
	// ServerPayload holds data from the responder (dst->src).
	ClientPayload []byte `json:"client_payload,omitempty"`
	ServerPayload []byte `json:"server_payload,omitempty"`
}

// CanonicalFlowID returns a direction-independent identifier for a transport
// conversation. The returned endpoint fields are ordered consistently so packets
// from either direction land on the same Flow.
func CanonicalFlowID(l4 L4, srcIP string, srcPort uint16, dstIP string, dstPort uint16) (id string, canonSrcIP string, canonSrcPort uint16, canonDstIP string, canonDstPort uint16, reversed bool) {
	srcPortS := strconv.FormatUint(uint64(srcPort), 10)
	dstPortS := strconv.FormatUint(uint64(dstPort), 10)
	id, reversed = CanonicalFlowIDStringPorts(l4, srcIP, srcPortS, dstIP, dstPortS)
	if reversed {
		return id, dstIP, dstPort, srcIP, srcPort, true
	}
	return id, srcIP, srcPort, dstIP, dstPort, false
}

// CanonicalFlowIDStringPorts is the string-port variant used by TCP
// reassembly, where gopacket exposes transport flow endpoints as strings.
func CanonicalFlowIDStringPorts(l4 L4, srcIP, srcPort, dstIP, dstPort string) (id string, reversed bool) {
	if endpointLess(dstIP, dstPort, srcIP, srcPort) {
		srcIP, srcPort, dstIP, dstPort = dstIP, dstPort, srcIP, srcPort
		reversed = true
	}
	return fmt.Sprintf("%s|%s:%s>%s:%s", l4, srcIP, srcPort, dstIP, dstPort), reversed
}

func endpointLess(ipA, portA, ipB, portB string) bool {
	if ipA != ipB {
		return ipA < ipB
	}
	a, errA := strconv.ParseUint(portA, 10, 16)
	b, errB := strconv.ParseUint(portB, 10, 16)
	if errA == nil && errB == nil && a != b {
		return a < b
	}
	return portA < portB
}

// Direction of a packet relative to the captured host.
type Direction string

const (
	DirOut Direction = "out"
	DirIn  Direction = "in"
)

// Packet is a single captured frame summary (raw bytes optional / truncated).
type Packet struct {
	CaptureID string    `json:"capture_id,omitempty"` // owning capture session
	FlowID    string    `json:"flow_id"`
	TS        time.Time `json:"ts"`
	Dir       Direction `json:"dir"`
	Length    int       `json:"length"`
	Layers    []string  `json:"layers,omitempty"` // decoded layer names, outer->inner
	Raw       []byte    `json:"raw,omitempty"`    // optional, may be truncated
}

// HTTPTx is one request/response captured (and possibly decrypted) at L7.
// Scheme distinguishes the Burp-style "HTTP history" vs "HTTPS history" views;
// ReqRaw/RespRaw hold the full wire text shown in the request/response panes.
type HTTPTx struct {
	ID       uint64            `json:"id"`
	FlowID   string            `json:"flow_id"`
	TS       time.Time         `json:"ts"`
	LastSeen time.Time         `json:"last_seen,omitempty"`
	Scheme   string            `json:"scheme"` // "http" | "https"
	Method   string            `json:"method"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	URL      string            `json:"url"`
	Status   int               `json:"status"`
	RespLen  int               `json:"resp_len"`
	Proto    string            `json:"proto,omitempty"` // negotiated response proto, e.g. "HTTP/2.0"
	MIME     string            `json:"mime,omitempty"`
	ReqHdr   map[string]string `json:"req_hdr,omitempty"`
	RespHdr  map[string]string `json:"resp_hdr,omitempty"`
	ReqRaw   string            `json:"req_raw,omitempty"`  // full request text (start line + headers + body)
	RespRaw  string            `json:"resp_raw,omitempty"` // full response text
	// Paged disk reads can omit raw bodies while retaining lazy-detail metadata.
	ReqRawLen  int  `json:"req_raw_len,omitempty"`
	RespRawLen int  `json:"resp_raw_len,omitempty"`
	Decrypted  bool `json:"decrypted"`
	RepeatCnt  int  `json:"repeat_count,omitempty"` // collapsed identical transactions, including the first one.
	// ServerAddr is the upstream server's resolved ip:port for this tx (from the
	// proxy's dial). It lets the correlation engine join an HTTP tx to the
	// sniffer flow and in-process hook events that share the same endpoint.
	ServerAddr string `json:"server_addr,omitempty"`
	// Transport-owned provenance; these values are never read from HTTP headers.
	// A VPN peer identifies a capture channel, not a process or Android App.
	CaptureMode string `json:"capture_mode,omitempty"`
	ClientAddr  string `json:"client_addr,omitempty"`
	CapturePeer string `json:"capture_peer,omitempty"`
	// InScope is false when the transaction was recorded while Target scope
	// excluded it. Out-of-scope txs still appear in history so they are not
	// silently dropped.
	InScope bool `json:"in_scope"`
	// OutOfScope is the inverse of InScope; zero value means in-scope so
	// older records and tests stay visible in the default history.
	OutOfScope bool `json:"out_of_scope,omitempty"`
	// BodyTruncated is true when ReqRaw/RespRaw was clipped to the capture cap.
	BodyTruncated bool `json:"body_truncated,omitempty"`
}

// WSDir is the direction of a WebSocket frame relative to the client.
type WSDir string

const (
	WSSend WSDir = "send" // client -> server
	WSRecv WSDir = "recv" // server -> client
)

// WSMessage is a single WebSocket frame captured on an upgraded connection.
type WSMessage struct {
	ID     uint64    `json:"id"`
	ConnID string    `json:"conn_id,omitempty"`
	FlowID string    `json:"flow_id"`
	TS     time.Time `json:"ts"`
	URL    string    `json:"url"`    // ws:// or wss:// endpoint
	Dir    WSDir     `json:"dir"`    // send | recv
	Opcode string    `json:"opcode"` // "text" | "binary"
	Length int       `json:"length"`
	Data   string    `json:"data,omitempty"` // text payload (or hex/base64 for binary)
}

// HookEvent is a single in-process function hook observation (Frida). The
// flagship use is dumping plaintext from TLS write/read functions (SSL_write /
// SSL_read on OpenSSL, EncryptMessage / DecryptMessage on Windows SChannel)
// *before* it is encrypted on the wire, defeating cert pinning.
type HookEvent struct {
	PID  uint32    `json:"pid"`
	TS   time.Time `json:"ts"`
	Func string    `json:"func"`           // hooked function, e.g. "SSL_write"
	Dir  string    `json:"dir,omitempty"`  // "send" | "recv"
	Len  int       `json:"len"`            // plaintext length in bytes
	Peer string    `json:"peer,omitempty"` // best-effort remote endpoint
	Data string    `json:"data,omitempty"` // plaintext preview (utf-8 or hex)
}

// MemHit is a single memory-scan result.
type MemHit struct {
	PID    uint32    `json:"pid"`
	Addr   uint64    `json:"addr"`
	Type   string    `json:"type"`  // i32/i64/f32/f64/u32/u64/aob
	Value  string    `json:"value"` // textual rendering of bytes at addr
	TS     time.Time `json:"ts,omitempty"`
	HTTPID uint64    `json:"http_id,omitempty"` // matched HTTP history id, if any
	Host   string    `json:"host,omitempty"`    // host from the matched HTTP tx
}

// CaptureMode controls how aggressively a capture interacts with traffic.
type CaptureMode string

const (
	// ModePassive only observes (read-only sniffing / proxy pass-through).
	ModePassive CaptureMode = "passive"
	// ModeActive permits inline modification (match&replace, inject). Requires
	// explicit policy opt-in.
	ModeActive CaptureMode = "active"
)

// Capture is a running or finished capture session descriptor.
type Capture struct {
	ID        string      `json:"id"`
	Iface     string      `json:"iface"`
	Filter    string      `json:"filter"` // BPF filter, e.g. "tcp or udp"
	Mode      CaptureMode `json:"mode"`
	Started   time.Time   `json:"started"`
	Stopped   *time.Time  `json:"stopped,omitempty"`
	Running   bool        `json:"running"`
	PacketCnt uint64      `json:"packet_cnt"`
	FlowCnt   uint64      `json:"flow_cnt"`
	Backend   string      `json:"backend"`   // e.g. "gopacket", "stub"
	LinkType  int         `json:"link_type"` // libpcap link type (1=Ethernet, 101=raw IP)
}
