package inline

// Stateful TCP sequence/ACK fix-up for variable-length rewrites.
//
// When a rule changes the byte length of a TCP segment's payload, every later
// segment in that direction carries sequence numbers the sender computed from
// the *original* byte counts, and the peer's ACKs refer to the *modified* byte
// counts it actually received. Left alone the stream desyncs. This tracker sits
// in the engine, keyed by connection 4-tuple, and:
//
//   - rewrites the SEQ of each forward segment by the cumulative byte delta
//     injected before it, and
//   - rewrites the ACK of each reverse segment from the modified byte space back
//     into the original space the other endpoint expects,
//
// then recomputes the TCP checksum. It is correct for in-order delivery and
// idempotent across retransmissions (a segment seen twice maps identically).
// Aggressive reordering and the byte offsets inside SACK option blocks are not
// rewritten (documented limitation); the common in-order case now stays in sync.

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10

	maxTrackedConns = 8192
	maxCheckpoints  = 4096
)

// tcpCheckpointks, in modified-space byte offset (relative to the ISN), the
// end of a forward segment and the cumulative delta applied through it. The
// reverse direction maps an ACK back to original space by subtracting the cum of
// the latest checkpoint at or before the ACK offset.
type tcpCheckpoint struct {
	modEnd int64
	cum    int64
}

type tcpDirState struct {
	isn      uint32
	haveISN  bool
	accDelta int64            // running cumulative delta applied to this direction
	applied  map[uint32]int64 // origSeq -> deltaBefore (retransmit idempotency)
	cps      []tcpCheckpoint  // ascending by modEnd
	cpFloor  int64            // cum carried for checkpoints pruned off the front
}

type tcpConnState struct {
	dirs     [2]*tcpDirState
	lastSeen time.Time
}

func (c *tcpConnState) dir(i int) *tcpDirState {
	if c.dirs[i] == nil {
		c.dirs[i] = &tcpDirState{applied: map[uint32]int64{}}
	}
	return c.dirs[i]
}

// TCPFixer tracks connections to keep TCP sequence/ACK numbers consistent after
// variable-length payload rewrites.
type TCPFixer struct {
	mu    sync.Mutex
	conns map[string]*tcpConnState
}

// NewTCPFixer returns an empty fixer.
func NewTCPFixer() *TCPFixer { return &TCPFixer{conns: map[string]*tcpConnState{}} }

// fixTCP adjusts the SEQ/ACK of a TCP/IP packet (and its checksum) for a tracked
// connection. info is the parsed transport location; thisDelta is the byte
// change the rules applied to this packet's payload (0 if unchanged). It returns
// true if it modified the packet. Packets it cannot parse are left untouched.
func (f *TCPFixer) fixTCP(pkt []byte, info L4Info, thisDelta int) bool {
	if info.Proto != "tcp" {
		return false
	}
	off := info.L4Off
	if len(pkt) < off+20 {
		return false
	}
	srcIP, dstIP, ok := ipPair(pkt, info.IPVer)
	if !ok {
		return false
	}
	seq := binary.BigEndian.Uint32(pkt[off+4 : off+8])
	ack := binary.BigEndian.Uint32(pkt[off+8 : off+12])
	flags := pkt[off+13]
	hdrLen := int(pkt[off+12]>>4) * 4
	payloadOff := off + hdrLen
	if hdrLen < 20 || payloadOff > len(pkt) {
		return false
	}

	key, di := connKeyDir(srcIP, dstIP, uint16(info.SrcPort), uint16(info.DstPort))

	f.mu.Lock()
	defer f.mu.Unlock()

	c := f.conns[key]
	if c == nil {
		if flags&tcpFlagRST != 0 {
			return false
		}
		f.gcLocked()
		c = &tcpConnState{}
		f.conns[key] = c
	}
	c.lastSeen = time.Now()
	fwd := c.dir(di)
	rev := c.dir(1 - di)

	if !fwd.haveISN {
		fwd.isn = seq
		fwd.haveISN = true
	}

	newPayloadLen := len(pkt) - payloadOff

	// --- forward SEQ rewrite ---
	// deltaBefore is the cumulative delta injected ahead of this segment's first
	// byte. Only data-carrying segments are tracked for retransmit idempotency;
	// pure ACKs (no payload) share the next data segment's SEQ and must not be
	// mistaken for it.
	deltaBefore := fwd.accDelta
	isRetransmit := false
	if newPayloadLen > 0 {
		if d, ok := fwd.applied[seq]; ok {
			deltaBefore = d
			isRetransmit = true
		}
	}
	if deltaBefore != 0 {
		binary.BigEndian.PutUint32(pkt[off+4:off+8], seq+uint32(deltaBefore))
	}

	// Record a checkpoint (for reverse ACK mapping) and advance the cumulative
	// delta — once per new data segment.
	if newPayloadLen > 0 && !isRetransmit {
		origOff := int64(int32(seq - fwd.isn))
		modEnd := origOff + deltaBefore + int64(newPayloadLen)
		fwd.cps = append(fwd.cps, tcpCheckpoint{modEnd: modEnd, cum: deltaBefore + int64(thisDelta)})
		if len(fwd.cps) > maxCheckpoints {
			fwd.cpFloor = fwd.cps[0].cum
			fwd.cps = fwd.cps[1:]
		}
		fwd.applied[seq] = deltaBefore
		fwd.accDelta = deltaBefore + int64(thisDelta)
		if len(fwd.applied) > maxCheckpoints {
			fwd.applied = map[uint32]int64{seq: deltaBefore}
		}
	}

	// --- reverse ACK rewrite ---
	modifiedAck := false
	if flags&tcpFlagACK != 0 && rev.haveISN {
		ackOff := int64(int32(ack - rev.isn))
		if cum := rev.cumAt(ackOff); cum != 0 {
			binary.BigEndian.PutUint32(pkt[off+8:off+12], ack-uint32(cum))
			modifiedAck = true
			rev.pruneBelow(ackOff)
		}
	}

	if flags&(tcpFlagRST) != 0 {
		delete(f.conns, key)
	}

	changed := deltaBefore != 0 || modifiedAck || thisDelta != 0
	if changed {
		fixTCPChecksum(pkt, info)
	}
	return changed
}

// cumAt returns the cumulative delta applied to bytes at modified offset off.
func (d *tcpDirState) cumAt(off int64) int64 {
	cum := d.cpFloor
	for _, cp := range d.cps {
		if cp.modEnd <= off {
			cum = cp.cum
		} else {
			break
		}
	}
	return cum
}

// pruneBelow drops checkpoints fully acknowledged below off (keeping their cum
// as the floor), since ACKs only advance.
func (d *tcpDirState) pruneBelow(off int64) {
	n := 0
	for n < len(d.cps) && d.cps[n].modEnd <= off {
		n++
	}
	if n > 1 {
		d.cpFloor = d.cps[n-1].cum
		d.cps = d.cps[n-1:]
	}
}

func (f *TCPFixer) gcLocked() {
	if len(f.conns) < maxTrackedConns {
		return
	}
	// Evict the least-recently-seen quarter.
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(f.conns))
	for k, c := range f.conns {
		all = append(all, kv{k, c.lastSeen})
	}
	// Partial selection: drop anything older than the median-ish cutoff.
	cutoff := time.Now().Add(-30 * time.Second)
	for _, e := range all {
		if e.t.Before(cutoff) {
			delete(f.conns, e.k)
		}
	}
	// If still over budget, hard-trim.
	for k := range f.conns {
		if len(f.conns) < maxTrackedConns {
			break
		}
		delete(f.conns, k)
	}
}

// ipPair returns the source/destination IP (as map-key strings) of a raw IP
// packet.
func ipPair(pkt []byte, ipVer int) (src, dst string, ok bool) {
	switch ipVer {
	case 4:
		if len(pkt) < 20 {
			return "", "", false
		}
		return net.IP(pkt[12:16]).String(), net.IP(pkt[16:20]).String(), true
	case 6:
		if len(pkt) < 40 {
			return "", "", false
		}
		return net.IP(pkt[8:24]).String(), net.IP(pkt[24:40]).String(), true
	}
	return "", "", false
}

// connKeyDir returns a canonical connection key and a direction index (0/1) so
// both flows of a connection share one state object.
func connKeyDir(srcIP, dstIP string, sp, dp uint16) (string, int) {
	a := srcIP + ":" + strconv.Itoa(int(sp))
	b := dstIP + ":" + strconv.Itoa(int(dp))
	if a <= b {
		return a + "|" + b, 0
	}
	return b + "|" + a, 1
}

// fixTCPChecksum recomputes the TCP checksum over the pseudo-header + segment.
func fixTCPChecksum(pkt []byte, info L4Info) {
	off := info.L4Off
	if off+18 > len(pkt) {
		return
	}
	tcpLen := len(pkt) - off
	pkt[off+16], pkt[off+17] = 0, 0

	var sum uint32
	switch info.IPVer {
	case 4:
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
		}
	case 6:
		for i := 8; i < 40; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
		}
	default:
		return
	}
	sum += uint32(ipProtoTCP)
	sum += uint32(tcpLen)
	for i := off; i+1 < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[off+16:off+18], ^uint16(sum))
}
