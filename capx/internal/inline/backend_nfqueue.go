//go:build linux && nfqueue

// NFQUEUE backend (M6). Requires libnetfilter_queue-dev and capx running as
// root. The iptables rule that feeds packets into the queue must be set up
// externally (or by the caller before Start); this backend only handles the
// userspace side via the /proc/net/netfilter/nfnetlink_queue interface through
// raw syscalls (no cgo, no external C library at runtime).
//
// Build with:
//
//	go build -tags "nfqueue" ./cmd/captured
//
// The actual match/replace decision is made by the platform-independent Engine
// (engine.go); this file is only the kernel I/O plumbing: it receives packets
// from the NFQUEUE, hands each packet to the engine, sets the verdict to DROP
// or ACCEPT (with possibly rewritten payload), and publishes events.
package inline

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

// Netlink / NFQUEUE constants (from linux/netfilter/nfnetlink.h and
// linux/netfilter/nfnetlink_queue.h). We define only the subset we need
// to avoid any cgo or external dependency.
const (
	nfnlSubsysQueue = 3

	nfqnlMsgPacket       = 0
	nfqnlMsgVerdict      = 1
	nfqnlMsgConfig       = 2
	nfqnlMsgVerdictBatch = 3 // unused, listed for reference

	nfqaCfgCmd         = 1
	nfqaCfgParams      = 2
	nfqaCfgQueueMaxLen = 3

	nfqaPacketHdr = 1
	nfqaPayload   = 10

	nfqnlCfgCmdBind   = 1
	nfqnlCfgCmdUnbind = 2

	nfqnlCopyPacket = 2

	nfAccept = 1
	nfDrop   = 0

	nfqueueNum = 0 // default queue number; callers set up iptables to match
)

type nfqueueBackend struct {
	mu       sync.Mutex
	fd       int
	open     bool
	ipt      [][]string
	iptRules bool
	redir    [][]string
}

func newBackend() backend {
	return &nfqueueBackend{fd: -1}
}

func (b *nfqueueBackend) name() string { return "nfqueue" }

func (b *nfqueueBackend) available() bool {
	// Probe: can we open a netlink socket?
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 12 /* NETLINK_NETFILTER */)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

func (b *nfqueueBackend) run(ctx context.Context, filter string, eng *Engine, st *store.Store) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 12)
	if err != nil {
		return fmt.Errorf("nfqueue: socket: %w", err)
	}

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("nfqueue: bind: %w", err)
	}

	b.mu.Lock()
	b.fd = fd
	b.open = true
	b.mu.Unlock()

	// Unbind any existing handler, then bind our queue.
	if err := b.sendCfgCmd(fd, nfqnlCfgCmdUnbind, nfqueueNum); err != nil {
		// Ignore unbind error — may not be bound.
	}
	if err := b.sendCfgCmd(fd, nfqnlCfgCmdBind, nfqueueNum); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("nfqueue: bind queue: %w", err)
	}
	if err := b.sendCfgParams(fd, nfqueueNum, nfqnlCopyPacket, 65535); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("nfqueue: set params: %w", err)
	}

	// Auto-manage the iptables rules that feed packets into our queue so callers
	// don't have to set them up by hand. Best-effort: if iptables is missing or
	// we lack privilege, we keep running (a caller may have rules already).
	b.setupIptables(filter, st)

	go func() {
		<-ctx.Done()
		b.teardownIptables(st)
		b.mu.Lock()
		if b.open {
			syscall.Close(b.fd)
			b.open = false
		}
		b.mu.Unlock()
	}()

	buf := make([]byte, 65535+512) // room for nlmsg + nfq headers + full packet
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("nfqueue: recv: %w", err)
		}
		if n < 16 {
			continue
		}

		packetID, payload := b.parseNfqPacket(buf[:n])
		if payload == nil {
			continue
		}

		proto, sport, dport := parseL4(payload)
		out, drop, hit, modified := eng.Apply(payload, proto, sport, dport)

		if drop {
			if hit {
				st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_drop",
					Data: map[string]string{"proto": proto, "len": fmt.Sprint(len(payload))}})
			}
			b.sendVerdict(fd, packetID, nfDrop, nil)
			continue
		}

		if modified {
			fixIPChecksum(out)
			fixL4Checksum(out)
			if hit {
				st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_replace",
					Data: map[string]string{"proto": proto, "len": fmt.Sprint(len(out))}})
			}
			b.sendVerdict(fd, packetID, nfAccept, out)
		} else {
			b.sendVerdict(fd, packetID, nfAccept, nil)
		}
	}
}

// setupIptables inserts NFQUEUE-target rules derived from a simple filter so the
// kernel diverts matching packets to our queue. The filter understands tokens
// like "tcp", "udp", "port 443", "tcp port 8080"; empty means all TCP+UDP. Rules
// are added to both OUTPUT and INPUT (and the v6 chains) and recorded for clean
// removal on stop.
func (b *nfqueueBackend) setupIptables(filter string, st *store.Store) {
	if _, err := exec.LookPath("iptables"); err != nil {
		return // no iptables; assume the caller pre-provisioned the queue
	}
	specs := iptablesMatchSpecs(filter)
	queueArgs := []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(nfqueueNum)}

	var added [][]string
	for _, bin := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"OUTPUT", "INPUT"} {
			for _, m := range specs {
				rule := append([]string{"-I", chain}, m...)
				rule = append(rule, queueArgs...)
				if err := runIptables(bin, rule); err != nil {
					continue
				}
				// Record the delete form (same args, -D instead of -I).
				del := append([]string{bin, "-D", chain}, m...)
				del = append(del, queueArgs...)
				added = append(added, del)
			}
		}
	}
	b.mu.Lock()
	b.ipt = added
	b.iptRules = len(added) > 0
	b.mu.Unlock()
	if len(added) > 0 && st != nil {
		st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_iptables",
			Data: map[string]string{"action": "insert", "count": strconv.Itoa(len(added))}})
	}
}

func (b *nfqueueBackend) teardownIptables(st *store.Store) {
	b.mu.Lock()
	rules := b.ipt
	b.ipt = nil
	b.iptRules = false
	b.mu.Unlock()
	for _, r := range rules {
		if len(r) < 2 {
			continue
		}
		_ = runIptables(r[0], r[1:])
	}
	if len(rules) > 0 && st != nil {
		st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_iptables",
			Data: map[string]string{"action": "delete", "count": strconv.Itoa(len(rules))}})
	}
}

// iptablesMatchSpecs turns the filter into one or more iptables match fragments.
func iptablesMatchSpecs(filter string) [][]string {
	f := strings.ToLower(strings.TrimSpace(filter))
	proto := ""
	port := ""
	toks := strings.Fields(f)
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "tcp", "udp":
			proto = toks[i]
		case "port", "dport", "sport":
			if i+1 < len(toks) {
				port = toks[i+1]
				i++
			}
		default:
			if _, err := strconv.Atoi(toks[i]); err == nil && port == "" {
				port = toks[i]
			}
		}
	}
	protos := []string{proto}
	if proto == "" {
		protos = []string{"tcp", "udp"}
	}
	var specs [][]string
	for _, p := range protos {
		m := []string{"-p", p}
		if port != "" {
			// Match either direction's port via multiport.
			m = append(m, "-m", "multiport", "--ports", port)
		}
		specs = append(specs, m)
	}
	return specs
}

func runIptables(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *nfqueueBackend) send(pkt []byte, outbound bool) error {
	// Raw packet injection on Linux uses a raw socket.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("nfqueue send: raw socket: %w", err)
	}
	defer syscall.Close(fd)

	if len(pkt) < 20 {
		return fmt.Errorf("nfqueue send: packet too short")
	}
	// Extract destination IP from IP header for sendto.
	var dstIP [4]byte
	copy(dstIP[:], pkt[16:20])
	sa := &syscall.SockaddrInet4{Addr: dstIP}
	return syscall.Sendto(fd, pkt, 0, sa)
}

func (b *nfqueueBackend) runRedirect(ctx context.Context, filter string, redir *Redirector, st *store.Store) error {
	host := "127.0.0.1"
	port := 18081
	if redir != nil && redir.listenPort != 0 {
		port = int(redir.listenPort)
	}
	uid := "0"
	if u := os.Getuid(); u >= 0 {
		uid = strconv.Itoa(u)
	}
	dports := "80,443"
	if redir != nil && len(redir.httpPorts) > 0 {
		var ps []string
		for p := range redir.httpPorts {
			ps = append(ps, strconv.Itoa(int(p)))
		}
		sort.Strings(ps)
		dports = strings.Join(ps, ",")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found; cannot redirect :%s to %s:%d", dports, host, port)
	}
	udpOnly := redir != nil && redir.udpOnly
	type iptRule struct {
		bin  string
		rule []string
	}
	var specs []iptRule
	if !udpOnly {
		specs = append(specs,
			iptRule{"iptables", []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-m", "owner", "--uid-owner", uid, "-j", "RETURN"}},
			iptRule{"iptables", []string{"-t", "nat", "-I", "OUTPUT", "2", "-p", "tcp", "-m", "multiport", "--dports", dports, "!", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)}},
			iptRule{"ip6tables", []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-m", "owner", "--uid-owner", uid, "-j", "RETURN"}},
			iptRule{"ip6tables", []string{"-t", "nat", "-I", "OUTPUT", "2", "-p", "tcp", "-m", "multiport", "--dports", dports, "!", "-d", "::1", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)}},
		)
	}
	specs = append(specs,
		iptRule{"iptables", []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "-m", "multiport", "--dports", dports, "!", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)}},
		iptRule{"ip6tables", []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "-m", "multiport", "--dports", dports, "!", "-d", "::1", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)}},
	)
	var added [][]string
	var firstErr error
	for _, spec := range specs {
		if _, err := exec.LookPath(spec.bin); err != nil {
			if spec.bin == "iptables" && firstErr == nil {
				firstErr = fmt.Errorf("%s not found; cannot redirect :%s to %s:%d", spec.bin, dports, host, port)
			}
			continue
		}
		if err := runIptables(spec.bin, spec.rule); err != nil {
			if spec.bin == "iptables" && firstErr == nil {
				firstErr = err
			}
			continue // ip6tables may be missing; IPv4 still works
		}
		del := append([]string{spec.bin, "-t", "nat", "-D"}, spec.rule[3:]...)
		added = append(added, del)
	}
	if len(added) == 0 {
		if firstErr != nil {
			return firstErr
		}
		return fmt.Errorf("no iptables/ip6tables REDIRECT rules installed")
	}
	b.mu.Lock()
	b.redir = added
	b.mu.Unlock()
	if st != nil {
		st.Publish(model.Event{Source: model.SourceProxy, Kind: "transparent_redirect",
			Data: map[string]string{"addr": host + ":" + strconv.Itoa(port), "backend": "iptables"}})
	}
	<-ctx.Done()
	b.mu.Lock()
	rules := b.redir
	b.redir = nil
	b.mu.Unlock()
	for _, r := range rules {
		if len(r) >= 2 {
			_ = runIptables(r[0], r[1:])
		}
	}
	return ctx.Err()
}

// --- netlink message construction helpers ---

func nlmsgAlign(l int) int { return (l + 3) & ^3 }
func nlaAlign(l int) int   { return (l + 3) & ^3 }

func (b *nfqueueBackend) sendCfgCmd(fd int, cmd uint8, queueNum uint16) error {
	// Build: nlmsghdr + nfgenmsg + nla(nfqa_cfg_cmd)
	const nfgenmsgLen = 4
	cmdPayload := []byte{cmd, 0, 0, 0} // pf = 0 (unused)
	nlaLen := 4 + len(cmdPayload)
	msgLen := 16 + nfgenmsgLen + nlaAlign(nlaLen)
	msg := make([]byte, msgLen)

	// nlmsghdr
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], uint16((nfnlSubsysQueue<<8)|nfqnlMsgConfig))
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], 0)  // seq
	binary.LittleEndian.PutUint32(msg[12:16], 0) // pid

	// nfgenmsg
	msg[16] = syscall.AF_UNSPEC
	msg[17] = 0 // version
	binary.BigEndian.PutUint16(msg[18:20], queueNum)

	// nla
	off := 20
	binary.LittleEndian.PutUint16(msg[off:off+2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(msg[off+2:off+4], nfqaCfgCmd)
	copy(msg[off+4:], cmdPayload)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}

func (b *nfqueueBackend) sendCfgParams(fd int, queueNum uint16, copyMode uint8, copyRange uint32) error {
	const nfgenmsgLen = 4
	paramPayload := make([]byte, 5)
	binary.BigEndian.PutUint32(paramPayload[0:4], copyRange)
	paramPayload[4] = copyMode
	nlaLen := 4 + len(paramPayload)
	msgLen := 16 + nfgenmsgLen + nlaAlign(nlaLen)
	msg := make([]byte, msgLen)

	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], uint16((nfnlSubsysQueue<<8)|nfqnlMsgConfig))
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	msg[16] = syscall.AF_UNSPEC
	msg[17] = 0
	binary.BigEndian.PutUint16(msg[18:20], queueNum)

	off := 20
	binary.LittleEndian.PutUint16(msg[off:off+2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(msg[off+2:off+4], nfqaCfgParams)
	copy(msg[off+4:], paramPayload)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}

func (b *nfqueueBackend) sendVerdict(fd int, packetID uint32, verdict uint32, modifiedPayload []byte) {
	const nfgenmsgLen = 4
	// verdict NLA: type=nfqa_verdict_hdr, value = verdict(u32) + id(u32)
	verdictPayload := make([]byte, 8)
	binary.BigEndian.PutUint32(verdictPayload[0:4], verdict)
	binary.BigEndian.PutUint32(verdictPayload[4:8], packetID)
	verdictNlaLen := 4 + 8

	payloadNlaLen := 0
	if modifiedPayload != nil {
		payloadNlaLen = nlaAlign(4 + len(modifiedPayload))
	}

	msgLen := 16 + nfgenmsgLen + nlaAlign(verdictNlaLen) + payloadNlaLen
	msg := make([]byte, msgLen)

	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], uint16((nfnlSubsysQueue<<8)|nfqnlMsgVerdict))
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	msg[16] = syscall.AF_UNSPEC
	msg[17] = 0
	binary.BigEndian.PutUint16(msg[18:20], 0)

	off := 20
	binary.LittleEndian.PutUint16(msg[off:off+2], uint16(verdictNlaLen))
	binary.LittleEndian.PutUint16(msg[off+2:off+4], 1) // NFQA_VERDICT_HDR
	copy(msg[off+4:off+12], verdictPayload)
	off += nlaAlign(verdictNlaLen)

	if modifiedPayload != nil {
		binary.LittleEndian.PutUint16(msg[off:off+2], uint16(4+len(modifiedPayload)))
		binary.LittleEndian.PutUint16(msg[off+2:off+4], nfqaPayload)
		copy(msg[off+4:], modifiedPayload)
	}

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	_ = syscall.Sendto(fd, msg, 0, sa)
}

// parseNfqPacket extracts the packet id and payload from a netlink message
// containing an NFQUEUE packet notification.
func (b *nfqueueBackend) parseNfqPacket(data []byte) (packetID uint32, payload []byte) {
	if len(data) < 20 {
		return 0, nil
	}
	// Skip nlmsghdr (16 bytes) + nfgenmsg (4 bytes) = 20 bytes to NLAs.
	off := 20
	for off+4 <= len(data) {
		nlaLen := int(binary.LittleEndian.Uint16(data[off : off+2]))
		nlaType := binary.LittleEndian.Uint16(data[off+2 : off+4])
		if nlaLen < 4 {
			break
		}
		valOff := off + 4
		valLen := nlaLen - 4
		if valOff+valLen > len(data) {
			break
		}
		switch nlaType {
		case nfqaPacketHdr:
			if valLen >= 7 {
				packetID = binary.BigEndian.Uint32(data[valOff : valOff+4])
			}
		case nfqaPayload:
			payload = make([]byte, valLen)
			copy(payload, data[valOff:valOff+valLen])
		}
		off += nlaAlign(nlaLen)
	}
	return packetID, payload
}

// fixIPChecksum recomputes the IPv4 header checksum after payload modification.
func fixIPChecksum(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	// Zero checksum field, recompute.
	pkt[10], pkt[11] = 0, 0
	var sum uint32
	for i := 0; i+1 < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
}

// fixL4Checksum recomputes the TCP or UDP checksum after payload modification.
func fixL4Checksum(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	l4 := pkt[ihl:totalLen]
	if len(l4) < 8 {
		return
	}

	// Pseudo-header checksum: src_ip + dst_ip + zero + proto + l4_len
	var pseudo uint32
	for i := 12; i < 20; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	pseudo += uint32(proto)
	pseudo += uint32(len(l4))

	var csumOff int
	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return
		}
		csumOff = 16
	case 17: // UDP
		csumOff = 6
	default:
		return
	}

	// Zero checksum, compute over L4 data.
	l4[csumOff], l4[csumOff+1] = 0, 0
	sum := pseudo
	for i := 0; i+1 < len(l4); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4[i : i+2]))
	}
	if len(l4)%2 == 1 {
		sum += uint32(l4[len(l4)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if proto == 17 && csum == 0 {
		csum = 0xffff // UDP zero checksum encoding
	}
	binary.BigEndian.PutUint16(l4[csumOff:csumOff+2], csum)
}

// parseL4 extracts transport protocol and ports from a raw IP packet. This is
// the same helper used by the WinDivert backend; on Linux the nfqueue backend
// needs it too but cannot share the file (different build tags), so we define a
// compatible copy. The engine_test.go file tests the Engine logic itself.
func parseL4(pkt []byte) (proto string, sport, dport int) {
	if len(pkt) < 20 {
		return "", 0, 0
	}
	var (
		l4   byte
		toff int
	)
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+4 {
			return "", 0, 0
		}
		l4, toff = pkt[9], ihl
	case 6:
		if len(pkt) < 44 {
			return "", 0, 0
		}
		l4, toff = pkt[6], 40
	default:
		return "", 0, 0
	}
	switch l4 {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		return "", 0, 0
	}
	if len(pkt) < toff+4 {
		return proto, 0, 0
	}
	sport = int(binary.BigEndian.Uint16(pkt[toff : toff+2]))
	dport = int(binary.BigEndian.Uint16(pkt[toff+2 : toff+4]))
	return proto, sport, dport
}
