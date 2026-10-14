//go:build pcap

// Live L3/L4 capture backend using gopacket/libpcap with TCP stream reassembly.
//
// Build with: go build -tags pcap ./... (from packet-capture/capx)
// Requires Npcap (Windows) or libpcap (Linux/macOS) plus the gopacket module:
//
//	go get github.com/google/gopacket
package sniffer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"github.com/hquip/capx/internal/decode"
	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

const maxReassembledPayload = 256 * 1024 // 256 KB per direction

type pcapSniffer struct {
	permissionCheck func() error
}

func newBackend() Sniffer { return pcapSniffer{} }

func (pcapSniffer) Backend() string { return "gopacket" }

func (s pcapSniffer) permissions() error {
	if s.permissionCheck != nil {
		return s.permissionCheck()
	}
	return checkPCapPermissions()
}

func (s pcapSniffer) Interfaces() ([]Device, error) {
	if err := s.permissions(); err != nil {
		return nil, err
	}
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find devices: %w", err)
	}
	out := make([]Device, 0, len(ifs))
	for _, i := range ifs {
		d := Device{Name: i.Name, Description: i.Description}
		for _, a := range i.Addresses {
			if a.IP != nil {
				d.Addresses = append(d.Addresses, a.IP.String())
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s pcapSniffer) Run(ctx context.Context, captureID string, cfg Config, st *store.Store) error {
	if err := s.permissions(); err != nil {
		return err
	}
	iface := cfg.Iface
	if iface == "" {
		ifs, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("find devices: %w", err)
		}
		if len(ifs) == 0 {
			return fmt.Errorf("no capture devices found")
		}
		devs := make([]Device, 0, len(ifs))
		for _, i := range ifs {
			d := Device{Name: i.Name, Description: i.Description}
			for _, a := range i.Addresses {
				if a.IP != nil {
					d.Addresses = append(d.Addresses, a.IP.String())
				}
			}
			devs = append(devs, d)
		}
		iface = PreferCaptureDevice(devs).Name
	}
	snap := cfg.Snap
	if snap == 0 {
		snap = 65536
	}
	// A finite read timeout is required so stop/cancel can unblock
	// PacketSource.Packets() instead of hanging until the next frame.
	h, err := pcap.OpenLive(iface, snap, true, 250*time.Millisecond)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer h.Close()

	filter := cfg.Filter
	if filter == "" {
		filter = "tcp or udp"
	}
	if err := h.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set bpf %q: %w", filter, err)
	}

	// Record the link type so exported PCAP files declare the correct DLT.
	st.SetCaptureLinkType(captureID, int(h.LinkType()))

	// Set up TCP reassembly.
	sf := &capxStreamFactory{st: st}
	pool := tcpassembly.NewStreamPool(sf)
	assembler := tcpassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = 256
	assembler.MaxBufferedPagesTotal = 4096

	src := gopacket.NewPacketSource(h, h.LinkType())
	src.NoCopy = true
	packets := src.Packets()

	// Periodic flush of old connections.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			assembler.FlushAll()
			return ctx.Err()
		case <-ticker.C:
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		case pkt, ok := <-packets:
			if !ok {
				assembler.FlushAll()
				return nil
			}
			handlePacket(captureID, cfg, st, pkt, assembler)
		}
	}
}

// decryptQUICInitialSafe decrypts a QUIC Initial packet, returning nil when it
// cannot be decrypted. Packets here are untrusted bytes off the wire and this
// runs on the capture loop's goroutine, so a decoder panic is contained to the
// one packet instead of taking the whole daemon down.
func decryptQUICInitialSafe(app []byte) (dec *decode.QUICInitial) {
	defer func() {
		if recover() != nil {
			dec = nil
		}
	}()
	d, err := decode.DecryptQUICInitial(app)
	if err != nil {
		return nil
	}
	return d
}

func handlePacket(captureID string, cfg Config, st *store.Store, pkt gopacket.Packet, assembler *tcpassembly.Assembler) {
	net := pkt.NetworkLayer()
	trans := pkt.TransportLayer()
	if net == nil || trans == nil {
		return
	}

	var l4 model.L4
	var sp, dp uint16
	switch t := trans.(type) {
	case *layers.TCP:
		l4 = model.TCP
		sp, dp = uint16(t.SrcPort), uint16(t.DstPort)
		// Feed TCP packets into the reassembler.
		assembler.AssembleWithTimestamp(net.NetworkFlow(), t, pkt.Metadata().Timestamp)
	case *layers.UDP:
		l4 = model.UDP
		sp, dp = uint16(t.SrcPort), uint16(t.DstPort)
	default:
		return
	}

	// Flag QUIC/HTTP-3 handshakes so they are visible even though the payload is
	// encrypted (decryption would need the TLS keylog + QUIC key derivation).
	if l4 == model.UDP {
		if app := trans.LayerPayload(); len(app) > 0 {
			if info, ok := decode.DetectQUIC(app); ok {
				data := map[string]any{"version": info.Version, "type": info.Type,
					"src_port": sp, "dst_port": dp}
				// Initial packets are decryptable from the DCID alone — pull the
				// ClientHello SNI/ALPN so QUIC/HTTP3 targets are identifiable.
				if dec := decryptQUICInitialSafe(app); dec != nil {
					if dec.SNI != "" {
						data["sni"] = dec.SNI
					}
					if len(dec.ALPN) > 0 {
						data["alpn"] = dec.ALPN
					}
				}
				st.Publish(model.Event{Source: model.SourceSniffer, Kind: "quic_detected", Data: data})
			}
		}
	}

	srcIP := net.NetworkFlow().Src().String()
	dstIP := net.NetworkFlow().Dst().String()
	now := pkt.Metadata().Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	flowID, canonSrcIP, canonSrcPort, canonDstIP, canonDstPort, reversed := model.CanonicalFlowID(l4, srcIP, sp, dstIP, dp)
	// CanonicalFlowID may swap endpoints for a stable id. reversed means this
	// packet is dst->src relative to that id, i.e. the responder's direction.
	dir := model.DirOut
	if reversed {
		dir = model.DirIn
	}

	if st.EnsureFlow(&model.Flow{
		ID: flowID, L4: l4,
		SrcIP: canonSrcIP, SrcPort: canonSrcPort,
		DstIP: canonDstIP, DstPort: canonDstPort,
		Started: now, Updated: now,
	}) {
		st.Publish(model.Event{Source: model.SourceSniffer, Kind: "flow_new", CorrID: flowID,
			Data: &model.Flow{ID: flowID, L4: l4, SrcIP: canonSrcIP, SrcPort: canonSrcPort, DstIP: canonDstIP, DstPort: canonDstPort, Started: now}})
	}
	st.AddFlowPacket(flowID, len(pkt.Data()), now)

	layerNames := make([]string, 0, len(pkt.Layers()))
	for _, l := range pkt.Layers() {
		layerNames = append(layerNames, l.LayerType().String())
	}
	frame := pkt.Data()
	// Retain the full frame (capped at snap length) for PCAP export.
	st.AddPacket(model.Packet{
		CaptureID: captureID, FlowID: flowID, TS: now, Dir: dir, Length: len(frame),
		Layers: layerNames, Raw: capBytes(frame, 65535),
	})
	// The SSE "packet" event carries only as much raw as MaxRaw requests.
	p := model.Packet{
		CaptureID: captureID, FlowID: flowID, TS: now, Dir: dir, Length: len(frame), Layers: layerNames,
	}
	if cfg.MaxRaw > 0 {
		p.Raw = capBytes(frame, cfg.MaxRaw)
	}
	st.Publish(model.Event{Source: model.SourceSniffer, Kind: "packet", CorrID: flowID, Data: p})
}

func capBytes(b []byte, max int) []byte {
	if max > 0 && len(b) > max {
		return b[:max]
	}
	return b
}

// --- TCP stream reassembly (gopacket/tcpassembly) ---

// capxStreamFactory creates new streams for the TCP assembler. Each TCP
// connection (identified by its network + transport flow) gets a capxStream
// that drains reassembled bytes and stores them on the corresponding Flow.
type capxStreamFactory struct {
	st *store.Store
}

func (f *capxStreamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	s := &capxStream{
		st:        f.st,
		netFlow:   netFlow,
		transFlow: transFlow,
		reader:    tcpreader.NewReaderStream(),
	}
	go s.drain()
	return &s.reader
}

type capxStream struct {
	st        *store.Store
	netFlow   gopacket.Flow
	transFlow gopacket.Flow
	reader    tcpreader.ReaderStream

	mu      sync.Mutex
	payload []byte
}

// drain reads all reassembled bytes from the tcpreader and appends them to the
// stream's payload buffer (capped at maxReassembledPayload). When the stream
// closes (reader returns EOF), it writes the accumulated payload to the store's
// Flow and publishes a "flow_reassembled" event.
func (s *capxStream) drain() {
	buf := make([]byte, 4096)
	for {
		n, err := s.reader.Read(buf)
		if n > 0 {
			s.mu.Lock()
			remaining := maxReassembledPayload - len(s.payload)
			if remaining > 0 {
				chunk := buf[:n]
				if n > remaining {
					chunk = chunk[:remaining]
				}
				s.payload = append(s.payload, chunk...)
			}
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
	}

	// Stream closed: write reassembled payload to the Flow.
	s.mu.Lock()
	data := s.payload
	s.mu.Unlock()
	if len(data) == 0 {
		return
	}

	srcIP := s.netFlow.Src().String()
	dstIP := s.netFlow.Dst().String()
	srcPort := s.transFlow.Src().String()
	dstPort := s.transFlow.Dst().String()

	flowID, reversed := model.CanonicalFlowIDStringPorts(model.TCP, srcIP, srcPort, dstIP, dstPort)
	dir := "client"
	if reversed {
		dir = "server"
	}
	if s.st.AppendFlowPayload(flowID, dir, data, maxReassembledPayload) {
		s.st.Publish(model.Event{Source: model.SourceSniffer, Kind: "flow_reassembled", CorrID: flowID,
			Data: map[string]any{"flow_id": flowID, "dir": dir, "bytes": len(data)}})
	}
}
