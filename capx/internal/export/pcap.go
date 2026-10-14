package export

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/hquip/capx/internal/model"
)

// PCAP file format constants (libpcap).
const (
	pcapMagic      = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	// LinkRaw is LINKTYPE_RAW (raw IP packets); LinkEthernet is LINKTYPE_ETHERNET.
	// Callers pass the capture's actual link type so Wireshark parses frames
	// correctly (live gopacket captures are Ethernet, not raw IP).
	LinkRaw      = 101
	LinkEthernet = 1
	pcapSnapLen  = 65535
)

// WritePCAP writes a PCAP file containing the provided packets (with raw bytes)
// to w using the given libpcap link type (LinkEthernet for live frames, LinkRaw
// for raw IP). Packets without raw data are skipped. The result is a valid
// libpcap file that can be opened by Wireshark, tcpdump, etc.
func WritePCAP(w io.Writer, packets []model.Packet, linkType int) error {
	if linkType == 0 {
		linkType = LinkEthernet
	}
	// Global header: 24 bytes.
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)  // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))
	if _, err := w.Write(hdr); err != nil {
		return err
	}

	// Packet records.
	rec := make([]byte, 16) // reuse for per-packet record headers
	for _, p := range packets {
		if len(p.Raw) == 0 {
			continue
		}
		ts := p.TS
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		sec := ts.Unix()
		usec := ts.Nanosecond() / 1000

		inclLen := uint32(len(p.Raw))
		origLen := uint32(p.Length)
		if origLen < inclLen {
			origLen = inclLen
		}

		binary.LittleEndian.PutUint32(rec[0:4], uint32(sec))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(usec))
		binary.LittleEndian.PutUint32(rec[8:12], inclLen)
		binary.LittleEndian.PutUint32(rec[12:16], origLen)
		if _, err := w.Write(rec); err != nil {
			return err
		}
		if _, err := w.Write(p.Raw); err != nil {
			return err
		}
	}
	return nil
}

// PCAPNG Section Header Block, Interface Description Block, and Enhanced Packet
// Block constants.
const (
	pcapngSHBType        = 0x0A0D0D0A
	pcapngIDBType        = 0x00000001
	pcapngEPBType        = 0x00000006
	pcapngByteOrderMagic = 0x1A2B3C4D
	pcapngVersionMaj     = 1
	pcapngVersionMin     = 0
)

// WritePCAPNG writes a PCAP-NG file to w using the given libpcap link type.
// This format is the modern successor to PCAP and is the default save format
// for Wireshark. Packets without raw data are skipped.
func WritePCAPNG(w io.Writer, packets []model.Packet, linkType int) error {
	if linkType == 0 {
		linkType = LinkEthernet
	}
	// Section Header Block (SHB).
	shb := make([]byte, 28)
	binary.LittleEndian.PutUint32(shb[0:4], pcapngSHBType)
	binary.LittleEndian.PutUint32(shb[4:8], 28) // block total length
	binary.LittleEndian.PutUint32(shb[8:12], pcapngByteOrderMagic)
	binary.LittleEndian.PutUint16(shb[12:14], pcapngVersionMaj)
	binary.LittleEndian.PutUint16(shb[14:16], pcapngVersionMin)
	// Section length: -1 (not specified).
	binary.LittleEndian.PutUint32(shb[16:20], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(shb[20:24], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(shb[24:28], 28) // block total length (repeated)
	if _, err := w.Write(shb); err != nil {
		return err
	}

	// Interface Description Block (IDB).
	idb := make([]byte, 20)
	binary.LittleEndian.PutUint32(idb[0:4], pcapngIDBType)
	binary.LittleEndian.PutUint32(idb[4:8], 20)                // block total length
	binary.LittleEndian.PutUint16(idb[8:10], uint16(linkType)) // link type
	binary.LittleEndian.PutUint16(idb[10:12], 0)               // reserved
	binary.LittleEndian.PutUint32(idb[12:16], pcapSnapLen)
	binary.LittleEndian.PutUint32(idb[16:20], 20) // block total length (repeated)
	if _, err := w.Write(idb); err != nil {
		return err
	}

	// Enhanced Packet Blocks (EPB).
	for _, p := range packets {
		if len(p.Raw) == 0 {
			continue
		}
		ts := p.TS
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		// Timestamp as microseconds since epoch, split into high/low 32 bits.
		usec := uint64(ts.UnixNano() / 1000)
		tsHigh := uint32(usec >> 32)
		tsLow := uint32(usec & 0xFFFFFFFF)

		capturedLen := uint32(len(p.Raw))
		origLen := uint32(p.Length)
		if origLen < capturedLen {
			origLen = capturedLen
		}

		// Pad packet data to 4-byte boundary.
		padLen := (4 - (capturedLen % 4)) % 4
		blockLen := 32 + capturedLen + padLen // header(32) + data + padding + trailer(already in 32)
		// Actually: Block Type(4) + Block Total Len(4) + Interface ID(4) + TS High(4) +
		//           TS Low(4) + Captured Len(4) + Original Len(4) + Packet Data(capturedLen) +
		//           Padding(padLen) + Block Total Len(4)
		blockLen = 32 + capturedLen + padLen

		hdr := make([]byte, 28)
		binary.LittleEndian.PutUint32(hdr[0:4], pcapngEPBType)
		binary.LittleEndian.PutUint32(hdr[4:8], blockLen)
		binary.LittleEndian.PutUint32(hdr[8:12], 0) // interface ID
		binary.LittleEndian.PutUint32(hdr[12:16], tsHigh)
		binary.LittleEndian.PutUint32(hdr[16:20], tsLow)
		binary.LittleEndian.PutUint32(hdr[20:24], capturedLen)
		binary.LittleEndian.PutUint32(hdr[24:28], origLen)
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		if _, err := w.Write(p.Raw); err != nil {
			return err
		}
		if padLen > 0 {
			if _, err := w.Write(make([]byte, padLen)); err != nil {
				return err
			}
		}
		// Trailing block total length.
		var trail [4]byte
		binary.LittleEndian.PutUint32(trail[:], blockLen)
		if _, err := w.Write(trail[:]); err != nil {
			return err
		}
	}
	return nil
}
