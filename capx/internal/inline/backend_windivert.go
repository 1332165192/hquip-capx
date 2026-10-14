//go:build windows && windivert

// WinDivert backend (M6). Requires the WinDivert driver + DLL (WinDivert.dll /
// WinDivert64.sys) present and capx running elevated. Build with:
//
//	go build -tags "windivert" ./cmd/captured
//
// The actual match/replace decision is made by the platform-independent Engine
// (engine.go); this file is only the kernel I/O plumbing: it diverts packets
// at the NETWORK layer, hands each packet to the engine, drops or rewrites it,
// recomputes checksums via WinDivertHelperCalcChecksums, and re-injects.
package inline

import (
	"context"
	"fmt"
	"sync"
	"unsafe"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
	"golang.org/x/sys/windows"
)

// WinDivert 2.x WINDIVERT_ADDRESS is 64 bytes. We treat it as opaque except for
// the Outbound flag (used when injecting). Layout (offsets):
//
//	0  INT64  Timestamp
//	8  UINT8  Layer
//	9  UINT8  Event
//	10 UINT8  bitflags: bit0 Sniffed, bit1 Outbound, bit2 Loopback, ...
//	11 UINT8  Reserved1
//	12 UINT32 Reserved2
//	16 union (48 bytes)
const wdAddrSize = 64

type windivertBackend struct {
	dll      *windows.LazyDLL
	pOpen    *windows.LazyProc
	pRecv    *windows.LazyProc
	pSend    *windows.LazyProc
	pClose   *windows.LazyProc
	pCalcSum *windows.LazyProc

	mu     sync.Mutex
	handle windows.Handle
}

func newBackend() backend {
	dll := windows.NewLazyDLL("WinDivert.dll")
	b := &windivertBackend{
		dll:      dll,
		pOpen:    dll.NewProc("WinDivertOpen"),
		pRecv:    dll.NewProc("WinDivertRecv"),
		pSend:    dll.NewProc("WinDivertSend"),
		pClose:   dll.NewProc("WinDivertClose"),
		pCalcSum: dll.NewProc("WinDivertHelperCalcChecksums"),
		handle:   windows.InvalidHandle,
	}
	return b
}

func (b *windivertBackend) name() string { return "windivert" }

// available reports whether WinDivert.dll could be loaded.
func (b *windivertBackend) available() bool {
	if err := b.dll.Load(); err != nil {
		return false
	}
	return b.pOpen.Find() == nil
}

func (b *windivertBackend) open(filter string) (windows.Handle, error) {
	if filter == "" {
		filter = "tcp or udp"
	}
	cfilter, err := windows.BytePtrFromString(filter)
	if err != nil {
		return windows.InvalidHandle, err
	}
	// WinDivertOpen(filter, layer=0 NETWORK, priority=0, flags=0)
	r, _, e := b.pOpen.Call(
		uintptr(unsafe.Pointer(cfilter)),
		0, 0, 0,
	)
	h := windows.Handle(r)
	if h == windows.InvalidHandle {
		return h, fmt.Errorf("WinDivertOpen failed: %v", e)
	}
	return h, nil
}

func (b *windivertBackend) run(ctx context.Context, filter string, eng *Engine, st *store.Store) error {
	h, err := b.open(filter)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.handle = h
	b.mu.Unlock()

	// Closing the handle unblocks WinDivertRecv on cancel.
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if b.handle != windows.InvalidHandle {
			b.pClose.Call(uintptr(b.handle))
			b.handle = windows.InvalidHandle
		}
		b.mu.Unlock()
	}()

	packet := make([]byte, 65535)
	var addr [wdAddrSize]byte
	var recvLen uint32

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r, _, _ := b.pRecv.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(len(packet)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if r == 0 { // FALSE => handle closed or error
			return nil
		}
		pkt := packet[:recvLen]
		proto, sport, dport := parseL4(pkt)

		out, drop, hit, modified := eng.Apply(pkt, proto, sport, dport)
		if drop {
			if hit {
				st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_drop",
					Data: map[string]string{"proto": proto, "len": fmt.Sprint(len(pkt))}})
			}
			continue // do not re-inject => dropped
		}
		if modified {
			// recompute checksums after an in-place rewrite or TCP seq/ack fix-up
			b.pCalcSum.Call(
				uintptr(unsafe.Pointer(&out[0])),
				uintptr(len(out)),
				uintptr(unsafe.Pointer(&addr[0])),
				0,
			)
		}
		if hit {
			st.Publish(model.Event{Source: model.SourceProxy, Kind: "inline_replace",
				Data: map[string]string{"proto": proto, "len": fmt.Sprint(len(out))}})
		}
		var sendLen uint32
		b.pSend.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&out[0])),
			uintptr(len(out)),
			uintptr(unsafe.Pointer(&sendLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
	}
}

func (b *windivertBackend) send(pkt []byte, outbound bool) error {
	b.mu.Lock()
	h := b.handle
	b.mu.Unlock()
	if h == windows.InvalidHandle {
		// open a transient handle in send-only mode (filter "false" => no recv)
		var err error
		h, err = b.open("false")
		if err != nil {
			return err
		}
		defer b.pClose.Call(uintptr(h))
	}
	var addr [wdAddrSize]byte
	addr[8] = 0 // Layer = NETWORK
	if outbound {
		addr[10] |= 1 << 1 // Outbound bit
	}
	// fill checksums for the injected packet
	b.pCalcSum.Call(
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&addr[0])),
		0,
	)
	var sendLen uint32
	r, _, e := b.pSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertSend failed: %v", e)
	}
	return nil
}

func (b *windivertBackend) runRedirect(ctx context.Context, filter string, redir *Redirector, st *store.Store) error {
	h, err := b.open(filter)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.handle = h
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if b.handle != windows.InvalidHandle {
			b.pClose.Call(uintptr(b.handle))
			b.handle = windows.InvalidHandle
		}
		b.mu.Unlock()
	}()

	packet := make([]byte, 65535)
	var addr [wdAddrSize]byte
	var recvLen uint32
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r, _, _ := b.pRecv.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(len(packet)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if r == 0 {
			return nil
		}
		pkt := packet[:recvLen]
		outbound := addr[10]&(1<<1) != 0
		mod, flip := redir.Apply(pkt, outbound)
		if flip {
			if outbound {
				addr[10] &^= 1 << 1
			} else {
				addr[10] |= 1 << 1
			}
		}
		if mod {
			b.pCalcSum.Call(
				uintptr(unsafe.Pointer(&pkt[0])),
				uintptr(len(pkt)),
				uintptr(unsafe.Pointer(&addr[0])),
				0,
			)
			st.Publish(model.Event{Source: model.SourceProxy, Kind: "transparent_redirect",
				Data: map[string]string{"len": fmt.Sprint(len(pkt))}})
		}
		var sendLen uint32
		b.pSend.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&pkt[0])),
			uintptr(len(pkt)),
			uintptr(unsafe.Pointer(&sendLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
	}
}

// parseL4 extracts the transport protocol and ports from a raw IP packet
// (IPv4/IPv6, TCP/UDP), walking IPv6 extension headers via the shared parser.
// Returns ("", 0, 0) when unknown.
func parseL4(pkt []byte) (proto string, sport, dport int) {
	info := parseIP(pkt)
	return info.Proto, info.SrcPort, info.DstPort
}
