package memscan

import (
	"fmt"
	"sort"
)

const (
	ptrMaxSlots   = 2_000_000
	ptrMaxResults = 512
	ptrMaxLevel   = 6
	ptrChunk      = 1 << 20
)

// ptrRegion is one readable mapping used while collecting pointer slots.
type ptrRegion struct {
	base, size uint64
	static     bool // module image / file-backed mapping (CE static base)
}

type ptrSlot struct {
	pointee uint64
	addr    uint64
	static  bool
}

type ptrMem interface {
	PtrWidth() int
	Read(addr uint64, buf []byte) (int, error)
}

func clampPtrLevel(maxLevel uint32) int {
	if maxLevel < 1 {
		return 1
	}
	if maxLevel > ptrMaxLevel {
		return int(ptrMaxLevel)
	}
	return int(maxLevel)
}

func inReadable(ranges [][2]uint64, p uint64) bool {
	if p == 0 || len(ranges) == 0 {
		return false
	}
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i][0] > p })
	if i == 0 {
		return false
	}
	s, e := ranges[i-1][0], ranges[i-1][1]
	return p >= s && p < e
}

func collectPtrSlots(mem ptrMem, regs []ptrRegion) []ptrSlot {
	wd := mem.PtrWidth()
	if wd != 4 && wd != 8 {
		wd = 8
	}
	ranges := make([][2]uint64, 0, len(regs))
	for _, r := range regs {
		if r.size == 0 {
			continue
		}
		ranges = append(ranges, [2]uint64{r.base, r.base + r.size})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })

	slots := make([]ptrSlot, 0, 1024)
	buf := make([]byte, ptrChunk)
	for _, r := range regs {
		addr := r.base
		if rem := addr % uint64(wd); rem != 0 {
			addr += uint64(wd) - rem
		}
		end := r.base + r.size
		for addr < end && len(slots) < ptrMaxSlots {
			want := uint64(ptrChunk)
			if left := end - addr; left < want {
				want = left
			}
			if want < uint64(wd) {
				break
			}
			n, err := mem.Read(addr, buf[:want])
			if err != nil || n < wd {
				addr += want
				continue
			}
			n -= n % wd
			for i := 0; i+wd <= n && len(slots) < ptrMaxSlots; i += wd {
				var v uint64
				if wd == 4 {
					v = uint64(leUint32(buf[i : i+4]))
				} else {
					v = leUint64(buf[i : i+8])
				}
				if v != 0 && inReadable(ranges, v) {
					slots = append(slots, ptrSlot{pointee: v, addr: addr + uint64(i), static: r.static})
				}
			}
			addr += want
		}
		if len(slots) >= ptrMaxSlots {
			break
		}
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].pointee < slots[j].pointee })
	return slots
}

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leUint64(b []byte) uint64 {
	return uint64(leUint32(b[:4])) | uint64(leUint32(b[4:8]))<<32
}

type ptrFrame struct {
	tgt     uint64
	depth   int
	offsRev []uint64
}

// pointerScanFromSlots is the CE reverse-DFS: find static-base + offset chains
// that currently resolve to target. maxOffset is per-level slack.
func pointerScanFromSlots(target, maxOffset uint64, maxLevel int, slots []ptrSlot) []PointerPath {
	if target == 0 || len(slots) == 0 {
		return nil
	}
	if maxOffset == 0 {
		maxOffset = 0x400
	}
	if maxLevel < 1 {
		maxLevel = 1
	}
	if maxLevel > ptrMaxLevel {
		maxLevel = ptrMaxLevel
	}
	pointees := make([]uint64, len(slots))
	for i, s := range slots {
		pointees[i] = s.pointee
	}
	results := make([]PointerPath, 0)
	stack := []ptrFrame{{tgt: target}}
	for len(stack) > 0 && len(results) < ptrMaxResults {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		lo := uint64(0)
		if fr.tgt > maxOffset {
			lo = fr.tgt - maxOffset
		}
		hi := fr.tgt
		idx := sort.Search(len(pointees), func(i int) bool { return pointees[i] >= lo })
		for idx < len(slots) && pointees[idx] <= hi && len(results) < ptrMaxResults {
			slot := slots[idx]
			idx++
			off := fr.tgt - slot.pointee
			offsRev := make([]uint64, len(fr.offsRev)+1)
			copy(offsRev, fr.offsRev)
			offsRev[len(fr.offsRev)] = off
			if slot.static {
				offsets := make([]uint64, len(offsRev))
				for i := range offsRev {
					offsets[i] = offsRev[len(offsRev)-1-i]
				}
				results = append(results, PointerPath{Base: slot.addr, Offsets: offsets})
			}
			if fr.depth+1 < maxLevel && slot.addr != fr.tgt {
				stack = append(stack, ptrFrame{tgt: slot.addr, depth: fr.depth + 1, offsRev: offsRev})
			}
		}
	}
	return results
}

func runPointerScan(mem ptrMem, regs []ptrRegion, target, maxOffset uint64, maxLevel uint32) ([]PointerPath, error) {
	if target == 0 {
		return nil, fmt.Errorf("memscan: zero target")
	}
	slots := collectPtrSlots(mem, regs)
	return pointerScanFromSlots(target, maxOffset, clampPtrLevel(maxLevel), slots), nil
}
