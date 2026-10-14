package memscan

import "testing"

func TestPointerScanFromSlotsMultiLevel(t *testing.T) {
	// Static slot 0x1000 holds 0x2000.
	// Heap slot 0x2000 holds 0x3000.
	// Target is 0x3010 => path [0x1000] + [0, 0x10]
	slots := []ptrSlot{
		{pointee: 0x2000, addr: 0x1000, static: true},
		{pointee: 0x3000, addr: 0x2000, static: false},
	}
	paths := pointerScanFromSlots(0x3010, 0x20, 3, slots)
	if len(paths) == 0 {
		t.Fatal("expected at least one path")
	}
	found := false
	for _, p := range paths {
		if p.Base != 0x1000 || len(p.Offsets) != 2 {
			continue
		}
		if p.Offsets[0] == 0 && p.Offsets[1] == 0x10 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing static chain 0x1000 + [0, 0x10]: %+v", paths)
	}
}

func TestPointerScanDirectStatic(t *testing.T) {
	slots := []ptrSlot{
		{pointee: 0x5000, addr: 0x140001000, static: true},
	}
	paths := pointerScanFromSlots(0x5010, 0x20, 3, slots)
	if len(paths) != 1 {
		t.Fatalf("got %d paths: %+v", len(paths), paths)
	}
	if paths[0].Base != 0x140001000 || len(paths[0].Offsets) != 1 || paths[0].Offsets[0] != 0x10 {
		t.Fatalf("unexpected path %+v", paths[0])
	}
}

func TestInReadable(t *testing.T) {
	ranges := [][2]uint64{{0x1000, 0x2000}, {0x8000, 0x9000}}
	if !inReadable(ranges, 0x1000) || !inReadable(ranges, 0x1fff) {
		t.Fatal("in-range missed")
	}
	if inReadable(ranges, 0x2000) || inReadable(ranges, 0) || inReadable(ranges, 0x7000) {
		t.Fatal("out-of-range accepted")
	}
}
