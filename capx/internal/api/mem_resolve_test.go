package api

import "testing"

func TestResolvePath(t *testing.T) {
	// base 0x1000 -> deref -> 0x5000; +0x10 -> 0x5010 -> deref -> 0x9000; +8 -> 0x9008
	mem := map[uint64]uint64{
		0x1000: 0x5000,
		0x5010: 0x9000,
	}
	read := func(a uint64) (uint64, bool) { v, ok := mem[a]; return v, ok }

	// single level: [0x1000]+0x10 = 0x5010
	if got, ok := resolvePath(0x1000, []uint64{0x10}, read); !ok || got != 0x5010 {
		t.Fatalf("one level = 0x%x ok=%v, want 0x5010", got, ok)
	}
	// two levels: [[0x1000]+0x10]+8 = 0x9008
	if got, ok := resolvePath(0x1000, []uint64{0x10, 0x8}, read); !ok || got != 0x9008 {
		t.Fatalf("two level = 0x%x ok=%v, want 0x9008", got, ok)
	}
	// zero offsets => base itself
	if got, ok := resolvePath(0x1234, nil, read); !ok || got != 0x1234 {
		t.Fatalf("no offsets = 0x%x ok=%v, want 0x1234", got, ok)
	}
	// broken deref
	if _, ok := resolvePath(0xdead, []uint64{0}, read); ok {
		t.Fatal("expected broken path to fail")
	}
}

func TestResolveExpr(t *testing.T) {
	mods := map[string]uint64{
		"game.exe": 0x140000000,
		"game":     0x140000000,
		"lib.dll":  0x7ff800000000,
	}
	// Fake pointer memory: addr -> value.
	mem := map[uint64]uint64{
		0x140000010:    0x200,     // [game.exe+0x10] = 0x200
		0x210:          0x50000,   // [[game.exe+0x10]+0x10] = 0x50000
		0x7ff800000008: 0xdead000, // [lib.dll+8]
	}
	read := func(addr uint64) (uint64, bool) { v, ok := mem[addr]; return v, ok }

	cases := []struct {
		expr string
		want uint64
		ok   bool
	}{
		{"0x1234", 0x1234, true},
		{"4096", 4096, true},
		{"game.exe+0x1000", 0x140001000, true},
		{"game+0x1000", 0x140001000, true},        // without extension
		{"GAME.EXE+0x10", 0x140000010, true},      // case-insensitive
		{"[game.exe+0x10]", 0x200, true},          // single deref
		{"[game.exe+0x10]+8", 0x208, true},        // deref + offset
		{"[[game.exe+0x10]+0x10]", 0x50000, true}, // two-level chain
		{"lib.dll+8", 0x7ff800000008, true},
		{"[lib.dll+8]", 0xdead000, true},
		{"missing.dll+1", 0, false},  // unknown module
		{"[0xbadbad]", 0, false},     // unreadable deref
		{"game.exe+", 0, false},      // trailing operator
		{"[game.exe+0x10", 0, false}, // missing bracket
	}
	for _, c := range cases {
		got, err := resolveExpr(c.expr, mods, read)
		if c.ok {
			if err != nil {
				t.Errorf("resolveExpr(%q) error: %v", c.expr, err)
				continue
			}
			if got != c.want {
				t.Errorf("resolveExpr(%q) = 0x%x, want 0x%x", c.expr, got, c.want)
			}
		} else if err == nil {
			t.Errorf("resolveExpr(%q) = 0x%x, want error", c.expr, got)
		}
	}
}
