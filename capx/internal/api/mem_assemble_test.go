package api

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAssembleBasics(t *testing.T) {
	got, err := assemble(0x1000, []string{"nop", "nop 3", "int3", "ret", "db 90 cc"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x90, 0x90, 0x90, 0x90, 0xCC, 0xC3, 0x90, 0xCC}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestAssembleRelJmpCall(t *testing.T) {
	// jmp from 0x1000 to 0x1005 => disp = 0x1005 - (0x1000+5) = 0 => E9 00000000
	got, err := assemble(0x1000, []string{"jmp 0x1005"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0xE9 || binary.LittleEndian.Uint32(got[1:]) != 0 {
		t.Fatalf("jmp rel32 wrong: % x", got)
	}

	// call backwards: from 0x2000 to 0x1000 => disp = 0x1000-(0x2000+5) = -0x1005
	got, err = assemble(0x2000, []string{"call 0x1000"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0xE8 {
		t.Fatalf("call opcode wrong: % x", got)
	}
	disp := int32(binary.LittleEndian.Uint32(got[1:]))
	if disp != int32(0x1000-(0x2000+5)) {
		t.Fatalf("call disp = %d, want %d", disp, int32(0x1000-(0x2000+5)))
	}
}

func TestAssembleAbsJmpWhenFar(t *testing.T) {
	// A target far outside rel32 range must fall back to FF25 abs64.
	got, err := assemble(0x1000, []string{"jmp 0x7ff800000000"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0xFF || got[1] != 0x25 {
		t.Fatalf("expected FF25 abs jmp, got % x", got[:2])
	}
	if binary.LittleEndian.Uint64(got[6:]) != 0x7ff800000000 {
		t.Fatalf("abs target wrong: %x", binary.LittleEndian.Uint64(got[6:]))
	}
}

func TestAssembleErrors(t *testing.T) {
	for _, src := range [][]string{
		{"frobnicate rax"}, // unknown mnemonic
		{"jmp"},            // missing target
		{"db zz"},          // bad hex
	} {
		if _, err := assemble(0x1000, src); err == nil {
			t.Errorf("expected error for %v", src)
		}
	}
}
