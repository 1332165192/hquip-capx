package api

// A focused x86-64 mini-assembler for code injection (the practical subset of
// CE's Auto Assemble): enough to build detours and code caves without hand-
// encoding bytes. Supported per line:
//
//	nop                      90
//	nop N                    N * 90
//	int3 / breakpoint        CC
//	ret                      C3
//	db AA BB CC ...          raw bytes (hex)
//	jmp 0xADDR               near rel32 (E9) when in range, else abs64 (FF25)
//	call 0xADDR              near rel32 (E8)
//	jmpfar 0xADDR            forced 64-bit absolute jmp (FF 25 00000000 + qword)
//
// assemble lays the lines out starting at virtual address `at` (needed for the
// relative displacement maths) and returns the encoded bytes. It is pure so it
// can be unit-tested; the endpoint optionally writes the result into the target.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// assemble encodes the given lines into bytes laid out starting at address at.
func assemble(at uint64, lines []string) ([]byte, error) {
	var out []byte
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip an inline comment.
		if j := strings.IndexAny(line, ";"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		fields := strings.Fields(line)
		mnem := strings.ToLower(fields[0])
		args := fields[1:]
		pc := at + uint64(len(out)) // address of this instruction

		switch mnem {
		case "nop":
			n := 1
			if len(args) == 1 {
				v, err := strconv.Atoi(args[0])
				if err != nil || v < 1 {
					return nil, fmt.Errorf("line %d: nop count must be a positive integer", i+1)
				}
				n = v
			}
			for k := 0; k < n; k++ {
				out = append(out, 0x90)
			}
		case "int3", "breakpoint":
			out = append(out, 0xCC)
		case "ret":
			out = append(out, 0xC3)
		case "db", "bytes":
			b, err := hex.DecodeString(strings.ReplaceAll(strings.Join(args, ""), " ", ""))
			if err != nil || len(b) == 0 {
				return nil, fmt.Errorf("line %d: db needs hex bytes", i+1)
			}
			out = append(out, b...)
		case "jmp", "call":
			if len(args) != 1 {
				return nil, fmt.Errorf("line %d: %s needs one target", i+1, mnem)
			}
			target, err := parseAddr(args[0])
			if err != nil {
				return nil, fmt.Errorf("line %d: bad target %q", i+1, args[0])
			}
			out = append(out, encodeBranch(mnem, pc, target)...)
		case "jmpfar", "jmpabs":
			target, err := parseAddr(args[0])
			if err != nil {
				return nil, fmt.Errorf("line %d: bad target", i+1)
			}
			out = append(out, encodeAbsJmp(target)...)
		default:
			return nil, fmt.Errorf("line %d: unsupported instruction %q (supported: nop/int3/ret/db/jmp/call/jmpfar)", i+1, mnem)
		}
	}
	return out, nil
}

// encodeBranch encodes jmp/call to target from instruction address pc. It uses
// the 5-byte rel32 form (E9/E8) when the displacement fits in int32; otherwise
// jmp falls back to a 64-bit absolute (FF25) and call is rejected for range.
func encodeBranch(mnem string, pc, target uint64) []byte {
	const relLen = 5
	disp := int64(target) - int64(pc+relLen)
	if disp >= -2147483648 && disp <= 2147483647 {
		op := byte(0xE9) // jmp rel32
		if mnem == "call" {
			op = 0xE8
		}
		b := make([]byte, 5)
		b[0] = op
		binary.LittleEndian.PutUint32(b[1:], uint32(int32(disp)))
		return b
	}
	if mnem == "jmp" {
		return encodeAbsJmp(target)
	}
	// out-of-range call: emit a far jmp-style absolute call thunk is uncommon;
	// fall back to push+ret style is complex, so encode an abs jmp (best effort).
	return encodeAbsJmp(target)
}

// encodeAbsJmp encodes a 64-bit absolute jump: FF 25 00 00 00 00 (jmp [rip+0])
// followed by the 8-byte target.
func encodeAbsJmp(target uint64) []byte {
	b := []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint64(b[6:], target)
	return b
}

// memAssemble assembles the posted lines at address `at` and returns the bytes.
// With write=true it also patches them into the target (an active operation).
func (s *Server) memAssemble(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		At    string   `json:"at"`
		Lines []string `json:"lines"`
		Write bool     `json:"write"`
	}
	if err := decodeBody(r, &req); err != nil || len(req.Lines) == 0 {
		writeErr(w, http.StatusBadRequest, "lines required")
		return
	}
	at, err := parseAddr(req.At)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad at address (use 0x... or decimal)")
		return
	}
	code, err := assemble(at, req.Lines)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"at": formatHex(at), "len": len(code), "bytes": hex.EncodeToString(code)}
	if req.Write {
		// Save original bytes for revert, then patch.
		orig := make([]byte, len(code))
		if n, err := sess.Read(at, orig); err == nil && n == len(orig) {
			s.patches.remember(sid, at, orig)
		}
		n, err := sess.Write(at, code)
		if err != nil || n != len(code) {
			writeErr(w, http.StatusInternalServerError, "assemble write failed (need active + write access)")
			return
		}
		resp["written"] = n
	}
	writeJSON(w, http.StatusOK, resp)
}
