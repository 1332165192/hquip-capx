package api

// Structure dissect (CE's "Dissect data/structures"): given a base address and
// a length, read the block once and decode every offset as multiple value
// types at the same time, so an unknown struct can be reverse-engineered by
// eye. Each row also flags whether the 8 bytes at the offset look like a
// pointer into a currently-mapped region.

import (
	"encoding/binary"
	"math"
	"net/http"
)

// dissectField is one decoded interpretation of the bytes at an offset.
type dissectRow struct {
	Offset int     `json:"offset"`
	Addr   string  `json:"addr"`
	Hex    string  `json:"hex"` // the step-width raw bytes, hex
	U8     uint8   `json:"u8"`
	I8     int8    `json:"i8"`
	U16    uint16  `json:"u16"`
	I16    int16   `json:"i16"`
	U32    uint32  `json:"u32"`
	I32    int32   `json:"i32"`
	U64    uint64  `json:"u64"`
	I64    int64   `json:"i64"`
	F32    float64 `json:"f32"`
	F64    float64 `json:"f64"`
	Ptr    string  `json:"ptr"`    // 8 bytes as an address
	PtrTo  string  `json:"ptr_to"` // region path the pointer lands in, or ""
	IsPtr  bool    `json:"is_ptr"` // true if Ptr resolves into a mapped region
	ASCII  string  `json:"ascii"`
}

// memDissect reads {addr, len, step} and returns per-offset multi-type decodes.
func (s *Server) memDissect(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Addr string `json:"addr"`
		Len  int    `json:"len"`
		Step int    `json:"step"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	base, err := parseAddr(req.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	length := req.Len
	if length <= 0 {
		length = 256
	}
	if length > 64*1024 {
		length = 64 * 1024
	}
	step := req.Step
	if step != 1 && step != 2 && step != 4 && step != 8 {
		step = 4
	}

	// Read the block plus 8 trailing bytes so the last rows can still decode a
	// full u64/pointer/f64.
	buf := make([]byte, length+8)
	n, err := sess.Read(base, buf)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusInternalServerError, "cannot read memory at address")
		return
	}

	// Build a region index once so pointer targets can be annotated.
	regions, _ := listRegions(s.extFor(sid).pid)

	rows := make([]dissectRow, 0, length/step+1)
	for off := 0; off+step <= n && off < length; off += step {
		row := dissectRow{Offset: off, Addr: formatHex(base + uint64(off))}
		seg := buf[off:n]
		row.Hex = bytesToHex(buf[off : off+step])
		row.ASCII = bytesASCII(buf[off : off+step])
		row.U8 = seg[0]
		row.I8 = int8(seg[0])
		if len(seg) >= 2 {
			row.U16 = binary.LittleEndian.Uint16(seg)
			row.I16 = int16(row.U16)
		}
		if len(seg) >= 4 {
			row.U32 = binary.LittleEndian.Uint32(seg)
			row.I32 = int32(row.U32)
			row.F32 = float64(math.Float32frombits(row.U32))
		}
		if len(seg) >= 8 {
			row.U64 = binary.LittleEndian.Uint64(seg)
			row.I64 = int64(row.U64)
			row.F64 = math.Float64frombits(row.U64)
			row.Ptr = formatHex(row.U64)
			if path, ok := regionOf(regions, row.U64); ok {
				row.IsPtr = true
				row.PtrTo = path
			}
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"addr": formatHex(base), "len": n, "step": step, "rows": rows,
	})
}

// regionOf returns the backing path of the region containing addr (or
// "(anon)" for an unnamed mapping) and whether addr falls inside any region.
func regionOf(regions []memRegion, addr uint64) (string, bool) {
	for _, rg := range regions {
		if addr >= rg.Start && addr < rg.End {
			if rg.Path == "" {
				return "(anon)", true
			}
			return rg.Path, true
		}
	}
	return "", false
}

const hexDigits = "0123456789ABCDEF"

func bytesToHex(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0xF])
	}
	return string(out)
}

func bytesASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
