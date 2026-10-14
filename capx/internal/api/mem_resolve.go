package api

// CE-style address expressions: a saved cheat-table address can be a pointer
// path that survives ASLR, e.g. "game.exe+0x1234", "[[game.exe+0x10]+0x20]+8",
// or a plain "0x...". This resolver evaluates such an expression against the
// target's module map (name -> base) and a pointer reader (8-byte little-endian
// dereference). It is split from I/O so the parser is unit-testable.

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/memscan"
)

// resolvePath resolves a CE-style pointer path (a base address plus a chain of
// dereference offsets): start at base, then for each offset o compute
// addr = deref(addr) + o. The final addr is the value address. ok is false when
// any intermediate dereference fails.
func resolvePath(base uint64, offsets []uint64, read ptrReader) (uint64, bool) {
	addr := base
	for _, o := range offsets {
		v, ok := read(addr)
		if !ok {
			return 0, false
		}
		addr = v + o
	}
	return addr, true
}

// sessionPtrReader returns a ptrReader that dereferences 8-byte little-endian
// pointers through a live scan session.
func sessionPtrReader(sess memscan.Session) ptrReader {
	wd := 8
	if w := sess.PtrWidth(); w == 4 || w == 8 {
		wd = w
	}
	return func(addr uint64) (uint64, bool) {
		b := make([]byte, wd)
		n, err := sess.Read(addr, b)
		if err != nil || n != wd {
			return 0, false
		}
		if wd == 4 {
			return uint64(binary.LittleEndian.Uint32(b)), true
		}
		return binary.LittleEndian.Uint64(b), true
	}
}

// memResolve evaluates a CE-style address expression (module+offset / pointer
// chain) against the attached process and returns the final address, plus its
// live value when a value type is supplied.
func (s *Server) memResolve(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Expr string            `json:"expr"`
		Type memscan.ValueType `json:"type"`
	}
	if err := decodeBody(r, &req); err != nil || strings.TrimSpace(req.Expr) == "" {
		writeErr(w, http.StatusBadRequest, "expr required")
		return
	}
	e := s.extFor(sid)
	addr, err := resolveExpr(req.Expr, moduleMap(e.pid), sessionPtrReader(sess))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"expr": req.Expr, "addr": formatHex(addr)}
	if wd := req.Type.Width(); wd > 0 {
		buf := make([]byte, wd)
		if n, err := sess.Read(addr, buf); err == nil && n == wd {
			resp["value"] = decodeValue(req.Type, buf)
			resp["type_name"] = typeName(req.Type)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ptrReader dereferences a pointer-sized (8-byte LE) value at addr. ok is false
// when the address is unreadable.
type ptrReader func(addr uint64) (uint64, bool)

// resolveExpr evaluates a CE-style address expression. mods maps lower-cased
// module names (with and without extension) to their load base; read derefs a
// pointer. It returns the final address.
func resolveExpr(expr string, mods map[string]uint64, read ptrReader) (uint64, error) {
	p := &exprParser{s: strings.TrimSpace(expr), mods: mods, read: read}
	v, err := p.parseSum()
	if err != nil {
		return 0, err
	}
	p.skipSpaces()
	if p.pos != len(p.s) {
		return 0, fmt.Errorf("unexpected trailing input at %q", p.s[p.pos:])
	}
	return v, nil
}

type exprParser struct {
	s    string
	pos  int
	mods map[string]uint64
	read ptrReader
}

func (p *exprParser) skipSpaces() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

// parseSum parses term (('+'|'-') term)* with left-to-right evaluation.
func (p *exprParser) parseSum() (uint64, error) {
	v, err := p.parseTerm()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpaces()
		if p.pos >= len(p.s) {
			return v, nil
		}
		op := p.s[p.pos]
		if op != '+' && op != '-' {
			return v, nil
		}
		p.pos++
		rhs, err := p.parseTerm()
		if err != nil {
			return 0, err
		}
		if op == '+' {
			v += rhs
		} else {
			v -= rhs
		}
	}
}

// parseTerm parses a bracketed dereference, a module name, or a number.
func (p *exprParser) parseTerm() (uint64, error) {
	p.skipSpaces()
	if p.pos >= len(p.s) {
		return 0, fmt.Errorf("unexpected end of expression")
	}
	switch c := p.s[p.pos]; {
	case c == '[':
		p.pos++
		inner, err := p.parseSum()
		if err != nil {
			return 0, err
		}
		p.skipSpaces()
		if p.pos >= len(p.s) || p.s[p.pos] != ']' {
			return 0, fmt.Errorf("missing closing ']'")
		}
		p.pos++
		if p.read == nil {
			return 0, fmt.Errorf("no pointer reader available")
		}
		v, ok := p.read(inner)
		if !ok {
			return 0, fmt.Errorf("cannot dereference 0x%x", inner)
		}
		return v, nil
	case c == '(':
		p.pos++
		v, err := p.parseSum()
		if err != nil {
			return 0, err
		}
		p.skipSpaces()
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return 0, fmt.Errorf("missing closing ')'")
		}
		p.pos++
		return v, nil
	case isDigit(c):
		return p.parseNumber()
	case isIdentStart(c):
		return p.parseModule()
	default:
		return 0, fmt.Errorf("unexpected %q at offset %d", string(c), p.pos)
	}
}

// parseNumber parses a hex (0x...) or decimal literal.
func (p *exprParser) parseNumber() (uint64, error) {
	start := p.pos
	if strings.HasPrefix(strings.ToLower(p.s[p.pos:]), "0x") {
		p.pos += 2
		hs := p.pos
		for p.pos < len(p.s) && isHexDigit(p.s[p.pos]) {
			p.pos++
		}
		if p.pos == hs {
			return 0, fmt.Errorf("bad hex literal at %d", start)
		}
		return strconv.ParseUint(p.s[hs:p.pos], 16, 64)
	}
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("bad number at %d", start)
	}
	return strconv.ParseUint(p.s[start:p.pos], 10, 64)
}

// parseModule parses a module identifier (letters, digits, '.', '_', '-') and
// returns its load base.
func (p *exprParser) parseModule() (uint64, error) {
	start := p.pos
	for p.pos < len(p.s) && isIdentChar(p.s[p.pos]) {
		p.pos++
	}
	name := lowerASCII(p.s[start:p.pos])
	if p.mods == nil {
		return 0, fmt.Errorf("module %q referenced but no module map available", name)
	}
	base, ok := p.mods[name]
	if !ok {
		if i := lastDot(name); i > 0 {
			base, ok = p.mods[name[:i]]
		}
	}
	if !ok {
		return 0, fmt.Errorf("module %q not found in target", name)
	}
	return base, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-'
}
