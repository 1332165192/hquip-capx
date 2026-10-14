package decode

import (
	"fmt"
	"strconv"
	"strings"
)

// A small display-filter language for the HTTP history (Wireshark-ish):
//
//	host == api.example.com
//	status >= 400 and method == POST
//	url contains "/admin" or mime contains json
//	host != localhost and not status == 200
//
// Supported fields: host, method, url, status, mime, scheme. Operators:
// == != contains > >= < <= (numeric compares only valid on status). Boolean
// glue: and / or / not, with parentheses. Strings may be quoted or bare.

// FilterFields is the value bag a filter is evaluated against.
type FilterFields struct {
	Host   string
	Method string
	URL    string
	MIME   string
	Scheme string
	Status int
}

// Filter is a compiled display filter.
type Filter struct{ root filterNode }

type filterNode interface{ eval(f FilterFields) bool }

// CompileFilter parses a display-filter expression. An empty expression matches
// everything.
func CompileFilter(expr string) (*Filter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return &Filter{root: trueNode{}}, nil
	}
	p := &filterParser{toks: tokenizeFilter(expr)}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q", p.toks[p.pos])
	}
	return &Filter{root: n}, nil
}

// Match reports whether the fields satisfy the filter.
func (f *Filter) Match(ff FilterFields) bool { return f.root.eval(ff) }

// --- AST nodes ---

type trueNode struct{}

func (trueNode) eval(FilterFields) bool { return true }

type notNode struct{ x filterNode }

func (n notNode) eval(f FilterFields) bool { return !n.x.eval(f) }

type andNode struct{ a, b filterNode }

func (n andNode) eval(f FilterFields) bool { return n.a.eval(f) && n.b.eval(f) }

type orNode struct{ a, b filterNode }

func (n orNode) eval(f FilterFields) bool { return n.a.eval(f) || n.b.eval(f) }

type cmpNode struct {
	field string
	op    string
	val   string
}

func (n cmpNode) eval(f FilterFields) bool {
	if n.field == "status" {
		got := f.Status
		want, err := strconv.Atoi(n.val)
		if err == nil {
			switch n.op {
			case "==":
				return got == want
			case "!=":
				return got != want
			case ">":
				return got > want
			case ">=":
				return got >= want
			case "<":
				return got < want
			case "<=":
				return got <= want
			}
		}
	}
	got := strings.ToLower(n.fieldVal(f))
	want := strings.ToLower(n.val)
	switch n.op {
	case "==":
		return got == want
	case "!=":
		return got != want
	case "contains":
		return strings.Contains(got, want)
	}
	return false
}

func (n cmpNode) fieldVal(f FilterFields) string {
	switch n.field {
	case "host":
		return f.Host
	case "method":
		return f.Method
	case "url":
		return f.URL
	case "mime":
		return f.MIME
	case "scheme":
		return f.Scheme
	case "status":
		return strconv.Itoa(f.Status)
	}
	return ""
}

// --- parser ---

type filterParser struct {
	toks []string
	pos  int
}

func (p *filterParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *filterParser) parseOr() (filterNode, error) {
	n, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.pos++
		rhs, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		n = orNode{n, rhs}
	}
	return n, nil
}

func (p *filterParser) parseAnd() (filterNode, error) {
	n, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.pos++
		rhs, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		n = andNode{n, rhs}
	}
	return n, nil
}

func (p *filterParser) parseUnary() (filterNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.pos++
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	if p.peek() == "(" {
		p.pos++
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing ')'")
		}
		p.pos++
		return n, nil
	}
	return p.parseCmp()
}

var filterFields = map[string]bool{"host": true, "method": true, "url": true, "status": true, "mime": true, "scheme": true}
var filterOps = map[string]bool{"==": true, "!=": true, "contains": true, ">": true, ">=": true, "<": true, "<=": true}

func (p *filterParser) parseCmp() (filterNode, error) {
	if p.pos+3 > len(p.toks) {
		return nil, fmt.Errorf("incomplete comparison")
	}
	field := strings.ToLower(p.toks[p.pos])
	op := strings.ToLower(p.toks[p.pos+1])
	val := unquote(p.toks[p.pos+2])
	if !filterFields[field] {
		return nil, fmt.Errorf("unknown field %q", field)
	}
	if !filterOps[op] {
		return nil, fmt.Errorf("unknown operator %q", op)
	}
	p.pos += 3
	return cmpNode{field: field, op: op, val: val}, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// tokenizeFilter splits an expression into tokens: parens, operators, quoted
// strings, and bare words.
func tokenizeFilter(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(s) && s[j] != c {
				j++
			}
			toks = append(toks, s[i:min(j+1, len(s))])
			i = j + 1
		case c == '=' || c == '!' || c == '<' || c == '>':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, s[i:i+2])
				i += 2
			} else {
				toks = append(toks, string(c))
				i++
			}
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t()=!<>\"'", rune(s[j])) {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks
}
