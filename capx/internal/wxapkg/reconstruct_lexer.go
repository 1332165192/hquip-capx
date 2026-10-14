package wxapkg

// This is a bounded lexical reader, not a JavaScript runtime. It only recovers
// complete literal wrappers and leaves unsupported structures in the original
// bundle. Quotes, comments, regexes and template expressions are opaque to the
// delimiter matcher, so their braces cannot truncate a recovered module.
import (
	"strconv"
	"strings"
	"unicode/utf16"
)

type jsToken struct {
	start, end int
	text       string
	kind       byte
}

type jsReader struct {
	src           string
	i             int
	failed        bool
	regexAllowed  bool
	previous      string
	controls      []bool
	templateDepth int
}

func newJSReader(src string) *jsReader { return &jsReader{src: src, regexAllowed: true} }
func jsWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$' || c >= 0x80
}
func jsSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' }
func (r *jsReader) next() jsToken {
	for !r.failed && r.i < len(r.src) {
		c := r.src[r.i]
		if jsSpace(c) {
			r.i++
			continue
		}
		if c == '/' && r.i+1 < len(r.src) {
			if r.src[r.i+1] == '/' {
				for r.i < len(r.src) && r.src[r.i] != '\n' {
					r.i++
				}
				continue
			}
			if r.src[r.i+1] == '*' {
				end := strings.Index(r.src[r.i+2:], "*/")
				if end < 0 {
					r.failed = true
					return jsToken{}
				}
				r.i += end + 4
				continue
			}
		}
		start, kind := r.i, byte('p')
		switch {
		case c == '"' || c == '\'':
			kind = 's'
			r.i++
			closed := false
			for r.i < len(r.src) {
				if r.src[r.i] == '\\' {
					if r.i+2 < len(r.src) && r.src[r.i+1] == '\r' && r.src[r.i+2] == '\n' {
						r.i += 3
					} else {
						r.i += 2
					}
					continue
				}
				if r.src[r.i] == c {
					r.i++
					closed = true
					break
				}
				if r.src[r.i] == '\n' || r.src[r.i] == '\r' {
					break
				}
				r.i++
			}
			if !closed {
				r.failed = true
				return jsToken{}
			}
		case c == '`':
			kind = 'o'
			if !r.skipTemplate() {
				r.failed = true
				return jsToken{}
			}
		case c == '/' && r.regexAllowed:
			kind = 'o'
			r.i++
			closed, class := false, false
			for r.i < len(r.src) {
				ch := r.src[r.i]
				if ch == '\\' {
					r.i += 2
					continue
				}
				if ch == '\n' || ch == '\r' {
					break
				}
				if ch == '[' {
					class = true
				}
				if ch == ']' {
					class = false
				}
				r.i++
				if ch == '/' && !class {
					closed = true
					break
				}
			}
			if !closed {
				r.failed = true
				return jsToken{}
			}
			for r.i < len(r.src) && jsWord(r.src[r.i]) {
				r.i++
			}
		case jsWord(c):
			kind = 'w'
			r.i++
			for r.i < len(r.src) && (jsWord(r.src[r.i]) || r.src[r.i] >= '0' && r.src[r.i] <= '9') {
				r.i++
			}
		case c >= '0' && c <= '9':
			kind = 'n'
			r.i++
			for r.i < len(r.src) && (jsWord(r.src[r.i]) || r.src[r.i] >= '0' && r.src[r.i] <= '9' || r.src[r.i] == '.') {
				r.i++
			}
		default:
			r.i++
			if (c == '+' || c == '-') && r.i < len(r.src) && r.src[r.i] == c {
				r.i++
			}
		}
		if r.i > len(r.src) {
			r.failed = true
			return jsToken{}
		}
		t := jsToken{start: start, end: r.i, text: r.src[start:r.i], kind: kind}
		switch t.text {
		case "(":
			if len(r.controls) >= 128 {
				r.failed = true
				return jsToken{}
			}
			control := r.previous == "if" || r.previous == "while" || r.previous == "for" || r.previous == "with" || r.previous == "switch" || r.previous == "catch"
			r.controls = append(r.controls, control)
			r.regexAllowed = true
		case ")":
			r.regexAllowed = false
			if n := len(r.controls); n > 0 {
				r.regexAllowed = r.controls[n-1]
				r.controls = r.controls[:n-1]
			}
		case "]", ".", "++", "--":
			r.regexAllowed = false
		case "return", "throw", "case", "delete", "void", "typeof", "new", "in", "of", "yield", "await", "else", "do":
			r.regexAllowed = true
		default:
			r.regexAllowed = kind == 'p'
		}
		r.previous = t.text
		return t
	}
	return jsToken{}
}

func (r *jsReader) skipTemplate() bool {
	if r.templateDepth >= 64 {
		return false
	}
	r.i++
	for r.i < len(r.src) {
		switch r.src[r.i] {
		case '\\':
			r.i += 2
		case '`':
			r.i++
			return true
		case '$':
			if r.i+1 < len(r.src) && r.src[r.i+1] == '{' {
				inner := newJSReader(r.src)
				inner.i, inner.templateDepth = r.i+2, r.templateDepth+1
				depth := 1
				for depth > 0 {
					t := inner.next()
					if t.text == "" {
						return false
					}
					if t.text == "{" {
						depth++
					}
					if t.text == "}" {
						depth--
					}
					if depth > 128 {
						return false
					}
				}
				r.i = inner.i
			} else {
				r.i++
			}
		default:
			r.i++
		}
	}
	return false
}

type jsSpan struct{ start, end int }

// Opening '(' has already been read. Arguments stay bounded by this exact call.
func jsArguments(r *jsReader, open jsToken) ([]jsSpan, bool) {
	stack := []string{"("}
	start := open.end
	var args []jsSpan
	for {
		t := r.next()
		if t.text == "" {
			return nil, false
		}
		switch t.text {
		case "(", "[", "{":
			stack = append(stack, t.text)
			if len(stack) > 128 {
				return nil, false
			}
		case ")", "]", "}":
			if len(stack) == 0 {
				return nil, false
			}
			want := "("
			if t.text == "]" {
				want = "["
			}
			if t.text == "}" {
				want = "{"
			}
			if stack[len(stack)-1] != want {
				return nil, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return append(args, jsSpan{start, t.start}), true
			}
		case ",":
			if len(stack) == 1 {
				args = append(args, jsSpan{start, t.start})
				start = t.end
				if len(args) > 64 {
					return nil, false
				}
			}
		}
	}
}

func reconstructJS(src string) (modules, styles []File, skipped int) {
	r := newJSReader(src)
	previous := ""
	for {
		t := r.next()
		if t.text == "" {
			break
		}
		isCall := t.kind == 'w' && previous != "." && (t.text == "define" || t.text == "setCssToHead")
		previous = t.text
		if !isCall {
			continue
		}
		open := r.next()
		previous = open.text
		if open.text != "(" {
			continue
		}
		args, ok := jsArguments(r, open)
		previous = ")"
		if !ok {
			skipped++
			break
		}
		if t.text == "define" {
			if len(args) < 2 {
				skipped++
				continue
			}
			name, ok := literalString(src[args[0].start:args[0].end])
			body, complete := functionBody(src[args[1].start:args[1].end])
			if !ok || !complete {
				skipped++
				continue
			}
			if (strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".wxs")) && strings.TrimSpace(body) != "" {
				modules = append(modules, File{Name: "/" + strings.TrimLeft(name, "/"), Data: []byte(strings.TrimSpace(body))})
			}
		} else {
			if len(args) < 2 {
				skipped++
				continue
			}
			css, ok := literalCSS(src[args[0].start:args[0].end])
			name := ""
			for _, arg := range args[1:] {
				if value, found := cssPath(src[arg.start:arg.end]); found {
					name = value
					break
				}
			}
			if !ok || name == "" || css == "" {
				skipped++
				continue
			}
			name = strings.TrimPrefix(name, "./")
			if !strings.HasSuffix(name, ".wxss") {
				name += ".wxss"
			}
			styles = append(styles, File{Name: "/" + strings.TrimLeft(name, "/"), Data: []byte(css)})
		}
	}
	if r.failed {
		skipped++
	}
	return
}

func functionBody(src string) (string, bool) {
	r := newJSReader(src)
	if r.next().text != "function" {
		return "", false
	}
	t := r.next()
	if t.kind == 'w' {
		t = r.next()
	}
	if t.text != "(" {
		return "", false
	}
	if _, ok := jsArguments(r, t); !ok {
		return "", false
	}
	open := r.next()
	if open.text != "{" {
		return "", false
	}
	depth := 1
	for depth > 0 {
		t = r.next()
		if t.text == "" {
			return "", false
		}
		if t.text == "{" {
			depth++
		}
		if t.text == "}" {
			depth--
		}
		if depth > 128 {
			return "", false
		}
	}
	if r.next().text != "" || r.failed {
		return "", false
	}
	return src[open.end:t.start], true
}

func literalString(src string) (string, bool) {
	r := newJSReader(src)
	t := r.next()
	if t.kind != 's' || r.next().text != "" || r.failed {
		return "", false
	}
	return decodeJSString(t.text)
}

func cssPath(src string) (string, bool) {
	r := newJSReader(src)
	if r.next().text != "{" {
		return "", false
	}
	depth, previous, path, found := 1, "{", "", false
	for depth > 0 {
		t := r.next()
		if t.text == "" {
			return "", false
		}
		if depth == 1 && (previous == "{" || previous == ",") && (t.text == "path" || t.kind == 's') {
			key := t.text
			if t.kind == 's' {
				key, _ = decodeJSString(t.text)
			}
			if key == "path" {
				if r.next().text != ":" {
					return "", false
				}
				value := r.next()
				if value.kind != 's' {
					return "", false
				}
				var ok bool
				path, ok = decodeJSString(value.text)
				if !ok {
					return "", false
				}
				found = true
				separator := r.next()
				if separator.text == "}" {
					return path, r.next().text == "" && !r.failed
				}
				if separator.text != "," {
					return "", false
				}
				previous = ","
				continue
			}
		}
		if t.text == "{" || t.text == "[" || t.text == "(" {
			depth++
		}
		if t.text == "}" || t.text == "]" || t.text == ")" {
			depth--
		}
		previous = t.text
	}
	return path, found && r.next().text == "" && !r.failed
}

func literalCSS(src string) (string, bool) {
	r := newJSReader(src)
	if r.next().text != "[" {
		return "", false
	}
	var out strings.Builder
	for {
		t := r.next()
		if t.text == "]" {
			return out.String(), r.next().text == "" && !r.failed
		}
		switch {
		case t.kind == 's':
			decoded, ok := decodeJSString(t.text)
			if !ok {
				return "", false
			}
			out.WriteString(decoded)
		case t.text == "[":
			if r.next().text != "0" || r.next().text != "," {
				return "", false
			}
			value := r.next()
			number := value.text
			if number == "-" || number == "+" {
				value = r.next()
				number += value.text
			}
			if value.kind != 'n' {
				return "", false
			}
			if _, err := strconv.ParseFloat(number, 64); err != nil {
				return "", false
			}
			if r.next().text != "]" {
				return "", false
			}
			out.WriteString(number + "rpx")
		default:
			return "", false
		}
		t = r.next()
		if t.text == "]" {
			return out.String(), r.next().text == "" && !r.failed
		}
		if t.text != "," {
			return "", false
		}
	}
}

func decodeJSString(src string) (string, bool) {
	if len(src) < 2 || (src[0] != '"' && src[0] != '\'') || src[len(src)-1] != src[0] {
		return "", false
	}
	value := src[1 : len(src)-1]
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		i++
		if i >= len(value) {
			return "", false
		}
		switch value[i] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'v':
			out.WriteByte('\v')
		case '\n':
		case '\r':
			if i+1 < len(value) && value[i+1] == '\n' {
				i++
			}
		case 'x', 'u':
			n := 2
			if value[i] == 'u' {
				n = 4
			}
			if i+n >= len(value) {
				return "", false
			}
			number, err := strconv.ParseUint(value[i+1:i+1+n], 16, 32)
			if err != nil {
				return "", false
			}
			i += n
			rn := rune(number)
			if rn >= 0xD800 && rn <= 0xDBFF {
				if i+6 >= len(value) || value[i+1:i+3] != "\\u" {
					return "", false
				}
				low, err := strconv.ParseUint(value[i+3:i+7], 16, 16)
				if err != nil || low < 0xDC00 || low > 0xDFFF {
					return "", false
				}
				rn = utf16.DecodeRune(rn, rune(low))
				i += 6
			} else if rn >= 0xDC00 && rn <= 0xDFFF {
				return "", false
			}
			out.WriteRune(rn)
		case '0':
			if i+1 < len(value) && value[i+1] >= '0' && value[i+1] <= '9' {
				return "", false
			}
			out.WriteByte(0)
		default:
			if value[i] >= '1' && value[i] <= '9' {
				return "", false
			}
			out.WriteByte(value[i])
		}
	}
	return out.String(), true
}
