// Package ccj implements the JSON value and canonical byte rules of CCJ-1.
package ccj

import (
	"bytes"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

const MaxDepth = 16
const MaxInteger int64 = 9007199254740991

// Parse accepts legal wire variations while refusing duplicate names and lossy values.
// Numbers are int64; objects are map[string]any and arrays are []any.
// malformed selects the registration or enrollment schema refusal.
func Parse(data []byte, malformed refusal.Code) (any, error) {
	if !utf8.Valid(data) {
		return nil, refusal.New(malformed)
	}
	p := parser{data: data, malformed: malformed}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(data) {
		return nil, p.fail()
	}
	return v, nil
}

type parser struct {
	data      []byte
	pos       int
	malformed refusal.Code
}

func (p *parser) fail() error { return refusal.New(p.malformed) }
func (p *parser) space() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}
func (p *parser) take(b byte) bool {
	if p.pos < len(p.data) && p.data[p.pos] == b {
		p.pos++
		return true
	}
	return false
}
func (p *parser) value(depth int) (any, error) {
	p.space()
	if p.pos == len(p.data) {
		return nil, p.fail()
	}
	switch p.data[p.pos] {
	case '{':
		if depth >= MaxDepth {
			return nil, p.fail()
		}
		p.pos++
		obj := make(map[string]any)
		p.space()
		if p.take('}') {
			return obj, nil
		}
		for {
			p.space()
			key, err := p.string()
			if err != nil {
				return nil, err
			}
			if _, ok := obj[key]; ok {
				return nil, p.fail()
			}
			p.space()
			if !p.take(':') {
				return nil, p.fail()
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj[key] = v
			p.space()
			if p.take('}') {
				return obj, nil
			}
			if !p.take(',') {
				return nil, p.fail()
			}
		}
	case '[':
		if depth >= MaxDepth {
			return nil, p.fail()
		}
		p.pos++
		arr := make([]any, 0)
		p.space()
		if p.take(']') {
			return arr, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
			p.space()
			if p.take(']') {
				return arr, nil
			}
			if !p.take(',') {
				return nil, p.fail()
			}
		}
	case '"':
		return p.string()
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case 'n':
		if p.literal("null") {
			return nil, nil
		}
	default:
		start := p.pos
		p.take('-')
		digits := p.pos
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == digits {
			return nil, p.fail()
		}
		token := string(p.data[start:p.pos])
		n, err := strconv.ParseInt(token, 10, 64)
		if err != nil || n < -MaxInteger || n > MaxInteger || token != strconv.FormatInt(n, 10) {
			return nil, p.fail()
		}
		return n, nil
	}
	return nil, p.fail()
}
func (p *parser) literal(s string) bool {
	if bytes.HasPrefix(p.data[p.pos:], []byte(s)) {
		p.pos += len(s)
		return true
	}
	return false
}
func (p *parser) hex4() (uint16, bool) {
	if len(p.data)-p.pos < 4 {
		return 0, false
	}
	var n uint16
	for range 4 {
		b := p.data[p.pos]
		p.pos++
		var v byte
		switch {
		case b >= '0' && b <= '9':
			v = b - '0'
		case b >= 'a' && b <= 'f':
			v = b - 'a' + 10
		case b >= 'A' && b <= 'F':
			v = b - 'A' + 10
		default:
			return 0, false
		}
		n = n*16 + uint16(v)
	}
	return n, true
}
func (p *parser) string() (string, error) {
	if !p.take('"') {
		return "", p.fail()
	}
	var out []byte
	for p.pos < len(p.data) {
		b := p.data[p.pos]
		p.pos++
		switch {
		case b == '"':
			return string(out), nil
		case b < 0x20:
			return "", p.fail()
		case b == '\\':
			if p.pos == len(p.data) {
				return "", p.fail()
			}
			escape := p.data[p.pos]
			p.pos++
			switch escape {
			case '"', '\\', '/':
				out = append(out, escape)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				u, ok := p.hex4()
				if !ok {
					return "", p.fail()
				}
				r := rune(u)
				if u >= 0xd800 && u <= 0xdbff {
					if !p.take('\\') || !p.take('u') {
						return "", p.fail()
					}
					low, ok := p.hex4()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return "", p.fail()
					}
					r = utf16.DecodeRune(r, rune(low))
				} else if u >= 0xdc00 && u <= 0xdfff {
					return "", p.fail()
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", p.fail()
			}
		default:
			out = append(out, b)
		}
	}
	return "", p.fail()
}

// Marshal emits canonical bytes for the value types returned by Parse.
func Marshal(v any, malformed refusal.Code) ([]byte, error) { return appendValue(nil, v, 0, malformed) }
func appendValue(out []byte, v any, depth int, code refusal.Code) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, refusal.New(code) }
	switch x := v.(type) {
	case nil:
		return append(out, "null"...), nil
	case bool:
		if x {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case int64:
		if x < -MaxInteger || x > MaxInteger {
			return fail()
		}
		return strconv.AppendInt(out, x, 10), nil
	case string:
		if !utf8.ValidString(x) {
			return fail()
		}
		return appendString(out, x), nil
	case []any:
		if depth >= MaxDepth {
			return fail()
		}
		out = append(out, '[')
		for i, elem := range x {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			out, err = appendValue(out, elem, depth+1, code)
			if err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case map[string]any:
		if depth >= MaxDepth {
			return fail()
		}
		names := make([]string, 0, len(x))
		for name := range x {
			if !utf8.ValidString(name) {
				return fail()
			}
			names = append(names, name)
		}
		// Lexicographic UTF-8 order equals scalar-value order for valid strings.
		sort.Strings(names)
		out = append(out, '{')
		for i, name := range names {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendString(out, name)
			out = append(out, ':')
			var err error
			out, err = appendValue(out, x[name], depth+1, code)
			if err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	default:
		return fail()
	}
}
func appendString(out []byte, s string) []byte {
	const hex = "0123456789abcdef"
	out = append(out, '"')
	for _, b := range []byte(s) {
		switch b {
		case '"', '\\':
			out = append(out, '\\', b)
		case '\b':
			out = append(out, `\b`...)
		case '\f':
			out = append(out, `\f`...)
		case '\n':
			out = append(out, `\n`...)
		case '\r':
			out = append(out, `\r`...)
		case '\t':
			out = append(out, `\t`...)
		default:
			if b < 32 {
				out = append(out, '\\', 'u', '0', '0', hex[b>>4], hex[b&15])
			} else {
				out = append(out, b)
			}
		}
	}
	return append(out, '"')
}
