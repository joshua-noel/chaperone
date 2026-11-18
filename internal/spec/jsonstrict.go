package spec

import (
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting a hashed document may have (spec section 0).
const MaxDepth = 32

// maxSafeInteger is 2^53-1, the largest integer every JSON parser keeps exactly.
const maxSafeInteger = 9007199254740991

// JSONError reports why a document is not acceptable I-JSON.
type JSONError struct {
	Msg    string
	Offset int
}

func (e *JSONError) Error() string { return fmt.Sprintf("%s at offset %d", e.Msg, e.Offset) }

// ParseStrict parses a document that will be hashed or validated. It is JSON
// plus the I-JSON rules of RFC 8785 section 3.1 and the spec (section 0): it
// REJECTS duplicate member names, a number that is an integer outside +-(2^53-1)
// in any literal form (9007199254740993, 9007199254740993.0, 9.007199254740993e15,
// 1e20), a number that overflows a double, a lone surrogate, invalid UTF-8,
// nesting deeper than MaxDepth and trailing content.
//
// The result holds map[string]any, []any, string, float64, bool and nil, the
// same value model as the spec's reference loader (every number is a double).
func ParseStrict(data []byte) (any, error) {
	p := &strictParser{b: data}
	p.ws()
	v := p.value(0)
	if p.err == nil {
		p.ws()
		if p.i != len(p.b) {
			p.fail("unexpected trailing content")
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	return v, nil
}

type strictParser struct {
	b   []byte
	i   int
	err *JSONError
}

func (p *strictParser) fail(msg string) {
	if p.err == nil {
		p.err = &JSONError{Msg: msg, Offset: p.i}
	}
}

func (p *strictParser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *strictParser) peek() byte {
	if p.i < len(p.b) {
		return p.b[p.i]
	}
	return 0
}

func (p *strictParser) value(depth int) any {
	if p.err != nil {
		return nil
	}
	if depth > MaxDepth {
		p.fail(fmt.Sprintf("nesting deeper than %d", MaxDepth))
		return nil
	}
	p.ws()
	switch c := p.peek(); {
	case p.i >= len(p.b):
		p.fail("unexpected end of input")
		return nil
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	}
	for _, w := range [...]struct {
		word string
		v    any
	}{{"true", true}, {"false", false}, {"null", nil}} {
		if len(p.b)-p.i >= len(w.word) && string(p.b[p.i:p.i+len(w.word)]) == w.word {
			p.i += len(w.word)
			return w.v
		}
	}
	return p.number()
}

func (p *strictParser) object(depth int) any {
	p.i++
	obj := map[string]any{}
	p.ws()
	if p.peek() == '}' {
		p.i++
		return obj
	}
	for p.err == nil {
		p.ws()
		if p.peek() != '"' {
			p.fail("expected a string key")
			break
		}
		keyAt := p.i
		key := p.str()
		if p.err != nil {
			break
		}
		if _, dup := obj[key]; dup {
			p.i = keyAt
			p.fail(fmt.Sprintf("duplicate key '%s'", key))
			break
		}
		p.ws()
		if p.peek() != ':' || p.i >= len(p.b) {
			p.fail("expected ':'")
			break
		}
		p.i++
		obj[key] = p.value(depth + 1)
		if p.err != nil {
			break
		}
		p.ws()
		switch {
		case p.i < len(p.b) && p.b[p.i] == ',':
			p.i++
		case p.i < len(p.b) && p.b[p.i] == '}':
			p.i++
			return obj
		default:
			p.fail("expected ',' or '}'")
		}
	}
	return nil
}

func (p *strictParser) array(depth int) any {
	p.i++
	arr := []any{}
	p.ws()
	if p.peek() == ']' {
		p.i++
		return arr
	}
	for p.err == nil {
		arr = append(arr, p.value(depth+1))
		if p.err != nil {
			break
		}
		p.ws()
		switch {
		case p.i < len(p.b) && p.b[p.i] == ',':
			p.i++
		case p.i < len(p.b) && p.b[p.i] == ']':
			p.i++
			return arr
		default:
			p.fail("expected ',' or ']'")
		}
	}
	return nil
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

// u4 reads the four hex digits of a \u escape starting at offset at.
func (p *strictParser) u4(at int) (rune, bool) {
	if at+4 > len(p.b) {
		return 0, false
	}
	var r rune
	for _, c := range p.b[at : at+4] {
		h, ok := hexVal(c)
		if !ok {
			return 0, false
		}
		r = r<<4 | h
	}
	return r, true
}

func isHigh(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }
func isLow(r rune) bool  { return r >= 0xDC00 && r <= 0xDFFF }

func (p *strictParser) str() string {
	start := p.i
	p.i++
	var out []byte
	for {
		if p.i >= len(p.b) {
			p.i = start
			p.fail("unterminated string")
			return ""
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out)
		case c < 0x20:
			p.fail("control character in string")
			return ""
		case c == '\\':
			if p.i+1 >= len(p.b) {
				p.i = start
				p.fail("unterminated string")
				return ""
			}
			switch e := p.b[p.i+1]; e {
			case '"', '\\', '/':
				out = append(out, e)
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
				r, ok := p.u4(p.i + 2)
				if !ok {
					p.fail("invalid string")
					return ""
				}
				p.i += 4
				switch {
				case isHigh(r):
					low, ok := rune(0), false
					if p.i+7 < len(p.b) && p.b[p.i+2] == '\\' && p.b[p.i+3] == 'u' {
						low, ok = p.u4(p.i + 4)
					}
					if !ok || !isLow(low) {
						p.fail("string contains a lone surrogate")
						return ""
					}
					r = 0x10000 + (r-0xD800)<<10 + (low - 0xDC00)
					p.i += 6
				case isLow(r):
					p.fail("string contains a lone surrogate")
					return ""
				}
				out = utf8.AppendRune(out, r)
			default:
				p.fail("invalid string")
				return ""
			}
			p.i += 2
		default:
			r, size := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && size == 1 {
				p.fail("string is not valid UTF-8")
				return ""
			}
			out = append(out, p.b[p.i:p.i+size]...)
			p.i += size
		}
	}
}

// number scans -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)? and refuses
// integer values the reference loader refuses.
func (p *strictParser) number() any {
	start := p.i
	i := p.i
	digits := func() int {
		n := 0
		for i < len(p.b) && p.b[i] >= '0' && p.b[i] <= '9' {
			i++
			n++
		}
		return n
	}
	if i < len(p.b) && p.b[i] == '-' {
		i++
	}
	switch {
	case i < len(p.b) && p.b[i] == '0':
		i++
	case i < len(p.b) && p.b[i] >= '1' && p.b[i] <= '9':
		digits()
	default:
		p.fail("unexpected character")
		return nil
	}
	if i+1 < len(p.b) && p.b[i] == '.' && p.b[i+1] >= '0' && p.b[i+1] <= '9' {
		i++
		digits()
	}
	if i < len(p.b) && (p.b[i] == 'e' || p.b[i] == 'E') {
		j := i + 1
		if j < len(p.b) && (p.b[j] == '+' || p.b[j] == '-') {
			j++
		}
		if j < len(p.b) && p.b[j] >= '0' && p.b[j] <= '9' {
			i = j
			digits()
		}
	}
	lit := string(p.b[start:i])
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) {
		p.fail("number overflows a double")
		return nil
	}
	if unsafeInteger(f) {
		p.fail(fmt.Sprintf("number %s is an integer outside the safe range", lit))
		return nil
	}
	p.i = i
	return f
}

// unsafeInteger reports a double that is a whole number beyond +-(2^53-1).
// Every literal form of such a value would be rounded by some parser.
func unsafeInteger(f float64) bool {
	return math.Abs(f) > maxSafeInteger && f == math.Trunc(f)
}
