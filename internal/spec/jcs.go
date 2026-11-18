package spec

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JCS returns the RFC 8785 canonical form of a document tree: map[string]any,
// []any, string, bool, nil, float64, int and int64. It matches the spec's
// reference (src/hashing.mjs) byte for byte: object members sorted by UTF-16
// code units, numbers in ECMAScript form (so -0 is 0 and 1e-7 is 1e-7),
// strings escaped the way JSON.stringify does. It refuses what a hash must
// never bind: a non-finite number, an integer outside +-(2^53-1), a string
// that is not valid UTF-8, nesting deeper than MaxDepth, any other Go type.
func JCS(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := jcsValue(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func jcsValue(b *bytes.Buffer, v any, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("JCS input is nested deeper than %d", MaxDepth)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return jcsString(b, x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("JCS cannot encode a non-finite number")
		}
		if unsafeInteger(x) {
			return fmt.Errorf("JCS input has an integer outside the safe range")
		}
		b.WriteString(esNumber(x))
	case int:
		return jcsInt(b, int64(x))
	case int64:
		return jcsInt(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsValue(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := jcsValue(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("JCS cannot encode a value of type %T", v)
	}
	return nil
}

func jcsInt(b *bytes.Buffer, n int64) error {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return fmt.Errorf("JCS input has an integer outside the safe range")
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// lessUTF16 orders strings by UTF-16 code units, as RFC 8785 section 3.2.3
// requires. UTF-8 byte order differs for characters above U+FFFF against the
// range U+E000-U+FFFF.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := range min(len(ua), len(ub)) {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

// jcsString writes s as JSON.stringify does: only the quote, the backslash and
// the control characters below U+0020 are escaped.
func jcsString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("JCS cannot encode a string that is not valid UTF-8")
	}
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return nil
}

// esNumber formats a finite double as ECMAScript Number::toString does
// (RFC 8785 section 3.2.2.3).
func esNumber(f float64) string {
	if f == 0 {
		return "0" // also -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-trip digits: d.ddde+XX.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := mant[:1]
	if len(mant) > 2 {
		digits += mant[2:]
	}
	x, _ := strconv.Atoi(exp)
	k, n := len(digits), x+1 // value = 0.digits * 10^n
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + zeros(n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + zeros(-n) + digits
	default:
		ex := n - 1
		es := "+"
		if ex < 0 {
			es, ex = "-", -ex
		}
		if k == 1 {
			s = digits + "e" + es + strconv.Itoa(ex)
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ex)
		}
	}
	return sign + s
}

func zeros(n int) string { return strings.Repeat("0", n) }
