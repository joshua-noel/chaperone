package qr

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The golden hashes were produced by this encoder and then read back with an
// independent decoder (zxing-cpp) at every version from 1 to 10, so a change
// that alters a symbol has to be a conscious one.
func TestGoldenSymbols(t *testing.T) {
	for _, g := range []struct {
		text    string
		version int
		sha     string
	}{
		{"a", 1, "2e7add7dfd3288d4ed23295399f43abf38be57f9a3df265ce870eb6fa468237e"},
		{"https://pc.tail1234.ts.net/enroll#abcdefghijklmnopqrstuv", 4, "c6bdfcfecc358b6a1b3e759d8977c0a0e71f53aaf7fd2eac41df43044c9db168"},
	} {
		c, err := Encode(g.text)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version != g.version || c.Size != 17+4*g.version {
			t.Fatalf("%q: version %d size %d", g.text, c.Version, c.Size)
		}
		if got := hash(c); got != g.sha {
			t.Fatalf("%q: symbol hash %s, want %s", g.text, got, g.sha)
		}
	}
}

func hash(c *Code) string {
	var b strings.Builder
	for _, row := range c.Modules {
		for _, d := range row {
			if d {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// decode reads a symbol the way a scanner does: both format copies, unmask,
// codewords in the zigzag, every block's Reed-Solomon syndromes, then the byte-mode payload.
func decode(t *testing.T, c *Code) string {
	t.Helper()
	n := c.Size
	at := func(x, y int) int {
		if c.Modules[y][x] {
			return 1
		}
		return 0
	}
	// Format information, both copies.
	var f1, f2 int
	for i := range 15 {
		var x1, y1, x2, y2 int
		switch {
		case i <= 5:
			x1, y1 = 8, i
		case i == 6:
			x1, y1 = 8, 7
		case i == 7:
			x1, y1 = 8, 8
		case i == 8:
			x1, y1 = 7, 8
		default:
			x1, y1 = 14-i, 8
		}
		if i < 8 {
			x2, y2 = n-1-i, 8
		} else {
			x2, y2 = 8, n-15+i
		}
		f1 |= at(x1, y1) << i
		f2 |= at(x2, y2) << i
	}
	if f1 != f2 {
		t.Fatalf("the two format copies differ: %015b %015b", f1, f2)
	}
	data := (f1 ^ 0x5412) >> 10
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	if (data<<10|rem)^0x5412 != f1 {
		t.Fatalf("format bits %015b fail their BCH check", f1)
	}
	if data>>3 != 0 {
		t.Fatalf("error correction level bits %02b, want 00 (M)", data>>3)
	}
	mask := data & 7
	if mask != c.Mask {
		t.Fatalf("format says mask %d, encoder says %d", mask, c.Mask)
	}

	// Unmask a copy and read the codewords.
	m := newMatrix(n)
	m.drawFunctionPatterns(c.Version)
	for y := range n {
		for x := range n {
			m.dark[y][x] = c.Modules[y][x]
		}
	}
	m.applyMask(mask)
	var bits []int
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range n {
			for j := range 2 {
				x, y := right-j, vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !m.fn[y][x] {
					if m.dark[y][x] {
						bits = append(bits, 1)
					} else {
						bits = append(bits, 0)
					}
				}
			}
		}
	}
	spec := levelM[c.Version]
	total := spec.dataWords() + spec.ecc*(spec.groups[0][0]+spec.groups[1][0])
	if len(bits) < total*8 || len(bits)-total*8 > 7 {
		t.Fatalf("%d data modules for %d codewords", len(bits), total)
	}
	words := make([]byte, total)
	for i := range words {
		for k := range 8 {
			words[i] = words[i]<<1 | byte(bits[i*8+k])
		}
	}

	// De-interleave and check every block.
	var lens []int
	for _, g := range spec.groups {
		for range g[0] {
			lens = append(lens, g[1])
		}
	}
	blocks := make([][]byte, len(lens))
	pos := 0
	for i := 0; ; i++ {
		more := false
		for b := range blocks {
			if i < lens[b] {
				blocks[b] = append(blocks[b], words[pos])
				pos++
				more = true
			}
		}
		if !more {
			break
		}
	}
	for range spec.ecc {
		for b := range blocks {
			blocks[b] = append(blocks[b], words[pos])
			pos++
		}
	}
	var payload []byte
	for b, blk := range blocks {
		// A valid codeword polynomial is zero at alpha^0 .. alpha^(ecc-1).
		alpha := byte(1)
		for i := range spec.ecc {
			var acc byte
			for _, w := range blk {
				acc = gfMul(acc, alpha) ^ w
			}
			if acc != 0 {
				t.Fatalf("block %d: syndrome %d is %#x, not zero", b, i, acc)
			}
			alpha = gfMul(alpha, 2)
		}
		payload = append(payload, blk[:lens[b]]...)
	}

	// Byte mode: 0100, count, bytes.
	r := bitReader{b: payload}
	if mode := r.get(4); mode != 0b0100 {
		t.Fatalf("mode %04b, want byte mode", mode)
	}
	countBits := 8
	if c.Version >= 10 {
		countBits = 16
	}
	out := make([]byte, r.get(countBits))
	for i := range out {
		out[i] = byte(r.get(8))
	}
	return string(out)
}

type bitReader struct {
	b []byte
	n int
}

func (r *bitReader) get(bits int) int {
	v := 0
	for range bits {
		v = v<<1 | int(r.b[r.n/8]>>(7-uint(r.n%8))&1)
		r.n++
	}
	return v
}

func TestEncodeDecodesAtEveryVersion(t *testing.T) {
	seen := map[int]bool{}
	for n := 1; n <= MaxBytes; n++ {
		text := strings.Repeat("Zq9#/", n)[:n]
		c, err := Encode(text)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		seen[c.Version] = true
		if got := decode(t, c); got != text {
			t.Fatalf("%d bytes: decoded %q", n, got)
		}
	}
	for v := 1; v <= 10; v++ {
		if !seen[v] {
			t.Fatalf("version %d was never produced", v)
		}
	}
}

func TestEncodeRefusesWhatItCannotHold(t *testing.T) {
	if _, err := Encode(""); err == nil {
		t.Fatal("empty text accepted")
	}
	if _, err := Encode(strings.Repeat("x", MaxBytes+1)); err == nil {
		t.Fatal("a text over the capacity was accepted")
	}
	if _, err := Encode(strings.Repeat("x", MaxBytes)); err != nil {
		t.Fatalf("the capacity itself was refused: %v", err)
	}
}

func TestFunctionPatterns(t *testing.T) {
	c, err := Encode("https://pc.tail1234.ts.net/enroll#abcdefghijklmnopqrstuv")
	if err != nil {
		t.Fatal(err)
	}
	n := c.Size
	// Three finders: a dark ring, a light ring and a dark 3x3 centre.
	for _, o := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		for dy := range 7 {
			for dx := range 7 {
				d := max(abs(dx-3), abs(dy-3))
				if want := d != 2; c.Modules[o[1]+dy][o[0]+dx] != want {
					t.Fatalf("finder at %v module (%d,%d) = %v", o, dx, dy, !want)
				}
			}
		}
	}
	for i := 8; i < n-8; i++ { // timing
		if c.Modules[6][i] != (i%2 == 0) || c.Modules[i][6] != (i%2 == 0) {
			t.Fatalf("timing pattern broken at %d", i)
		}
	}
	if !c.Modules[n-8][8] {
		t.Fatal("the always-dark module is light")
	}
}

func TestSVGIsSelfContained(t *testing.T) {
	s, err := SVG("https://pc.tail1234.ts.net/enroll#abcdefghijklmnopqrstuv")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script", "href", "onload", "<image", "javascript:", "<style"} {
		if strings.Contains(s, bad) {
			t.Fatalf("the SVG contains %q", bad)
		}
	}
	if !strings.HasPrefix(s, "<svg ") || !strings.HasSuffix(s, "</svg>") {
		t.Fatalf("not one svg element: %.60s ... %s", s, s[len(s)-20:])
	}
	if _, err := SVG(strings.Repeat("x", MaxBytes+1)); err == nil {
		t.Fatal("an over-long text was drawn")
	}
}
