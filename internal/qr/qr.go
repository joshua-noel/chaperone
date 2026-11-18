// Package qr encodes a short text as a QR code (ISO/IEC 18004), for the one-time
// enrolment address the server console shows so the phone can read it with its
// camera instead of anyone typing a token (ADR-004 amendment 6 item 3).
//
// It is deliberately small: byte mode, error correction level M, versions 1 to
// 10 (up to 213 bytes), the eight masks chosen by the standard's penalty score,
// and an SVG writer. The standard library has no QR encoder and the
// dependency rules (ADR-001) ask for a reason to add a module; a few hundred
// lines that the tests check against a table-free decoder is the cheaper
// choice. Anything longer than 213 bytes is an error, not a silent downgrade.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// MaxBytes is the longest text [Encode] accepts.
const MaxBytes = 213

// Code is a QR symbol: Size x Size modules, true is dark. Modules[y][x].
type Code struct {
	Version int
	Mask    int
	Size    int
	Modules [][]bool
}

// ECC level M: per version, error correction codewords per block and the
// blocks as {count, data codewords} groups (ISO/IEC 18004 table 9).
type blockSpec struct {
	ecc    int
	groups [2][2]int // {blocks, data codewords per block}
}

var levelM = [...]blockSpec{
	1:  {10, [2][2]int{{1, 16}}},
	2:  {16, [2][2]int{{1, 28}}},
	3:  {26, [2][2]int{{1, 44}}},
	4:  {18, [2][2]int{{2, 32}}},
	5:  {24, [2][2]int{{2, 43}}},
	6:  {16, [2][2]int{{4, 27}}},
	7:  {18, [2][2]int{{4, 31}}},
	8:  {22, [2][2]int{{2, 38}, {2, 39}}},
	9:  {22, [2][2]int{{3, 36}, {2, 37}}},
	10: {26, [2][2]int{{4, 43}, {1, 44}}},
}

var alignment = [...][]int{
	1: {}, 2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

func (b blockSpec) dataWords() int {
	n := 0
	for _, g := range b.groups {
		n += g[0] * g[1]
	}
	return n
}

// Encode makes the QR code for text.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	if len(data) == 0 {
		return nil, errors.New("qr: nothing to encode")
	}
	ver := 0
	for v := 1; v < len(levelM); v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= 8*levelM[v].dataWords() {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, fmt.Errorf("qr: %d bytes is more than the %d this encoder holds", len(data), MaxBytes)
	}
	spec := levelM[ver]
	codewords := interleave(dataCodewords(data, ver), spec)

	size := 17 + 4*ver
	m := newMatrix(size)
	m.drawFunctionPatterns(ver)
	m.drawCodewords(codewords)

	best, bestScore := 0, -1
	for mask := 0; mask < 8; mask++ {
		m.applyMask(mask)
		m.drawFormat(mask)
		if s := m.penalty(); bestScore < 0 || s < bestScore {
			best, bestScore = mask, s
		}
		m.applyMask(mask) // masking is its own inverse
	}
	m.applyMask(best)
	m.drawFormat(best)

	c := &Code{Version: ver, Mask: best, Size: size, Modules: make([][]bool, size)}
	for y := range c.Modules {
		c.Modules[y] = append([]bool(nil), m.dark[y]...)
	}
	return c, nil
}

// SVG is the code as a self-contained SVG image with the four-module quiet zone
// the standard asks for. Its only content is paths the encoder made, so it is
// safe to embed.
func SVG(text string) (string, error) {
	c, err := Encode(text)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" role="img" aria-label="QR code of the enrolment address">`, n, n, n*6, n*6)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := range c.Size {
		for x := 0; x < c.Size; {
			if !c.Modules[y][x] {
				x++
				continue
			}
			run := 1
			for x+run < c.Size && c.Modules[y][x+run] {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// ---- the bit stream ----

type bitWriter struct {
	b []byte
	n int // bits written
}

func (w *bitWriter) put(v uint, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.b = append(w.b, 0)
		}
		if v>>uint(i)&1 == 1 {
			w.b[w.n/8] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

func dataCodewords(data []byte, ver int) []byte {
	capacity := levelM[ver].dataWords()
	var w bitWriter
	w.put(0b0100, 4) // byte mode
	if ver >= 10 {
		w.put(uint(len(data)), 16)
	} else {
		w.put(uint(len(data)), 8)
	}
	for _, c := range data {
		w.put(uint(c), 8)
	}
	w.put(0, min(4, 8*capacity-w.n)) // terminator
	w.put(0, (8-w.n%8)%8)            // to a byte boundary
	for pad := []byte{0xEC, 0x11}; len(w.b) < capacity; {
		w.b = append(w.b, pad[0])
		pad[0], pad[1] = pad[1], pad[0]
	}
	return w.b
}

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----

func gfMul(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x1D
		z ^= (y >> uint(i) & 1) * x
	}
	return z
}

func rsDivisor(degree int) []byte {
	out := make([]byte, degree)
	out[degree-1] = 1
	root := byte(1)
	for range degree {
		for j := range out {
			out[j] = gfMul(out[j], root)
			if j+1 < len(out) {
				out[j] ^= out[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return out
}

func rsRemainder(data, divisor []byte) []byte {
	out := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ out[0]
		copy(out, out[1:])
		out[len(out)-1] = 0
		for i := range out {
			out[i] ^= gfMul(divisor[i], factor)
		}
	}
	return out
}

// interleave splits the data into blocks, adds each block's error correction,
// and returns data codewords then error correction codewords, block by block.
func interleave(data []byte, s blockSpec) []byte {
	var blocks, ecc [][]byte
	div := rsDivisor(s.ecc)
	at := 0
	for _, g := range s.groups {
		for range g[0] {
			blk := data[at : at+g[1]]
			at += g[1]
			blocks = append(blocks, blk)
			ecc = append(ecc, rsRemainder(blk, div))
		}
	}
	var out []byte
	for i := 0; ; i++ {
		any := false
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
				any = true
			}
		}
		if !any {
			break
		}
	}
	for i := range s.ecc {
		for _, e := range ecc {
			out = append(out, e[i])
		}
	}
	return out
}

// ---- the matrix ----

type matrix struct {
	size int
	dark [][]bool
	fn   [][]bool // function modules: never data, never masked
}

func newMatrix(size int) *matrix {
	m := &matrix{size: size, dark: make([][]bool, size), fn: make([][]bool, size)}
	for i := range m.dark {
		m.dark[i] = make([]bool, size)
		m.fn[i] = make([]bool, size)
	}
	return m
}

func (m *matrix) set(x, y int, dark bool) {
	m.dark[y][x], m.fn[y][x] = dark, true
}

func (m *matrix) drawFunctionPatterns(ver int) {
	for i := range m.size { // timing
		m.set(6, i, i%2 == 0)
		m.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {m.size - 4, 3}, {3, m.size - 4}} { // finders with separators
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x < 0 || y < 0 || x >= m.size || y >= m.size {
					continue
				}
				d := max(abs(dx), abs(dy))
				m.set(x, y, d != 2 && d != 4)
			}
		}
	}
	al := alignment[ver]
	for i, cy := range al {
		for j, cx := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue // under a finder
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					m.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	m.drawFormat(0) // reserves the format modules; redrawn once the mask is chosen
	if ver >= 7 {
		rem := ver
		for range 12 {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := ver<<12 | rem
		for i := range 18 {
			bit := bits>>uint(i)&1 == 1
			a, b := m.size-11+i%3, i/3
			m.set(a, b, bit)
			m.set(b, a, bit)
		}
	}
}

// drawFormat writes the 15 format bits (level M, this mask) twice, and the
// always-dark module.
func (m *matrix) drawFormat(mask int) {
	data := 0<<3 | mask // level M is 00
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>uint(i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		m.set(8, i, bit(i))
	}
	m.set(8, 7, bit(6))
	m.set(8, 8, bit(7))
	m.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		m.set(14-i, 8, bit(i))
	}
	for i := range 8 {
		m.set(m.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		m.set(8, m.size-15+i, bit(i))
	}
	m.set(8, m.size-8, true)
}

// drawCodewords places the bits in the zigzag of the standard: two-module
// columns from the right, alternately upward and downward, skipping column 6.
func (m *matrix) drawCodewords(data []byte) {
	i := 0
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < m.size; vert++ {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = m.size - 1 - vert
				}
				if !m.fn[y][x] && i < len(data)*8 {
					m.dark[y][x] = data[i>>3]>>uint(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (m *matrix) applyMask(mask int) {
	for y := range m.size {
		for x := range m.size {
			var invert bool
			switch mask {
			case 0:
				invert = (x+y)%2 == 0
			case 1:
				invert = y%2 == 0
			case 2:
				invert = x%3 == 0
			case 3:
				invert = (x+y)%3 == 0
			case 4:
				invert = (x/3+y/2)%2 == 0
			case 5:
				invert = x*y%2+x*y%3 == 0
			case 6:
				invert = (x*y%2+x*y%3)%2 == 0
			case 7:
				invert = ((x+y)%2+x*y%3)%2 == 0
			}
			if invert && !m.fn[y][x] {
				m.dark[y][x] = !m.dark[y][x]
			}
		}
	}
}

// penalty is the standard's mask score: runs, 2x2 blocks, finder-like
// patterns and dark balance.
func (m *matrix) penalty() int {
	n := m.size
	score := 0
	line := func(get func(i int) bool) {
		run := 1
		for i := 1; i < n; i++ {
			if get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				score += 3 + run - 5
			}
			run = 1
		}
		if run >= 5 {
			score += 3 + run - 5
		}
		// 1:1:3:1:1 finder-like pattern with four light modules on a side.
		for i := 0; i+11 <= n; i++ {
			a := [11]bool{}
			for k := range a {
				a[k] = get(i + k)
			}
			pat := [7]bool{true, false, true, true, true, false, true}
			if [7]bool(a[0:7]) == pat && !a[7] && !a[8] && !a[9] && !a[10] {
				score += 40
			}
			if [7]bool(a[4:11]) == pat && !a[0] && !a[1] && !a[2] && !a[3] {
				score += 40
			}
		}
	}
	for y := range n {
		line(func(i int) bool { return m.dark[y][i] })
	}
	for x := range n {
		line(func(i int) bool { return m.dark[i][x] })
	}
	for y := 0; y+1 < n; y++ {
		for x := 0; x+1 < n; x++ {
			c := m.dark[y][x]
			if c == m.dark[y][x+1] && c == m.dark[y+1][x] && c == m.dark[y+1][x+1] {
				score += 3
			}
		}
	}
	dark := 0
	for y := range m.dark {
		for _, d := range m.dark[y] {
			if d {
				dark++
			}
		}
	}
	total := n * n
	// ceil(|dark% - 50| / 5) - 1 steps of ten points.
	score += ((abs(dark*20-total*10)+total-1)/total - 1) * 10
	return score
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
