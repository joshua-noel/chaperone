package ops

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// examples makes concrete paths that a glob matches: `**` stands for no directory or for one, and each `*` for
// nothing or for "x" (an empty name is skipped).
func examples(glob string) []string {
	out := []string{""}
	segs := strings.Split(glob, "/")
	for i, seg := range segs {
		var next []string
		for _, prefix := range out {
			join := func(s string) string {
				if prefix == "" && i == 0 {
					return s
				}
				return prefix + "/" + s
			}
			switch {
			case seg == "**" && i == len(segs)-1:
				next = append(next, join("x"))
			case seg == "**":
				next = append(next, prefix, join("d"))
			case strings.Contains(seg, "*"):
				for _, fill := range []string{"", "x"} {
					if s := strings.ReplaceAll(seg, "*", fill); s != "" && s != "." {
						next = append(next, join(s))
					}
				}
			default:
				next = append(next, join(seg))
			}
		}
		out = next
	}
	var clean []string
	for _, p := range out {
		if p != "" && !strings.HasPrefix(p, "/") {
			clean = append(clean, p)
		}
	}
	return clean
}

var plainSegmentRE = regexp.MustCompile(`^[A-Za-z0-9._+@()\[\],=-]([A-Za-z0-9._+@()\[\],= -]*[A-Za-z0-9._+@()\[\],=-])?$`)

// plainByTheRule is the rule written a second time, on its own: every component is ASCII from the allowed set, does not
// start or end with a space, does not end with a dot, has no "~", and is not empty, "." or "..".
func plainByTheRule(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if !plainSegmentRE.MatchString(seg) || seg == "." || seg == ".." || strings.HasSuffix(seg, ".") || strings.Contains(seg, "~") {
			return false
		}
	}
	return true
}

// shortForms are the 8.3 forms Windows gives a long name: the first six characters, "~N", the extension.
func shortForm(p string, n int) string {
	d, f := "", p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		d, f = p[:i+1], p[i+1:]
	}
	base, ext := f, ""
	if i := strings.LastIndexByte(f, '.'); i > 0 {
		base, ext = f[:i], f[i:]
	}
	base = strings.ToUpper(strings.ReplaceAll(strings.TrimLeft(base, "."), ".", ""))
	if len(base) > 6 {
		base = base[:6]
	}
	if len(ext) > 4 {
		ext = ext[:4]
	}
	return d + base + "~" + string(rune('0'+n)) + strings.ToUpper(ext)
}

// TestLowIsAStrictAllowListOnTheFormOfAPath: take an example of every protected and medium rule, edit it at random
// (insert, replace or append a rune from a wide range, change case, add or remove dots, spaces and "~N"), and
// whenever the result scores low it must be plain by the rule above and must not read as a protected or medium example
// (lower-cased, equal to one, or the 8.3 form of one). A fixed seed: a failure repeats.
func TestLowIsAStrictAllowListOnTheFormOfAPath(t *testing.T) {
	var protected []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			protected = append(protected, p)
		}
	}
	for _, g := range append(append([]string(nil), baselineHigh...), baselineMedium...) {
		for _, p := range examples(g) {
			add(p)
			add("sub/" + p)
		}
	}
	for _, p := range []string{"agents.md", "claude.md", "requirements.txt", "constraints.txt", "pyproject.toml", ".github/copilot-instructions.md", "CODEOWNERS", ".gitattributes", "internal/app/app.go"} {
		add(p)
	}
	if len(protected) < 100 {
		t.Fatalf("only %d examples of the protected and medium rules", len(protected))
	}
	protectedLower := map[string]bool{}
	short := map[string]bool{}
	for _, p := range protected {
		protectedLower[strings.ToLower(p)] = true
		for n := 1; n <= 3; n++ {
			short[shortForm(p, n)] = true
		}
	}

	g := PRTierGlobs{}
	rng := rand.New(rand.NewPCG(20261119, 0x9e3779b97f4a7c15))
	special := []rune{0x017f, 0xfb00, 0xfb05, 0xfb06, 0x0131, 0x0130, 0x212a, 0x00df, 0x1e9e, 0x200b, 0x200c, 0x200d, 0x202e, 0xfeff, 0x3164, 0x034f, 0xfe0f, 0xe0041, 0xe0100, 0x00a0, 0xff0e, 0x2024, 0x2215, 0xff0f, 0x00ad, 0}
	randRune := func() rune {
		switch rng.IntN(5) {
		case 0:
			return rune(0x20 + rng.IntN(0x5f)) // printable ASCII, every punctuation mark
		case 1:
			return special[rng.IntN(len(special))]
		case 2:
			return rune(0x80 + rng.IntN(0x800)) // Latin, Greek, Cyrillic, Hebrew, Arabic
		case 3:
			return rune(rng.IntN(0x30000))
		}
		return rune(rng.IntN(0x80)) // controls, too
	}
	mutate := func(p string) string {
		r := []rune(p)
		switch rng.IntN(9) {
		case 0: // insert
			i := rng.IntN(len(r) + 1)
			r = append(r[:i], append([]rune{randRune()}, r[i:]...)...)
		case 1: // replace
			r[rng.IntN(len(r))] = randRune()
		case 2: // append
			r = append(r, randRune())
		case 3: // change case
			for i := range r {
				if rng.IntN(2) == 0 {
					if s := strings.ToUpper(string(r[i])); len([]rune(s)) == 1 {
						r[i] = []rune(s)[0]
					}
				}
			}
		case 4: // dots
			if rng.IntN(2) == 0 {
				r = append(r, '.')
			} else if i := strings.IndexRune(string(r), '.'); i >= 0 {
				r = []rune(string(r)[:i] + string(r)[i+1:])
			}
		case 5: // spaces
			i := rng.IntN(len(r) + 1)
			r = append(r[:i], append([]rune{' '}, r[i:]...)...)
		case 6: // "~N"
			return shortForm(p, 1+rng.IntN(9))
		case 7: // "~N" somewhere
			i := rng.IntN(len(r) + 1)
			r = append(r[:i], append([]rune("~1"), r[i:]...)...)
		case 8: // strip one rune
			i := rng.IntN(len(r))
			r = append(r[:i], r[i+1:]...)
		}
		return string(r)
	}

	const cases = 250000
	low := 0
	for n := 0; n < cases; n++ {
		p := protected[rng.IntN(len(protected))]
		for k := rng.IntN(3); k >= 0; k-- {
			if p != "" {
				p = mutate(p)
			}
		}
		if p == "" || g.ClassifyPath(p) != TierLow {
			continue
		}
		low++
		if !plainByTheRule(p) {
			t.Fatalf("case %d: %q scores low but is not plain by the rule", n, p)
		}
		lower := strings.ToLower(p)
		if protectedLower[lower] {
			t.Fatalf("case %d: %q scores low but is a protected or medium example", n, p)
		}
		if short[strings.ToUpper(p)] || short[p] {
			t.Fatalf("case %d: %q scores low but is the 8.3 form of a protected or medium example", n, p)
		}
	}
	if low < 1000 {
		t.Errorf("only %d of %d cases scored low: the test is not reaching the allow-list", low, cases)
	}
	t.Logf("%d cases, %d scored low, none of them a protected or medium name", cases, low)
}

// Test-path treatment is unchanged for plain names and never applies to a name outside the form.
func TestTestPathTreatmentNeedsAPlainName(t *testing.T) {
	g := PRTierGlobs{}
	if r := g.Classify([]PRFile{{Path: "tests/foo_test.go", Status: "removed"}}); r.Tier != TierMedium || !r.TestsWeakened {
		t.Errorf("a removed plain test file = %+v, want medium and weakened", r)
	}
	if r := g.Classify([]PRFile{{Path: "tests/foo_test.go", Status: "modified", Changes: 1, Patch: "+t.Skip()\n"}}); r.Tier != TierMedium || !r.TestsWeakened {
		t.Errorf("a skipped plain test = %+v, want medium and weakened", r)
	}
	if r := g.Classify([]PRFile{{Path: "tests/foo_test.go", Status: "modified", Changes: 1, Patch: "+x := 1\n"}}); r.Tier != TierLow {
		t.Errorf("an edited plain test = %+v, want low", r)
	}
	for _, p := range []string{"tests/foo~1_test.go", "tests/f\u00f6o_test.go", "tests/foo_test.go.", "tests/fo\u200do_test.go", "TESTS~1/a_test.go"} {
		if isTestPath(p) {
			t.Errorf("isTestPath(%q) is true", p)
		}
		if r := g.Classify([]PRFile{{Path: p, Status: "removed"}}); r.Tier != TierHigh {
			t.Errorf("a removed %q = %s, want high", p, r.Tier)
		}
	}
}
