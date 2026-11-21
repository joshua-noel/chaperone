package tierglob_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/tierglob"
)

func TestValidateRefusesGlobsThatCanNeverMatch(t *testing.T) {
	for _, bad := range []string{
		"docs/caf\u00e9/**", "docs/\u65e5\u672c\u8a9e/**", "web/a~1/**", "docs/a#b.md", "docs/a$b/**", "docs/a;b/**",
		"docs/a{b}/**", "docs/a|b", "docs/a%b", "docs/a\tb", "docs/a:b", "docs/a!b", "docs/a\u200db", "docs/a\u00a0b",
	} {
		err := tierglob.Validate(bad)
		if err == nil {
			t.Errorf("%q accepted", bad)
		} else if !strings.Contains(err.Error(), strconv.Quote(bad)) || !strings.Contains(err.Error(), "always high") {
			t.Errorf("the refusal of %q does not name it and say what happens to such a path: %v", bad, err)
		}
	}
}

func TestValidateRefusesBadShapesAndSyntax(t *testing.T) {
	for _, bad := range []string{"", "/abs/**", `a\b`, "[x", "a/[/b"} {
		if err := tierglob.Validate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateAcceptsPlainGlobs(t *testing.T) {
	for _, ok := range []string{
		"docs/**", "**/*.sh", "a/**/b.go", "web/src/**/*.ts", "docs/[a-c]*.md", "docs/[^a]?.md", "Docs/Getting Started/**",
		"docs/v1.2/**", "x/a+b@c(1)[2],d=e_f-g/**", ".github/**", "**",
	} {
		if err := tierglob.Validate(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}

func TestPlainRune(t *testing.T) {
	for _, r := range "aZ09._-+@()[],= " {
		if !tierglob.PlainRune(r) {
			t.Errorf("%q is not plain", r)
		}
	}
	for _, r := range "~#$%&'!;`{}^|<>?*\"\t:/\\\u00e9\u017f\u200d" {
		if tierglob.PlainRune(r) {
			t.Errorf("%q is plain", r)
		}
	}
}

func TestValidateRefusesShapesThatCanNeverMatch(t *testing.T) {
	for name, bad := range map[string]string{
		"trailing slash": "docs/", "trailing slash after **": "docs/**/", "doubled slash": "docs//a", "dot component": "docs/./a",
		"dotdot component": "docs/../a", "dot only": ".", "dotdot only": "..", "leading space": "docs/ a", "trailing space": "docs/a ",
		"space after slash": "docs/ /a", "ends with a dot": "docs/a.", "star then dot": "docs/*.", "caret outside a class": "docs/a^b",
		"caret at the start": "^docs/**", "caret after a class": "docs/[a]^", "reversed range": "docs/[z-a]/**", "reversed digits": "x/[9-0]",
		"reversed in a negated class": "x/[^z-a]", "empty class": "docs/[]/a", "empty negated class": "docs/[^]/a", "class not closed": "docs/[ab",
		"class not closed after a range": "docs/[a-c",
	} {
		err := tierglob.Validate(bad)
		if err == nil {
			t.Errorf("%s: %q accepted", name, bad)
		} else if !strings.Contains(err.Error(), strconv.Quote(bad)) {
			t.Errorf("%s: the refusal does not name the glob: %v", name, err)
		}
	}
}

func TestValidateAcceptsClassesAndNegation(t *testing.T) {
	for _, ok := range []string{
		"docs/[a-c]*.md", "docs/[^a]?.md", "docs/[ab]/**", "docs/[a-cx-z]/**", "docs/[a^]/x", "docs/[1]/x",
		"app/?slug?/**", "**/[A-Z]*.md", "a.b/**", "x/a b/c",
	} {
		if err := tierglob.Validate(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}
