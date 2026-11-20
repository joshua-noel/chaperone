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
