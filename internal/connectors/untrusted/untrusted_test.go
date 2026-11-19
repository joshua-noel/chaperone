package untrusted_test

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
)

func TestCleanTextIsReturnedUnchanged(t *testing.T) {
	for _, s := range []string{"", "plain", "src/main.go", "line one\nline two\twith a tab", "caf\u00e9 \u65e5\u672c\u8a9e \U0001F600"} {
		if got := untrusted.Strip(s); got != s {
			t.Errorf("Strip(%q) = %q", s, got)
		}
		if got := untrusted.Clean(s, 1000); got != s {
			t.Errorf("Clean(%q) = %q", s, got)
		}
	}
	if got := untrusted.Line("src/main.go"); got != "src/main.go" {
		t.Errorf("Line = %q", got)
	}
}

func TestHostileCharactersAreRemoved(t *testing.T) {
	hostile := []rune{
		0x00, 0x07, 0x08, 0x1b, 0x7f, 0x85, 0x9b,
		0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff, 0x061c, 0x00ad, 0xe000,
	}
	for _, r := range hostile {
		in := "a" + string(r) + "b"
		for name, got := range map[string]string{
			"Strip": untrusted.Strip(in), "Line": untrusted.Line(in), "Clean": untrusted.Clean(in, 100),
		} {
			if got != "a b" {
				t.Errorf("%s(U+%04X) = %q, want the character replaced by one space", name, r, got)
			}
		}
	}
}

func TestCarriageReturnIsDropped(t *testing.T) {
	if got := untrusted.Strip("one\r\ntwo\rthree"); got != "one\ntwothree" {
		t.Errorf("Strip = %q", got)
	}
}

func TestLineKeepsNoLineBreak(t *testing.T) {
	if got := untrusted.Line("a\nb\tc"); got != "a b c" {
		t.Errorf("Line = %q", got)
	}
	if got := untrusted.Strip("a\nb\tc"); got != "a\nb\tc" {
		t.Errorf("Strip = %q", got)
	}
}

func TestInvalidUTF8IsDropped(t *testing.T) {
	if got := untrusted.Strip("a\xffb"); got != "ab" {
		t.Errorf("Strip = %q", got)
	}
}

func TestCleanCapsOnARuneBoundary(t *testing.T) {
	got := untrusted.Clean(strings.Repeat("\u00e9", 50), 21)
	if len(got) > 21 || !strings.HasSuffix(got, "...") {
		t.Errorf("Clean = %q (%d bytes)", got, len(got))
	}
	for _, r := range got {
		if r == 0xFFFD {
			t.Errorf("cut inside a rune: %q", got)
		}
	}
}

func TestCleanOrdersCleaningBeforeTheCap(t *testing.T) {
	// 40 zero-width characters then "end": the cap must count what is left.
	got := untrusted.Clean(strings.Repeat("\u200d", 40)+"end", 200)
	if !strings.HasSuffix(got, "end") || strings.Contains(got, "...") {
		t.Errorf("Clean = %q", got)
	}
}
