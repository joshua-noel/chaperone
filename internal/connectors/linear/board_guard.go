package linear

import (
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// The text an agent writes in a comment, a link or a link title must not point at an item of the operator board
// (the intake team): Linear may turn a mention or a link into a backlink on the item it names, and that would be a
// write to the board.
//
// THIS IS A BEST-EFFORT GUARD against accidental and simple references. It is not a barrier. An agent can always
// describe an item in words, and no check on text can know every way Linear, a markdown renderer or a person reads
// it. The real protection is that these operations cannot ACT on the board: every read and every write of an issue
// is refused for an item of the intake team or with the intake label (issueFence), whatever a comment says. This
// guard only keeps the issue ops from adding, by themselves, a reference that Linear would turn into a backlink.
//
// The check is therefore not a list of forms. It does three things:
//
//   - refuses text that cannot be read as it is shown: any invisible or default-ignorable character
//     (untrusted.Hidden), any letter of the full-width forms, and a word that mixes the Latin alphabet with another
//     alphabet that has look-alike letters (Cyrillic, Greek, Armenian, Cherokee, Coptic). Ordinary text in another
//     language passes, since a word in one alphabet is not refused; a word written wholly in look-alike letters is not
//     either, and that cannot create a backlink, because Linear reads only the ASCII identifier;
//   - works on a normalised copy (see [normalise]), so an escape or a bit of markup does not hide a reference;
//   - refuses any text that, once normalised, holds linear.app, or the identifier of the intake team, or a page of it.

// guardBoard is the check an agent's comment body, link title and link URL go through. what names the text for the
// refusal; the refusal never repeats the text.
func guardBoard(pol *policy.Linear, what, text string) error {
	if err := readableAsShown(what, text); err != nil {
		return err
	}
	n := normalise(text)
	if strings.Contains(strings.ToLower(n), "linear.app") {
		return intakeRefused("%s points at Linear itself (linear.app); the issue ops never link to Linear, because a link could name an item of the operator board", what)
	}
	return namesTheBoard(pol, what, n)
}

// namesTheBoard refuses normalised text that holds an identifier of the intake team (SHOP-12, in any case, alone or
// inside a URL) or a URL of that team's pages. The policy knows the team's key only, not its name or id, so those are
// not matched here (a page of the team is a linear.app URL, refused before this runs).
func namesTheBoard(pol *policy.Linear, what, text string) error {
	key := regexp.QuoteMeta(pol.Team)
	re := regexp.MustCompile("(?i)((^|[^a-z0-9])" + key + "-[0-9]|(/|%2f)team(/|%2f)" + key + "([^a-z0-9]|$))")
	if re.MatchString(text) {
		return intakeRefused("%s names an item or a page of the operator board (the intake team); the issue ops never point at it", what)
	}
	return nil
}

// readableAsShown refuses text that a reader could not take as it is shown: an invisible character, a full-width
// letter or digit, or a word that mixes the Latin alphabet with a look-alike one.
func readableAsShown(what, s string) error {
	for _, r := range s {
		switch {
		case untrusted.Hidden(r):
			return paramsInvalid("%s has an invisible character (U+%04X)", what, r)
		case fullWidthAlnum(r):
			return paramsInvalid("%s has a full-width letter or digit (U+%04X): write it in plain letters", what, r)
		}
	}
	for _, w := range words(s) {
		if mixesLookAlikes(w) {
			return paramsInvalid("%s has a word that mixes the Latin alphabet with look-alike letters of another (Cyrillic, Greek or similar): write the word in one alphabet", what)
		}
	}
	return nil
}

func fullWidthAlnum(r rune) bool {
	return r >= 0xFF10 && r <= 0xFF19 || r >= 0xFF21 && r <= 0xFF3A || r >= 0xFF41 && r <= 0xFF5A || r == 0xFF0D
}

// words splits s into runs of letters, digits and marks.
func words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r) })
}

// lookAlikeScripts are the alphabets whose letters can look like Latin ones.
var lookAlikeScripts = []*unicode.RangeTable{unicode.Cyrillic, unicode.Greek, unicode.Armenian, unicode.Cherokee, unicode.Coptic}

func mixesLookAlikes(w string) bool {
	latin, other := false, 0
	var seen [5]bool
	for _, r := range w {
		if r < utf8.RuneSelf {
			latin = latin || unicode.IsLetter(r)
			continue
		}
		if unicode.Is(unicode.Latin, r) {
			latin = true
			continue
		}
		for i, t := range lookAlikeScripts {
			if unicode.Is(t, r) && !seen[i] {
				seen[i] = true
				other++
			}
		}
	}
	return other > 1 || latin && other > 0
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	htmlTag     = regexp.MustCompile(`</?[A-Za-z][^>]*>`)
)

// normalise returns a copy of s as a renderer, a browser or Linear could read it: HTML entities and percent-escapes
// decoded until nothing changes (a few rounds at most), HTML comments and tags removed, the characters that markdown
// takes as emphasis or escape (backslash, asterisk, underscore, backtick, tilde) removed, and every kind of dash
// written as a hyphen. It is used only to look for references; the text itself is never changed.
func normalise(s string) string {
	for range 8 {
		prev := s
		s = percentDecode(html.UnescapeString(s))
		if s == prev {
			break
		}
	}
	s = strings.ToValidUTF8(s, "")
	s = htmlComment.ReplaceAllString(s, "")
	s = htmlTag.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\\' || r == '*' || r == '_' || r == '`' || r == '~':
			return -1
		case r == '\u2212' || unicode.Is(unicode.Pd, r):
			return '-'
		}
		return r
	}, s)
}

// percentDecode decodes every valid %XX; anything else is kept as it is (a lone "%" is just a percent sign).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}
