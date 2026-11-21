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
//     (untrusted.Hidden; the variation selector of an emoji or a keycap is ordinary and passes), any letter of the
//     full-width forms, and a word shaped like an issue identifier (letters and digits, a hyphen, a digit) that mixes
//     the Latin alphabet with another alphabet that has look-alike letters (Cyrillic, Greek, Armenian, Cherokee,
//     Coptic). Ordinary text passes: another language, a Greek letter in 120μs or Δt. A word written wholly in
//     look-alike letters passes as well, and that cannot create a backlink, because Linear reads only the ASCII
//     identifier;
//   - works on normalised copies (see [normalForms]), so an escape or a bit of markup does not hide a reference. Two
//     copies are looked at, with and without the HTML tags, because an autolink or an anchor is shaped like a tag;
//   - refuses any text that, once normalised, holds linear.app, or the identifier of the intake team, or a page of it.

// guardBoard is the check an agent's comment body, link title and link URL go through. what names the text for the
// refusal; the refusal never repeats the text.
func guardBoard(pol *policy.Linear, what, text string) error {
	if err := readableAsShown(what, text); err != nil {
		return err
	}
	// Two copies are looked at: the decoded text with its markup still in it, and the same with HTML comments and tags
	// removed. A tag-shaped piece is where a markdown autolink (<https://linear.app/...>) or an anchor lives, so the
	// check must see it before the removal as well as after.
	for _, n := range normalForms(text) {
		if strings.Contains(strings.ToLower(n), "linear.app") {
			return intakeRefused("%s points at Linear itself (linear.app); the issue ops never link to Linear, because a link could name an item of the operator board", what)
		}
		if err := namesTheBoard(pol, what, n); err != nil {
			return err
		}
	}
	return nil
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
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case (r == 0xFE0E || r == 0xFE0F) && variationSelectorIsOrdinary(rs, i):
			// An emoji written with its variation selector, or a keycap: ordinary text.
		case untrusted.Hidden(r):
			return paramsInvalid("%s has an invisible character (U+%04X)", what, r)
		case fullWidthAlnum(r):
			return paramsInvalid("%s has a full-width letter or digit (U+%04X): write it in plain letters", what, r)
		}
	}
	for _, w := range identifierWords(s) {
		if mixesLookAlikes(w) {
			return paramsInvalid("%s has an identifier-shaped word that mixes the Latin alphabet with look-alike letters of another (Cyrillic, Greek or similar): write it in one alphabet", what)
		}
	}
	return nil
}

// variationSelectorIsOrdinary reports whether the variation selector at rs[i] is the one an emoji carries: it follows a
// character that is not ASCII (a heart, a warning sign), or it follows a digit, # or * and starts a keycap (it is then
// followed by U+20E3). Inside an ASCII word, as in SHOP<U+FE0F>-1, it is a way to hide a reference, and is refused.
func variationSelectorIsOrdinary(rs []rune, i int) bool {
	if i == 0 {
		return false
	}
	switch prev := rs[i-1]; {
	case prev >= 0x80:
		return true
	case prev >= '0' && prev <= '9' || prev == '#' || prev == '*':
		return i+1 < len(rs) && rs[i+1] == 0x20E3
	}
	return false
}

func fullWidthAlnum(r rune) bool {
	return r >= 0xFF10 && r <= 0xFF19 || r >= 0xFF21 && r <= 0xFF3A || r >= 0xFF41 && r <= 0xFF5A || r == 0xFF0D
}

// identifierShaped finds the words that have the shape of an issue identifier: letters and digits, a hyphen (of any
// kind), then a digit. Only these are checked for look-alike letters: a Greek letter in 120μs or Δt, or a Cyrillic word
// next to a Latin one, is ordinary text and cannot be mistaken for SHOP-1.
var identifierShaped = regexp.MustCompile(`([\p{L}\p{N}\p{M}]+)[-\x{2010}-\x{2015}\x{2212}\x{FE58}\x{FE63}\x{FF0D}]\p{N}`)

func identifierWords(s string) []string {
	var out []string
	for _, m := range identifierShaped.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
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

// normalForms returns the copies of s that are looked at, as a renderer, a browser or Linear could read it: HTML entities and percent-escapes
// decoded until nothing changes (a few rounds at most), HTML comments and tags removed, the characters that markdown
// takes as emphasis or escape (backslash, asterisk, underscore, backtick, tilde) removed, and every kind of dash
// written as a hyphen. It is used only to look for references; the text itself is never changed.
func normalForms(s string) []string {
	for range 8 {
		prev := s
		s = percentDecode(html.UnescapeString(s))
		if s == prev {
			break
		}
	}
	s = strings.ToValidUTF8(s, "")
	stripped := htmlTag.ReplaceAllString(htmlComment.ReplaceAllString(s, ""), "")
	return []string{foldMarkup(s), foldMarkup(stripped)}
}

// foldMarkup removes the characters that markdown takes as emphasis or escape and makes every dash a hyphen.
func foldMarkup(s string) string {
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
