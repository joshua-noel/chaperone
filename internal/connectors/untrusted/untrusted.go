// Package untrusted cleans text that another person wrote before a connector
// puts it in a result, a check, a refusal or an approval summary.
//
// A pull request author controls a title, a branch name and a file path. A
// right-to-left override (U+202E) in a path can make "src/\u202Egnp.exe" read
// as "src/exe.png"; a zero-width character can make two different names look
// the same; a control character can rewrite a terminal line. Every connector
// that returns the service's text runs it through this package, so the rule is
// written once.
//
// What is removed: control characters (C0, DEL, C1), bidirectional controls
// (U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C), zero-width and invisible
// format characters (U+200B-200D, U+2060, U+FEFF and the rest of the Unicode
// "format" class and the other default-ignorable code points, see [Hidden]),
// private-use and surrogate code points, and bytes that are
// not UTF-8. A removed character becomes one space, so the reader sees that
// something was there. A carriage return is dropped. This package does not
// judge what the words say and does not look for secrets: chapd redacts every
// result as a whole.
package untrusted

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Strip returns s with the characters above removed. Tab and newline stay, so
// a body or a diff keeps its lines. Text that is clean is returned unchanged.
func Strip(s string) string { return strip(s, false) }

// Line is Strip for text that must stay on one line (a title, a branch, a
// path, a check name, a login): tab and newline become spaces too.
func Line(s string) string { return strip(s, true) }

// Clean is Strip followed by a cap of max bytes. A text that is cut ends in
// "...", and the cut is on a rune boundary.
func Clean(s string, max int) string {
	s = Strip(s)
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max-3], "") + "..."
}

func strip(s string, oneLine bool) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r, oneLine) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\r':
			return -1
		case (r == '\t' || r == '\n') && !oneLine:
			return r
		case unsafeRune(r, oneLine):
			return ' '
		}
		return r
	}, s)
}

// unsafeRune reports whether r is removed. A carriage return is handled by the
// caller (it is dropped, not replaced).
func unsafeRune(r rune, oneLine bool) bool {
	if r == '\t' || r == '\n' {
		return oneLine
	}
	return r == '\r' || r < ' ' || r == 0x7f || unicode.Is(unicode.C, r) || Hidden(r)
}

// Hidden reports whether r shows as nothing, or is a character that a file system or a renderer may ignore: a Unicode
// format character (class Cf: bidi controls, zero-width characters, a byte order mark), or another default-ignorable
// code point (U+034F, U+115F, U+1160, U+17B4, U+17B5, U+180B-U+180F, U+3164, U+FFA0, the variation selectors, the
// tags, and the ranges Unicode leaves unassigned inside the ignorable blocks). The text cleaning removes all of
// them, and the hidden_text note counts every value that held one, so the two never disagree.
func Hidden(r rune) bool {
	switch {
	case unicode.Is(unicode.Cf, r):
		return true
	case r == 0x034f, r == 0x115f, r == 0x1160, r == 0x17b4, r == 0x17b5, r == 0x3164, r == 0xffa0, r == 0x2065:
		return true
	case r >= 0x180b && r <= 0x180f, r >= 0xfe00 && r <= 0xfe0f, r >= 0xfff0 && r <= 0xfff8:
		return true
	case r >= 0xe0000 && r <= 0xe0fff: // the tags, the unassigned range after them, the variation selectors supplement and the rest
		return true
	}
	return false
}
