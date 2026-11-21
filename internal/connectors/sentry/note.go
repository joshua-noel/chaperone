package sentry

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// A note on a Sentry issue is markdown. Sentry tells the people who follow the
// issue about it, and turns `@name` into a mention of a person and `#name` into
// a mention of a team. The agent that writes the note must not be able to
// notify a person or a team that the operator did not choose.
//
// The guard is a narrow allow rule and not a list of bad forms. A note is plain
// text: letters, digits, spaces, line breaks and a short list of marks. Every
// other ASCII character is refused, which leaves no way to write an at sign, a
// number sign, an HTML entity or tag, a link bracket, a code fence or a
// backslash escape. Text that is not ASCII must be letters, digits, marks,
// punctuation or symbols that are visible: an invisible character, a
// control character and the full-width and small-form characters (which are
// look-alikes of the ASCII marks) are refused.
//
// It does not judge what the words say. A note can still be misleading, and a
// bare web address can still be written. The real protection is that the
// operation writes one note to an issue of an allowed project and to nothing
// else, and that it is off until the operator turns it on.

// noteMarks are the ASCII marks, besides letters and digits, that a note may
// hold. A space, a tab and a line break are allowed too.
const noteMarks = ".,:;!?()'\"-_/+=%"

func noteASCIIOK(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '\t', r == '\n':
		return true
	}
	for _, m := range noteMarks {
		if r == m {
			return true
		}
	}
	return false
}

// noteOtherOK reports whether a character outside ASCII may be in a note.
func noteOtherOK(r rune) bool {
	switch {
	case untrusted.Hidden(r), unicode.IsControl(r), r == utf8.RuneError:
		return false
	case r >= 0xFF00 && r <= 0xFFEF, r >= 0xFE50 && r <= 0xFE6F:
		// The full-width forms and the small forms: look-alikes of the ASCII marks
		// (U+FF20 and U+FE6B look like an at sign, U+FF03 and U+FE5F like a number sign).
		return false
	}
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// guardNote checks the text of a note. It returns a refusal that names the kind
// of character and never repeats the text.
func (b base) guardNote(s string) error {
	if len(s) > sentryspec.MaxCommentBytes {
		return paramsInvalid("body is longer than %d bytes", sentryspec.MaxCommentBytes)
	}
	if !utf8.ValidString(s) {
		return paramsInvalid("body is not valid UTF-8")
	}
	for _, r := range s {
		switch {
		case r < utf8.RuneSelf && noteASCIIOK(r):
		case r >= utf8.RuneSelf && noteOtherOK(r):
		case r == '@' || r == '#':
			return &ops.Refusal{Code: ops.CodePolicyRefused, Why: "note_plain_text: a note may not hold an at sign or a number sign: Sentry would turn it into a mention of a person or a team"}
		case r < ' ' || r == 0x7f || r >= utf8.RuneSelf && (untrusted.Hidden(r) || unicode.IsControl(r)):
			return paramsInvalid("body has an invisible or control character (U+%04X)", r)
		default:
			return &ops.Refusal{Code: ops.CodePolicyRefused, Why: clip(fmt.Sprintf("note_plain_text: a note is plain text: letters, digits, spaces, line breaks and these marks: %s; the character U+%04X is not allowed", noteMarks, r), 400)}
		}
	}
	// A bare link lets a person who clicks it carry data to a host the agent chose.
	if low := strings.ToLower(s); strings.Contains(low, "://") || strings.Contains(low, "www.") {
		return &ops.Refusal{Code: ops.CodePolicyRefused, Why: "note_no_link: a note may not hold a web address (`://` or `www.`): a link would take a person who clicks it to a host the agent chose"}
	}
	return b.scan("body", s)
}
