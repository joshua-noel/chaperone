package sentry

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/redact"
)

func guardOf(t *testing.T) base {
	t.Helper()
	return base{cfg: Config{Redactor: redact.NewRegistry()}}
}

// A note is plain text. Ordinary notes pass, in any language.
func TestNoteAllowsPlainText(t *testing.T) {
	b := guardOf(t)
	for _, s := range []string{
		"Looked at this.",
		"Cause: the retry loop (see app/cart.py), fixed in the deploy of 14 Nov - 50% done; ok?",
		"Two\nlines\tand a tab",
		"It's \"fine\" = yes + no",
		"snake_case_names are fine",
		"Ça marche déjà, ça va bien. Это работает. 日本語のメモ。",
		"Done \u2705",
		strings.Repeat("a", sentryspec.MaxCommentBytes),
	} {
		if err := b.guardNote(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
}

// Every way to write a mention, a link, markup or a hidden character is refused,
// and the refusal never repeats the text.
func TestNoteRefusesWhatCouldMentionOrLinkOrHide(t *testing.T) {
	b := guardOf(t)
	for name, c := range map[string]struct{ text, code string }{
		"a person":                 {"ping @alice", ops.CodePolicyRefused},
		"a person, in a word":      {"mail@alice", ops.CodePolicyRefused},
		"a team":                   {"for #backend", ops.CodePolicyRefused},
		"an issue number sign":     {"see #123", ops.CodePolicyRefused},
		"bold mention":             {"**@alice**", ops.CodePolicyRefused},
		"entity for an at sign":    {"&#64;alice", ops.CodePolicyRefused},
		"hex entity":               {"&#x40;alice", ops.CodePolicyRefused},
		"a tag":                    {"<b>x</b>", ops.CodePolicyRefused},
		"a link":                   {"[x](https://example.org)", ops.CodePolicyRefused},
		"a reference link":         {"[x]: https://example.org", ops.CodePolicyRefused},
		"a code fence":             {"```\ncode\n```", ops.CodePolicyRefused},
		"a backtick":               {"use `x`", ops.CodePolicyRefused},
		"a backslash":              {`\@alice`, ops.CodePolicyRefused},
		"emphasis":                 {"*bold*", ops.CodePolicyRefused},
		"a pipe":                   {"a | b", ops.CodePolicyRefused},
		"full-width at sign":       {"\uFF20alice", ops.CodePolicyRefused},
		"full-width number sign":   {"\uFF03backend", ops.CodePolicyRefused},
		"small at sign":            {"\uFE6Balice", ops.CodePolicyRefused},
		"small number sign":        {"\uFE5Fbackend", ops.CodePolicyRefused},
		"full-width letters":       {"\uFF21\uFF22", ops.CodePolicyRefused},
		"a no-break space":         {"a\u00a0b", ops.CodePolicyRefused},
		"a zero-width space":       {"a\u200bb", ops.CodeParamsInvalid},
		"a bidi override":          {"a\u202eb", ops.CodeParamsInvalid},
		"a variation selector":     {"a\ufe0fb", ops.CodeParamsInvalid},
		"a tag character":          {"a\U000E0041b", ops.CodeParamsInvalid},
		"a bell":                   {"a\x07b", ops.CodeParamsInvalid},
		"a carriage return":        {"a\rb", ops.CodeParamsInvalid},
		"a NUL":                    {"a\x00b", ops.CodeParamsInvalid},
		"bytes that are not UTF-8": {"a\xffb", ops.CodeParamsInvalid},
		"too long":                 {strings.Repeat("a", sentryspec.MaxCommentBytes+1), ops.CodeParamsInvalid},
		"a secret":                 {"the key is ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", ops.CodeRedactionBlocked},
	} {
		err := b.guardNote(c.text)
		r := wantRefusalNamed(t, name, err, c.code)
		if r != nil && len(c.text) > 6 && len(c.text) < 60 && strings.Contains(r.Why, c.text) {
			t.Errorf("%s: the refusal repeats the text: %s", name, r.Why)
		}
	}
}

func wantRefusalNamed(t *testing.T, name string, err error, code string) *ops.Refusal {
	t.Helper()
	ref, ok := err.(*ops.Refusal)
	if !ok {
		t.Errorf("%s: got %v, want a refusal %s", name, err, code)
		return nil
	}
	if ref.Code != code {
		t.Errorf("%s: code %s (%s), want %s", name, ref.Code, ref.Why, code)
	}
	return ref
}
