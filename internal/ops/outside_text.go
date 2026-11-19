package ops

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
)

// hiddenText counts the values of a result whose text held a hidden or control
// character (a bidi override, a zero-width joiner, an escape) that the cleaning
// removed. The operator and the agent see cleaned text, so this is the way they
// learn that it was changed. It never keeps the raw text.
type hiddenText struct {
	fields []string
	n      map[string]int
	plural map[string]string
}

// see counts raw under the field's name (singular and plural, "file path" and
// "file paths") when cleaning would change it. A carriage return alone does not
// count: a body written on Windows has them. Text that is cleaned as a block
// (a body, a diff) passes multiline.
func (h *hiddenText) see(singular, plural, raw string, multiline bool) {
	raw = strings.ReplaceAll(raw, "\r", "")
	clean := untrusted.Line(raw)
	if multiline {
		clean = untrusted.Strip(raw)
	}
	if clean == raw {
		return
	}
	if h.n == nil {
		h.n, h.plural = map[string]int{}, map[string]string{}
	}
	if h.n[singular] == 0 {
		h.fields = append(h.fields, singular)
		h.plural[singular] = plural
	}
	h.n[singular]++
}

// text is the plain-words warning, or "" when nothing was changed.
func (h *hiddenText) text() string {
	if len(h.fields) == 0 {
		return ""
	}
	parts := make([]string, len(h.fields))
	for i, f := range h.fields {
		n := h.n[f]
		if n == 1 {
			parts[i] = "1 " + f
		} else {
			parts[i] = strconv.Itoa(n) + " " + h.plural[f]
		}
	}
	return strings.Join(parts, ", ") + " held hidden or control characters; shown with each such character replaced by a space"
}

// safeURL returns a URL GitHub sent, for a result: at most n bytes, an https URL with a host, and no hidden, control
// or space character. Anything else (it does not parse, another scheme such as javascript: or http:, too long to be
// whole) is returned as "".
func safeURL(s string, n int) string {
	if s == "" || len(s) > n || untrusted.Line(s) != s || strings.ContainsAny(s, " \t") {
		return ""
	}
	if u, err := url.Parse(s); err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return s
}

// lineText is GitHub's or a git client's text for a result: one line, no control or format character, at most n bytes.
func lineText(s string, n int) string { return clamp(untrusted.Line(s), n) }
