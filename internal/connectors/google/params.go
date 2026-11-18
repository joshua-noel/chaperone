package google

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/redact"
)

func paramsInvalid(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodeParamsInvalid, Why: clipText(fmt.Sprintf(format, a...), 400)}
}

func policyRefused(format string, a ...any) error {
	return &ops.Refusal{Code: ops.CodePolicyRefused, Why: clipText(fmt.Sprintf(format, a...), 400)}
}

func redactionBlocked(where string, res redact.Result) error {
	rules := make([]string, 0, len(res.Hits))
	for _, h := range res.Hits {
		rules = append(rules, h.Rule)
	}
	return &ops.Refusal{Code: ops.CodeRedactionBlocked, Why: clipText(fmt.Sprintf(
		"%s holds something shaped like a secret (rule: %s); it was not stored or sent", where, strings.Join(rules, ", ")), 400)}
}

// onlyParams refuses a param the op does not define.
func onlyParams(p map[string]any, allowed ...string) error {
	for k := range p {
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if !ok {
			return paramsInvalid("unknown param %q", clipText(k, 40))
		}
	}
	return nil
}

// paramString reads a required, non-empty string param.
func paramString(p map[string]any, key string) (string, error) {
	s, ok := p[key].(string)
	if !ok || s == "" {
		return "", paramsInvalid("param %s is required and must be a non-empty string", key)
	}
	return s, nil
}

// paramStrings reads a list-of-strings param. A missing key is an empty list.
func paramStrings(p map[string]any, key string) ([]string, error) {
	v, present := p[key]
	if !present {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, paramsInvalid("param %s must be a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, paramsInvalid("param %s must be a list of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}

// checkText refuses text a human could misread on a card or in a mail client:
// invalid UTF-8, control characters (a tab and, when multiline, a newline are
// the exceptions) and Unicode format characters (bidi overrides, zero-width
// joiners, the BOM).
func checkText(what, s string, multiline bool, max int) error {
	if len(s) > max {
		return paramsInvalid("%s is longer than %d bytes", what, max)
	}
	if !utf8.ValidString(s) {
		return paramsInvalid("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		switch {
		case r == '\t' || (multiline && r == '\n'):
		case r < ' ' || r == 0x7f || unicode.Is(unicode.C, r):
			return paramsInvalid("%s has a control or invisible character (U+%04X)", what, r)
		}
	}
	return nil
}

// Redactor is the part of *redact.Registry the adapters use.
type Redactor interface {
	Redact(s string) (string, redact.Result)
	RedactBytes(b []byte) ([]byte, redact.Result)
}

var _ Redactor = (*redact.Registry)(nil)

// scan returns a refusal when s or any of data holds a secret.
func scan(r Redactor, where, s string) error {
	if r == nil || s == "" {
		return nil
	}
	if _, res := r.Redact(s); res.Blocked() {
		return redactionBlocked(where, res)
	}
	return nil
}
