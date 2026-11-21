package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// CauseCode is the denial cause (factory-spec, surface "output") a caller
// raises, with a ledger event, when [Result.Blocked] is true.
const CauseCode = "REDACTION_BLOCKED"

// MinExactLen is the shortest value the registry accepts. A shorter value
// would mask ordinary text ("abc" inside "abcdef"), so it is refused rather
// than half-protected; the vault refuses to store such a secret.
const MinExactLen = 8

// ErrTooShort is returned by [Registry.Set] for a value under [MinExactLen].
var ErrTooShort = errors.New("redact: value is too short to match safely")

// Hit says which rule fired and how often. It never carries the matched text.
type Hit struct {
	// Rule is "exact" for a registered value or the pattern's name, for
	// example "github-token" or "pem".
	Rule string
	// SecretID is the registry id of an exact match; empty for a pattern.
	SecretID string
	// Count is the number of replacements.
	Count int
}

// Result is the outcome of one redaction pass.
type Result struct {
	// Hits lists every rule that fired, in a stable order. Empty means the
	// input was clean.
	Hits []Hit
}

// Blocked reports whether anything was masked. A caller that gets true
// MUST raise [CauseCode] and write the ledger event.
func (r Result) Blocked() bool { return len(r.Hits) > 0 }

type pattern struct {
	name string
	re   *regexp.Regexp
}

// patterns are the shape rules (ADR-003, section 6). Order matters: a PEM
// block is masked first so a key inside it is not half-matched by another
// rule. Every expression is RE2, so matching is linear in the input.
//
// The GitHub rule has no upper length bound on purpose. Since 2026-10-02 a
// "ghs_" installation token is "ghs_APPID_JWT", about 520 characters of
// base64url, '.', '_' and '-' (ADR-002); the old 40-character expression
// would mask the first 40 and leak the rest.
var patterns = []pattern{
	{"pem", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----(?s:.*?)(?:-----END [A-Z0-9 ]+-----|\z)`)},
	{"github-pat", regexp.MustCompile(`github_pat_[A-Za-z0-9_\-]{20,}`)},
	{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_.\-]{20,}`)},
	{"anthropic-key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"google-oauth-token", regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{20,}`)},
	{"google-refresh-token", regexp.MustCompile(`1//[0-9A-Za-z_\-]{30,}`)},
	{"google-client-secret", regexp.MustCompile(`GOCSPX-[0-9A-Za-z_\-]{20,}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*`)},
	// Sentry's own token formats: a user token "sntryu_" and an organisation token "sntrys_".
	{"sentry-token", regexp.MustCompile(`sntry[us]_[A-Za-z0-9+/=_\-]{20,}`)},
	// An AWS access key id: AKIA and 16 capitals or digits, not inside a longer word.
	{"aws-access-key-id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	// Slack's token formats (docs.slack.dev, "Tokens" and "Using token rotation"). Every real token has a digit group
	// after the prefix, which keeps a word like "xoxo-love-letters" out. The rotating and app-level rules come before
	// the base rule so a whole "xoxe.xoxb-1-..." is masked, not only the part after the dot.
	//   rotating access "xoxe.xoxb-1-...", "xoxe.xoxp-1-...", configuration "xoxe.xoxp-...", refresh "xoxe-1-...",
	//   rotating app-level "xoxe.xapp-1-..."
	{"slack-rotating-token", regexp.MustCompile(`xoxe[.-](?:xox[abposr]-|xapp-)?[0-9]+-[A-Za-z0-9\-]{20,}`)},
	//   app-level "xapp-1-..."
	{"slack-app-token", regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9\-]{20,}`)},
	//   workflow "xwfp-": the documentation gives only the prefix, so any long run after it
	{"slack-workflow-token", regexp.MustCompile(`xwfp-[A-Za-z0-9\-]{20,}`)},
	//   bot "xoxb-", user "xoxp-", legacy "xoxa-2-", "xoxo-", "xoxr-", "xoxs-"; the docs' short-secret user token is
	//   "xoxp-111-222-333-d6bc76"
	{"slack-token", regexp.MustCompile(`xox[abposr]-[0-9]+-[A-Za-z0-9\-]{12,}`)},
	{"stripe-key", regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}`)},
	// Resend API key: "re_", 8 letters and digits, "_", 24 letters and digits. That is the shape of the one key in
	// Resend's documentation (API reference, Create API key) and of the key fixtures in its official SDK; no example
	// key is written here, because a host's secret scanner rightly refuses it. The lengths are exact: a looser rule also
	// masked ordinary code names followed by a hash. The stored key itself is masked by value; this rule is a backstop.
	{"resend-api-key", regexp.MustCompile(`\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b`)},
	{"chaperone-key", regexp.MustCompile(`chap_key_[A-Za-z0-9_\-]{43}`)}, // ADR-008: a custom key is never in any text, with or without the registry
}

type exact struct {
	id    string
	value []byte
}

// Registry masks registered secret values and secret-shaped strings.
// It is safe for concurrent use. The zero value is not usable; call
// [NewRegistry].
type Registry struct {
	mu      sync.RWMutex
	byID    map[string][]exact
	ordered []exact // all forms, longest first; rebuilt by Set, Remove, Clear
}

// NewRegistry returns an empty registry with the built-in pattern rules.
func NewRegistry() *Registry {
	return &Registry{byID: map[string][]exact{}}
}

// Set registers value as the current value of secret id, replacing the
// previous one. Besides the raw bytes it registers the base64 (standard and
// URL alphabets, padded and not), hex (lower and upper) and JSON-string-escaped
// forms, and the CRLF/LF variant of a multi-line value, so the common ways a
// value reaches a log are covered. Splitting or other encodings are not
// covered (RT-25 records that gap).
//
// The registry keeps its own copy; the caller may zero value afterwards.
func (r *Registry) Set(id string, value []byte) error {
	if id == "" {
		return errors.New("redact: empty secret id")
	}
	if len(value) < MinExactLen {
		return fmt.Errorf("%w (id %q)", ErrTooShort, id)
	}
	es := forms(id, value)
	r.mu.Lock()
	defer r.mu.Unlock()
	zeroAll(r.byID[id])
	r.byID[id] = es
	r.rebuildLocked()
	return nil
}

// Remove forgets secret id and zeroes the registry's copies.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	zeroAll(r.byID[id])
	delete(r.byID, id)
	r.rebuildLocked()
}

// Clear forgets every secret and zeroes the registry's copies.
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, es := range r.byID {
		zeroAll(es)
		delete(r.byID, id)
	}
	r.rebuildLocked()
}

// Len returns the number of registered secrets.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

func (r *Registry) rebuildLocked() {
	r.ordered = r.ordered[:0]
	for _, es := range r.byID {
		r.ordered = append(r.ordered, es...)
	}
	// Longest first, so a value that contains another registered value is
	// masked whole. Ties break on id for a stable Hits order.
	sort.Slice(r.ordered, func(i, j int) bool {
		a, b := r.ordered[i], r.ordered[j]
		if len(a.value) != len(b.value) {
			return len(a.value) > len(b.value)
		}
		return a.id < b.id
	})
}

// Redact returns s with every registered value and every pattern match
// replaced by "[REDACTED:<rule or id>]".
func (r *Registry) Redact(s string) (string, Result) {
	out, res := r.RedactBytes([]byte(s))
	return string(out), res
}

// RedactBytes is [Registry.Redact] for a byte slice. It returns the input
// slice itself when nothing matched.
func (r *Registry) RedactBytes(b []byte) ([]byte, Result) {
	var hits []Hit
	r.mu.RLock()
	for _, e := range r.ordered {
		if n := bytes.Count(b, e.value); n > 0 {
			b = bytes.ReplaceAll(b, e.value, mask(e.id))
			hits = mergeHit(hits, Hit{Rule: "exact", SecretID: e.id, Count: n})
		}
	}
	r.mu.RUnlock()
	for _, p := range patterns {
		if !p.re.Match(b) {
			continue // keeps a clean input uncopied
		}
		var n int
		b = p.re.ReplaceAllFunc(b, func([]byte) []byte {
			n++
			return mask(p.name)
		})
		if n > 0 {
			hits = mergeHit(hits, Hit{Rule: p.name, Count: n})
		}
	}
	return b, Result{Hits: hits}
}

// Contains reports whether b holds a registered value or a pattern match,
// without building the masked copy.
func (r *Registry) Contains(b []byte) bool {
	r.mu.RLock()
	for _, e := range r.ordered {
		if bytes.Contains(b, e.value) {
			r.mu.RUnlock()
			return true
		}
	}
	r.mu.RUnlock()
	for _, p := range patterns {
		if p.re.Match(b) {
			return true
		}
	}
	return false
}

func mask(rule string) []byte { return []byte("[REDACTED:" + rule + "]") }

// mergeHit adds h, folding it into an earlier hit for the same rule and id
// (one exact id has several encoded forms).
func mergeHit(hits []Hit, h Hit) []Hit {
	for i := range hits {
		if hits[i].Rule == h.Rule && hits[i].SecretID == h.SecretID {
			hits[i].Count += h.Count
			return hits
		}
	}
	return append(hits, h)
}

// forms returns the distinct byte strings that stand for value in output.
func forms(id string, value []byte) []exact {
	raw := string(value)
	cand := []string{raw}
	add := func(s string) { cand = append(cand, s) }

	add(base64.StdEncoding.EncodeToString(value))
	add(base64.RawStdEncoding.EncodeToString(value))
	add(base64.URLEncoding.EncodeToString(value))
	add(base64.RawURLEncoding.EncodeToString(value))
	h := hex.EncodeToString(value)
	add(h)
	add(strings.ToUpper(h))
	if j, err := json.Marshal(raw); err == nil && len(j) > 2 {
		add(string(j[1 : len(j)-1])) // the text between the quotes
	}
	if strings.Contains(raw, "\r\n") {
		add(strings.ReplaceAll(raw, "\r\n", "\n"))
	} else if strings.Contains(raw, "\n") {
		add(strings.ReplaceAll(raw, "\n", "\r\n"))
	}
	// A value stored with a trailing newline (an editor, `echo`, a console
	// paste) is used without it: both forms are secrets.
	if t := strings.TrimSpace(raw); t != raw {
		add(t)
	}

	seen := make(map[string]bool, len(cand))
	var out []exact
	for _, c := range cand {
		if len(c) < MinExactLen || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, exact{id: id, value: []byte(c)})
	}
	return out
}

func zeroAll(es []exact) {
	for _, e := range es {
		clear(e.value)
	}
}
