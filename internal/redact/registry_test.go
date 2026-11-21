package redact

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fake builds secret-shaped test data at run time: no fixture file holds a
// value that looks like a real credential.
func randB64URL(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)[:n]
}

// stateless builds a "ghs_APPID_JWT" token of exactly 520 characters:
// header.payload.signature in base64url, joined by dots.
func stateless(t *testing.T) string {
	t.Helper()
	const prefix = "ghs_1234567_"
	tok := prefix + "eyJ" + randB64URL(t, 36) + "." + randB64URL(t, 300) + "."
	tok += randB64URL(t, 520-len(tok))
	// Make sure the alphabet is exercised: '-' and '_' inside the body.
	tok = tok[:100] + "-_" + tok[102:]
	if len(tok) != 520 {
		t.Fatalf("test token is %d characters, want 520", len(tok))
	}
	return tok
}

func testPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestStatelessGitHubTokenIsMaskedWhole(t *testing.T) {
	r := NewRegistry()
	tok := stateless(t)
	for _, in := range []string{
		"Authorization: token " + tok,
		"x=" + tok + "&y=1",
		`{"token":"` + tok + `"}`,
		"\"" + tok + "\"\n",
	} {
		out, res := r.Redact(in)
		if !res.Blocked() {
			t.Fatalf("not blocked: %q", in[:20])
		}
		if strings.Contains(out, tok[:30]) || strings.Contains(out, tok[len(tok)-30:]) || strings.Contains(out, "eyJ") {
			t.Errorf("a fragment of the 520-character token survived: %q", out)
		}
		if strings.Count(out, "[REDACTED:github-token]") != 1 {
			t.Errorf("want exactly one mask, got %q", out)
		}
	}
	// The old 40-character token still matches.
	out, _ := r.Redact("old ghs_" + randB64URL(t, 36))
	if out != "old [REDACTED:github-token]" {
		t.Errorf("40-character token: %q", out)
	}
}

func TestPEMIsMasked(t *testing.T) {
	r := NewRegistry()
	p := testPEM(t)
	body := strings.Split(p, "\n")[1]

	cases := map[string]string{
		"lf":        "before\n" + p + "after",
		"crlf":      "before\r\n" + strings.ReplaceAll(p, "\n", "\r\n") + "after",
		"json":      mustJSON(t, map[string]string{"key": p}),
		"truncated": "log: " + strings.TrimSuffix(strings.TrimSpace(p), "-----END PRIVATE KEY-----"),
		"rsa":       "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----",
		"openssh":   "-----BEGIN OPENSSH PRIVATE KEY-----\nQUJD\n-----END OPENSSH PRIVATE KEY-----",
	}
	for name, in := range cases {
		out, res := r.Redact(in)
		if !res.Blocked() {
			t.Errorf("%s: not blocked", name)
			continue
		}
		if strings.Contains(out, body) {
			t.Errorf("%s: key material survived: %q", name, out)
		}
		if !strings.Contains(out, "[REDACTED:pem]") {
			t.Errorf("%s: no pem mask: %q", name, out)
		}
	}
	// Text around the block is kept.
	out, _ := r.Redact("before\n" + p + "after")
	if out != "before\n[REDACTED:pem]\nafter" {
		t.Errorf("surrounding text changed: %q", out)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPatternShapes(t *testing.T) {
	r := NewRegistry()
	cases := []struct{ rule, tok string }{
		{"github-pat", "github_pat_" + randB64URL(t, 82)},
		{"github-token", "ghp_" + randB64URL(t, 36)},
		{"github-token", "gho_" + randB64URL(t, 36)},
		{"anthropic-key", "sk-ant-api03-" + randB64URL(t, 80)},
		{"google-api-key", "AIza" + randB64URL(t, 35)},
		{"google-oauth-token", "ya29." + randB64URL(t, 120)},
		{"google-refresh-token", "1//" + randB64URL(t, 60)},
		{"google-client-secret", "GOCSPX-" + randB64URL(t, 28)},
		{"sentry-token", "sntryu_" + randB64URL(t, 64)},
		{"sentry-token", "sntrys_" + randB64URL(t, 120)},
		{"aws-access-key-id", "AKIA" + "IOSFODNN7EXAMPLE"},
		{"slack-token", "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"},
		{"slack-token", "xoxp-" + "123456789012-1234567890123"},
		{"stripe-key", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"},
		{"stripe-key", "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"},
		{"jwt", "eyJ" + randB64URL(t, 30) + ".eyJ" + randB64URL(t, 60) + "." + randB64URL(t, 43)},
	}
	for _, c := range cases {
		rule, tok := c.rule, c.tok
		out, res := r.Redact("pre " + tok + " post")
		if out != "pre [REDACTED:"+rule+"] post" {
			t.Errorf("%s: got %q", rule, out)
		}
		if len(res.Hits) != 1 || res.Hits[0].Rule != rule || res.Hits[0].Count != 1 {
			t.Errorf("%s: hits %+v", rule, res.Hits)
		}
	}
}

// The new shape rules are anchored tightly: ordinary words and near misses are left alone.
func TestSecretShapeRulesLeaveOrdinaryTextAlone(t *testing.T) {
	r := NewRegistry()
	for _, in := range []string{
		"the sntryu_ prefix and sntrys_ short", "sntryu_tooShort", "MAKIAIOSFODNN7EXAMPLEX", "AKIA", "AKIAshort", "akiaiosfodnn7example",
		"xoxb- and xoxz-1234567890123456", "xoxb-short", "sk_live_short", "task_live_4eC39HqLyjWDarjtT1zdp7dc", "desk_test_4eC39HqLyjWDarjtT1zdp7dc",
		"Rack and Pinion AKIRA", "ValueError: bad total (cart 4501234567)",
	} {
		if out, res := r.Redact(in); res.Blocked() || out != in {
			t.Errorf("%q changed: %q %+v", in, out, res.Hits)
		}
	}
}

func TestCleanInputUntouched(t *testing.T) {
	r := NewRegistry()
	if err := r.Set("k", []byte("correct-horse-battery")); err != nil {
		t.Fatal(err)
	}
	in := []byte("chap pr open --title 'fix ghs token docs' sha=" + strings.Repeat("a", 40) + " ghs_ short")
	out, res := r.RedactBytes(in)
	if res.Blocked() || string(out) != string(in) {
		t.Errorf("clean input changed: %q %+v", out, res)
	}
	if &out[0] != &in[0] {
		t.Error("clean input was copied")
	}
	if r.Contains(in) {
		t.Error("Contains true for clean input")
	}
}

func TestExactValuesAndEncodings(t *testing.T) {
	r := NewRegistry()
	canary := "canary-" + randB64URL(t, 24)
	if err := r.Set("canary", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	cb := []byte(canary)
	forms := map[string]string{
		"raw":      canary,
		"b64":      base64.StdEncoding.EncodeToString(cb),
		"b64raw":   base64.RawStdEncoding.EncodeToString(cb),
		"b64url":   base64.URLEncoding.EncodeToString(cb),
		"b64urlnp": base64.RawURLEncoding.EncodeToString(cb),
		"hex":      hex.EncodeToString(cb),
		"HEX":      strings.ToUpper(hex.EncodeToString(cb)),
	}
	for name, f := range forms {
		out, res := r.Redact("a " + f + " b")
		if out != "a [REDACTED:canary] b" {
			t.Errorf("%s: %q", name, out)
		}
		if len(res.Hits) != 1 || res.Hits[0].Rule != "exact" || res.Hits[0].SecretID != "canary" {
			t.Errorf("%s: hits %+v", name, res.Hits)
		}
	}
	// Hits never hold the value.
	_, res := r.Redact(canary + canary)
	if res.Hits[0].Count != 2 {
		t.Errorf("count %d, want 2", res.Hits[0].Count)
	}
	if strings.Contains(mustJSON(t, res), canary) {
		t.Error("Result carries the value")
	}
	if !r.Contains(cb) {
		t.Error("Contains false for a registered value")
	}
}

func TestExactMultilineValue(t *testing.T) {
	r := NewRegistry()
	v := "line one secret\nline two secret\n"
	if err := r.Set("ml", []byte(v)); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"lf":   "x " + v + " y",
		"crlf": "x " + strings.ReplaceAll(v, "\n", "\r\n") + " y",
		"json": `{"v":"` + `line one secret\nline two secret\n` + `"}`,
	} {
		out, _ := r.Redact(in)
		if strings.Contains(out, "line one") || strings.Contains(out, "line two") {
			t.Errorf("%s: %q", name, out)
		}
	}
}

// A secret saved with a trailing newline is used, and shows up, without it.
func TestExactValueSavedWithTrailingWhitespaceIsMaskedWithoutIt(t *testing.T) {
	r := NewRegistry()
	canary := "canary-" + randB64URL(t, 24)
	if err := r.Set("pasted", []byte(canary+"\r\n")); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{"bare": "x " + canary + " y", "with newline": "x " + canary + "\r\n y"} {
		out, res := r.Redact(in)
		if strings.Contains(out, canary) || !res.Blocked() {
			t.Errorf("%s: %q", name, out)
		}
	}
}

func TestLongestFirst(t *testing.T) {
	r := NewRegistry()
	short, long := "abcdefgh", "abcdefgh-and-more-tail"
	if err := r.Set("short", []byte(short)); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("long", []byte(long)); err != nil {
		t.Fatal(err)
	}
	out, _ := r.Redact("v=" + long)
	if out != "v=[REDACTED:long]" {
		t.Errorf("tail of the longer value leaked: %q", out)
	}
}

func TestSetReplaceRemoveClear(t *testing.T) {
	r := NewRegistry()
	if err := r.Set("k", []byte("first-value-1")); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("k", []byte("second-value-2")); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Errorf("Len %d", r.Len())
	}
	if out, _ := r.Redact("first-value-1"); out != "first-value-1" {
		t.Error("replaced value still masked")
	}
	if out, _ := r.Redact("second-value-2"); out != "[REDACTED:k]" {
		t.Errorf("new value not masked: %q", out)
	}

	// Remove zeroes the registry's own copy.
	r.mu.RLock()
	held := r.byID["k"][0].value
	r.mu.RUnlock()
	r.Remove("k")
	for _, b := range held {
		if b != 0 {
			t.Fatal("Remove left value bytes in memory")
		}
	}
	if out, _ := r.Redact("second-value-2"); out != "second-value-2" {
		t.Error("removed value still masked")
	}
	_ = r.Set("a", []byte("aaaaaaaa-1"))
	_ = r.Set("b", []byte("bbbbbbbb-2"))
	r.Clear()
	if r.Len() != 0 || r.Contains([]byte("aaaaaaaa-1 bbbbbbbb-2")) {
		t.Error("Clear left entries")
	}
}

func TestSetCopiesAndValidates(t *testing.T) {
	r := NewRegistry()
	v := []byte("zeroed-by-caller")
	if err := r.Set("k", v); err != nil {
		t.Fatal(err)
	}
	clear(v)
	if out, _ := r.Redact("zeroed-by-caller"); out != "[REDACTED:k]" {
		t.Errorf("registry aliased the caller's buffer: %q", out)
	}
	if err := r.Set("short", []byte("1234567")); !errors.Is(err, ErrTooShort) {
		t.Errorf("short value: %v", err)
	}
	if err := r.Set("", []byte("long-enough-value")); err == nil {
		t.Error("empty id accepted")
	}
	if err := r.Set("short", []byte("1234567")); err != nil && strings.Contains(err.Error(), "1234567") {
		t.Error("error contains the value")
	}
}

func TestConcurrentUse(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := string(rune('a' + i))
			for range 200 {
				_ = r.Set(id, []byte("value-for-"+id+"-xxxx"))
				r.Redact("value-for-" + id + "-xxxx ghp_" + strings.Repeat("A", 30))
				if i%2 == 0 {
					r.Remove(id)
				}
			}
		}()
	}
	wg.Wait()
}
