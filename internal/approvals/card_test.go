package approvals

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

func baseApproval(mut func(*Approval)) *Approval {
	req := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: "q-5h8w3c",
		Requester: spec.Requester{Kind: "run", RunID: "r-7f3a", TokenJTI: "n8Gf3kQ2xV7bTz1LwA9cYd", Profile: "host-interim"},
		Project:   "acme-shop", Op: "deploy", Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"},
		Params: map[string]any{"sha": "0588aa4ee0116267162e895016bcfda9ec3a3e2c"},
		Reason: "Ship it.", RequestedAt: "2026-10-24T12:00:00Z", ExpiresAt: "2026-10-24T12:15:00Z",
	}
	req.OpHash, _ = spec.OpHash(req)
	a := &Approval{Request: req, Op: req.Op, OpHash: req.OpHash, Class: ClassHigh, PolicyVersion: "baseline-2026.10.1",
		Checks:         []spec.ApprovalCheck{{Name: "backup.fresh", Passed: true, Detail: "verified 2026-10-24T11:40:00Z"}},
		Evidence:       []Evidence{{Title: "Commits since the pilot's SHA", Body: "0588aa4 fix the cart\n3f2e1d0 add the banner"}},
		RequestExpires: time.Date(2026, 10, 24, 12, 15, 0, 0, time.UTC)}
	if mut != nil {
		mut(a)
	}
	return a
}

func mustRender(t *testing.T, a *Approval) string {
	t.Helper()
	text, err := renderCard(a)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestDeployCardGolden(t *testing.T) {
	got := mustRender(t, baseApproval(nil))
	const golden = "testdata/deploy.card.txt"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("card changed; if intended bump cardVersion and rerun with UPDATE_GOLDEN=1.\n--- got ---\n%s", got)
	}
}

func TestCardIsDeterministicAndHashed(t *testing.T) {
	a := mustRender(t, baseApproval(nil))
	b := mustRender(t, baseApproval(nil))
	if a != b || DisplayHash(a) != DisplayHash(b) {
		t.Fatal("the same request must render the same card")
	}
	// Any change to what the card shows changes the hash.
	for name, mut := range map[string]func(*Approval){
		"one byte of a param": func(a *Approval) { a.Request.Params["sha"] = "0588aa4ee0116267162e895016bcfda9ec3a3e2d" },
		"the reason":          func(a *Approval) { a.Request.Reason = "Ship it!" },
		"the target":          func(a *Approval) { a.Request.Target.Ref = "prod" },
		"the project":         func(a *Approval) { a.Request.Project = "acme-shoq" },
		"a check":             func(a *Approval) { a.Checks[0].Detail = "verified" },
		"the evidence":        func(a *Approval) { a.Evidence[0].Body += "x" },
		"the policy version":  func(a *Approval) { a.PolicyVersion = "baseline-2026.10.2" },
		"the expiry":          func(a *Approval) { a.RequestExpires = a.RequestExpires.Add(time.Second) },
		"the class":           func(a *Approval) { a.Class = ClassCritical },
		"the requester":       func(a *Approval) { a.Request.Requester.RunID = "r-7f3b" },
		"an extra parameter":  func(a *Approval) { a.Request.Params["extra"] = true },
		"the request id":      func(a *Approval) { a.Request.RequestID = "q-5h8w3d" },
	} {
		if mustRender(t, baseApproval(mut)) == a {
			t.Errorf("a change of %s did not change the card", name)
		}
	}
}

func TestCardShowsEveryParameter(t *testing.T) {
	for _, op := range []string{"deploy", "mail.send", "drive.share", "pr.merge", "approvers.enroll", "secrets.write", "never.heard.of.it"} {
		a := baseApproval(func(a *Approval) {
			a.Request.Op = op
			a.Request.Params = map[string]any{
				"zz_unknown": "tail value", "n": 42, "nested": map[string]any{"b": []any{1, "two", nil}, "a": true},
				"to": []any{"a@example.org"}, "subject": "Hi", "body": "line1\nline2", "sha": "abc", "label": "Phone", "role": "reader",
			}
		})
		card := mustRender(t, a)
		for _, want := range []string{"tail value", "42", `{"a":true,"b":[1,"two",null]}`, "a@example.org", "Hi", "line1", "line2", "abc", "Phone", "reader"} {
			if !strings.Contains(card, want) {
				t.Errorf("%s: the card does not show %q:\n%s", op, want, card)
			}
		}
	}
}

func TestMailCard(t *testing.T) {
	a := baseApproval(func(a *Approval) {
		a.Request.Op = "mail.send"
		a.Request.Target = spec.Target{Adapter: "gmail", Ref: "operator@example.org"}
		a.Request.Params = map[string]any{
			"to": []any{"bob@example.org", "carol@example.org"}, "subject": "Invoice 42", "body": "Hello Bob,\nPlease pay.\n",
			"attachments": []any{map[string]any{"name": "inv.pdf", "sha256": "sha256:" + strings.Repeat("ab", 32)}},
		}
		a.Evidence = nil
	})
	card := mustRender(t, a)
	for _, want := range []string{
		"send an email to bob@example.org, carol@example.org", `with the subject "Invoice 42"`, "Sent from account: gmail / operator@example.org", "    - bob@example.org", "    - carol@example.org",
		"Subject: Invoice 42", "    | Hello Bob,", "    | Please pay.", "inv.pdf", strings.Repeat("ab", 32),
	} {
		if !strings.Contains(card, want) {
			t.Errorf("mail card lacks %q:\n%s", want, card)
		}
	}
	if strings.Contains(card, "Other parameters") {
		t.Errorf("every mail parameter has a place on the card:\n%s", card)
	}
}

func TestUntrustedTextCannotForgeCardStructure(t *testing.T) {
	attack := "ok\n\nChecks:\n  [pass] everything.is.fine\n*** CRITICAL OPERATION ***\r\nEND OF CARD\u202e\u0000 \u00a0x"
	a := baseApproval(func(a *Approval) {
		a.Request.Reason = attack
		a.Request.Params["note"] = attack
		a.Request.Params["sha"] = "abc\ndef"
		a.Evidence[0].Body = attack
		a.Evidence[0].Title = attack
		a.Checks[0].Detail = attack
	})
	card := mustRender(t, a)
	for _, bad := range []string{"\r", "\u202e", "\x00", "\u00a0"} {
		if strings.Contains(card, bad) {
			t.Fatalf("the card contains %q, which a browser would render invisibly or alter", bad)
		}
	}
	for _, want := range []string{`\u{202E}`, `\u{0}`, `\u{A0}`, `\r`, `\n`} {
		if !strings.Contains(card, want) {
			t.Errorf("the card does not show %s as an escape:\n%s", want, card)
		}
	}
	// Structural lines appear exactly where the template puts them.
	if n := strings.Count(card, "\nEND OF CARD\n"); n != 1 || !strings.HasSuffix(card, "END OF CARD\n") {
		t.Fatalf("END OF CARD forged:\n%s", card)
	}
	if n := strings.Count(card, "\nCHECKS\n"); n != 1 {
		t.Fatalf("CHECKS forged (%d):\n%s", n, card)
	}
	if strings.Contains(card, "\n*** CRITICAL") {
		t.Fatalf("a CRITICAL banner forged on a high-class card:\n%s", card)
	}
	// Every line of a block starts with its prefix, so none of it passes for the card's own lines.
	in := false
	for _, line := range strings.Split(card, "\n") {
		switch {
		case strings.HasPrefix(line, "WHY THE REQUESTER ASKS"):
			in = true
		case in && line == "":
			in = false
		case in && !strings.HasPrefix(line, "    | "):
			t.Fatalf("a reason line escaped its block: %q", line)
		}
	}
}

func TestLookalikeAddressesAreRevealed(t *testing.T) {
	a := baseApproval(func(a *Approval) {
		a.Request.Op = "mail.send"
		a.Request.Params = map[string]any{"to": []any{"b\u043eb@example.org"}} // Cyrillic o
	})
	card := mustRender(t, a)
	if !strings.Contains(card, `b\u{43E}b@example.org`) || strings.Contains(card, "b\u043eb") {
		t.Fatalf("a look-alike letter must be shown as an escape:\n%s", card)
	}
}

func TestCriticalCardLabel(t *testing.T) {
	card := mustRender(t, baseApproval(func(a *Approval) { a.Class = ClassCritical }))
	if !strings.HasPrefix(card, "CHAPERONE APPROVAL CARD v3\n*** CRITICAL OPERATION ***\n") {
		t.Fatalf("the CRITICAL label must come first:\n%s", card)
	}
	if strings.Contains(mustRender(t, baseApproval(nil)), "CRITICAL") {
		t.Fatal("only a critical-class card is labelled CRITICAL")
	}
}

func TestCardTextHasNothingABrowserWouldChange(t *testing.T) {
	// The console shows the card in a <pre> and the browser hashes its
	// textContent: a carriage return would be folded to a newline and a leading
	// newline dropped, and the two hashes would differ.
	for _, a := range []*Approval{baseApproval(nil), baseApproval(func(a *Approval) { a.Request.Reason = "a\r\nb\rc\x00d" })} {
		card := mustRender(t, a)
		if strings.ContainsAny(card, "\r\x00") || strings.HasPrefix(card, "\n") {
			t.Fatalf("%q", card)
		}
	}
}

func sectionKeys(t *testing.T, card string) []string {
	t.Helper()
	secs, ok := ParseCard(card)
	if !ok {
		t.Fatalf("the card does not parse:\n%s", card)
	}
	var keys []string
	for _, s := range secs {
		keys = append(keys, s.Key)
	}
	return keys
}

// The card opens with who wants to do what, in words, and keeps ids, the hash and the
// policy version for the end: the operator reads the request before any identifier.
func TestCardIsPlainFirst(t *testing.T) {
	card := mustRender(t, baseApproval(nil))
	i := func(s string) int { return strings.Index(card, s) }
	if !(i(headAsk) < i("wants to:") && i("wants to:") < i("Risk: HIGH") && i("Risk: HIGH") < i(headChanges) && i(headChanges) < i(headTech)) {
		t.Fatalf("the order of the card is wrong:\n%s", card)
	}
	for _, technical := range []string{"Op hash:", "Policy version:", "Request: q-", "sha256:", "class high"} {
		if i(technical) < i(headTech) {
			t.Errorf("%q appears before TECHNICAL DETAILS:\n%s", technical, card)
		}
	}
	secs, _ := ParseCard(card)
	who, what, ok := CardAsk(secs)
	if !ok || who != "Agent r-7f3a (host-interim)" || what != "deploy commit 0588aa4ee011... to pilot" {
		t.Fatalf("who %q, what %q, ok %v", who, what, ok)
	}
}

// Nothing a decision depends on hides in the folded part: every parameter, the reason, the checks and the
// evidence are in the sections above TECHNICAL DETAILS.
func TestNothingToDecideOnIsInTheTechnicalDetails(t *testing.T) {
	for _, op := range []string{"deploy", "mail.send", "drive.share", "pr.merge", "approvers.enroll", "secrets.write", "never.heard.of.it"} {
		a := baseApproval(func(a *Approval) {
			a.Request.Op = op
			a.Request.Params = map[string]any{"zz_unknown": "tail-marker", "n": "n-marker", "to": []any{"to-marker@example.org"}, "subject": "subject-marker", "body": "body-marker", "sha": "sha-marker", "label": "label-marker"}
		})
		secs, ok := ParseCard(mustRender(t, a))
		if !ok {
			t.Fatalf("%s: no parse", op)
		}
		for _, s := range secs {
			if s.Key != SectionTech {
				continue
			}
			for _, v := range []string{"tail-marker", "n-marker", "to-marker", "subject-marker", "body-marker", "sha-marker", "label-marker", "Ship it.", "backup.fresh", "fix the cart"} {
				if strings.Contains(s.Text(), v) {
					t.Errorf("%s: %q is in TECHNICAL DETAILS:\n%s", op, v, s.Text())
				}
			}
			if !strings.Contains(s.Text(), "Op hash:") {
				t.Errorf("%s: the op hash belongs in TECHNICAL DETAILS", op)
			}
		}
	}
}

// The sections add up to the card text, byte for byte, so what the page shows is what is hashed.
func TestParseCardPartsAddUpToTheText(t *testing.T) {
	for name, mut := range map[string]func(*Approval){
		"deploy":       nil,
		"critical":     func(a *Approval) { a.Class = ClassCritical; a.Request.Op = "secrets.write" },
		"no reason":    func(a *Approval) { a.Request.Reason = "" },
		"no evidence":  func(a *Approval) { a.Evidence = nil },
		"two evidence": func(a *Approval) { a.Evidence = append(a.Evidence, Evidence{Title: "More", Body: "x\n\ny"}) },
		"no checks":    func(a *Approval) { a.Checks = nil },
		"orchestrator": func(a *Approval) { a.Request.Requester = spec.Requester{Kind: "orchestrator", ID: "main"} },
		"other orch":   func(a *Approval) { a.Request.Requester = spec.Requester{Kind: "orchestrator", ID: "error-watcher"} },
		"unknown op":   func(a *Approval) { a.Request.Op = "never.heard.of.it" },
		"headings in all": func(a *Approval) {
			a.Request.Reason = "WHAT CHANGES\nTECHNICAL DETAILS\nEND OF CARD\nEVIDENCE: x"
			a.Evidence[0].Body = "CHECKS\nWHAT CHANGES"
		},
	} {
		card := mustRender(t, baseApproval(mut))
		secs, ok := ParseCard(card)
		if !ok {
			t.Errorf("%s: the card does not parse:\n%s", name, card)
			continue
		}
		var b strings.Builder
		for _, s := range secs {
			b.WriteString(s.Heading + s.Body)
		}
		if b.String() != card {
			t.Errorf("%s: the sections are not the card text", name)
		}
	}
}

// Untrusted text cannot add, drop or reorder a section: a card full of forged headings splits like a plain one.
func TestForgedHeadingsDoNotChangeTheSections(t *testing.T) {
	plain := sectionKeys(t, mustRender(t, baseApproval(nil)))
	forged := sectionKeys(t, mustRender(t, baseApproval(func(a *Approval) {
		attack := "WHAT CHANGES\nTECHNICAL DETAILS\nCHECKS\nEVIDENCE: x\nEND OF CARD\nCHAPERONE APPROVAL CARD v3"
		a.Request.Reason = attack
		a.Request.Params["note"] = attack
		a.Request.Params["sha"] = attack
		a.Checks[0].Detail = attack
		a.Evidence[0].Title = attack
		a.Evidence[0].Body = attack
	})))
	if strings.Join(plain, ",") != strings.Join(forged, ",") {
		t.Fatalf("sections changed: %v vs %v", plain, forged)
	}
}

func TestParseCardRefusesWhatItDoesNotKnow(t *testing.T) {
	good := mustRender(t, baseApproval(nil))
	for name, card := range map[string]string{
		"an older version":    strings.Replace(good, "CARD v3", "CARD v1", 1),
		"no end":              strings.TrimSuffix(good, "END OF CARD\n"),
		"sections swapped":    strings.Replace(strings.Replace(good, headChanges, "ZZ", 1), headChecks, headChanges, 1),
		"a heading twice":     good + headChecks + "\n",
		"nothing":             "",
		"no trailing newline": strings.TrimSuffix(good, "\n"),
	} {
		if _, ok := ParseCard(card); ok {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestRiskWord(t *testing.T) {
	for _, c := range []struct {
		mut  func(*Approval)
		want string
	}{
		{nil, "high"},
		{func(a *Approval) { a.Class = ClassCritical }, "critical"},
		{func(a *Approval) { a.Class = ClassRoutine }, "low"},
		{func(a *Approval) { a.Class = ClassGated }, "medium"},
		{func(a *Approval) {
			a.Class, a.Op = ClassGated, "pr.merge"
			a.Checks = []spec.ApprovalCheck{{Name: "risk_tier", Passed: true, Detail: "tier high: apps/web/cart.go"}}
		}, "high"},
		{func(a *Approval) {
			a.Class, a.Op = ClassGated, "pr.merge"
			a.Checks = []spec.ApprovalCheck{{Name: "risk_tier", Passed: true, Detail: "tier medium: a.go"}}
		}, "medium"},
		// a tier in some other check, or on another op, is not the risk
		{func(a *Approval) {
			a.Checks = []spec.ApprovalCheck{{Name: "risk_tier", Passed: true, Detail: "tier low"}}
		}, "high"},
	} {
		if got := Risk(baseApproval(c.mut)); got != c.want {
			t.Errorf("risk %q, want %q", got, c.want)
		}
	}
}

func TestPlainSentencesForEachOp(t *testing.T) {
	for _, c := range []struct {
		op, ref string
		params  map[string]any
		want    string
	}{
		{"pr.merge", "example-org/storefront#582", map[string]any{"base": "feat/d1-private-pilot"}, "merge pull request #582 into feat/d1-private-pilot"},
		{"deploy", "pilot", map[string]any{"sha": "0588aa4ee0116267162e895016bcfda9ec3a3e2c"}, "deploy commit 0588aa4ee011... to pilot"},
		{"mail.send", "operator@example.org", map[string]any{"to": []any{"a@x.org", "b@x.org", "c@x.org", "d@x.org"}, "subject": "Hi"}, `send an email to a@x.org, b@x.org, c@x.org, and 1 more with the subject "Hi"`},
		{"drive.share", "acct", map[string]any{"file_name": "Plan", "recipients": []any{"a@x.org"}, "role": "reader", "link_visibility": "anyone"}, `share "Plan" with a@x.org (they can reader); link visible to anyone`},
		{"drive.share", "acct", map[string]any{"file_name": "Plan", "recipients": []any{"a@x.org"}, "role": "reader"}, `share "Plan" with a@x.org (they can reader); link visibility not stated`},
		{"mail.send", "me", map[string]any{"bcc": []any{"x@evil.org", "y@evil.org"}, "subject": "Hi"}, `send an email to 0 visible recipients and 2 hidden (bcc) recipients (x@evil.org, y@evil.org) with the subject "Hi"`},
		{"mail.send", "me", map[string]any{"to": []any{"a@x.org"}, "cc": []any{"c@x.org"}, "bcc": []any{"x@evil.org"}, "attachments": []any{map[string]any{"name": "a.pdf"}}}, `send an email to a@x.org, Cc c@x.org and 1 hidden (bcc) recipient (x@evil.org), 1 attachment`},
		{"mail.send", "me", map[string]any{"to": []any{"a@x.org", 7}}, `send an email to a@x.org, 7`},
		{"secrets.write", "ledger-key", nil, "store a secret named ledger-key"},
		{"approvers.enroll", "x", map[string]any{"label": "Phone"}, `add a new approver device named "Phone"`},
		{"never.heard.of.it", "somewhere", nil, "run the operation never.heard.of.it on somewhere"},
	} {
		req := spec.Request{Op: c.op, Target: spec.Target{Ref: c.ref}, Params: c.params}
		if got := wantsTo(req, nil); got != c.want {
			t.Errorf("%s: %q, want %q", c.op, got, c.want)
		}
	}
}

func prApproval(title string) *Approval {
	return baseApproval(func(a *Approval) {
		a.Op, a.Class = "pr.merge", ClassGated
		a.Request.Op = "pr.merge"
		a.Request.Target = spec.Target{Adapter: "github", Ref: "example-org/storefront#582"}
		a.Request.Params = map[string]any{"base": "main", "head_sha": "0588aa4ee0116267162e895016bcfda9ec3a3e2c", "method": "squash"}
		a.Checks = []spec.ApprovalCheck{{Name: "risk_tier", Passed: true, Detail: "tier medium: apps/web/cart.ts"}}
		a.Evidence = []Evidence{{Title: EvidencePR, Body: "Title: " + title + "\nAuthor: octo\nSize: 3 file(s), +10 -2"}}
	})
}

// A merge card names the pull request, so the operator sees which change he is approving (review item 2). The title is
// the PR author's text: it is escaped, clipped, and the card the console lists is still read from the signed text.
func TestMergeCardNamesThePullRequest(t *testing.T) {
	a := prApproval("feat(cart): add a delivery fee")
	card := mustRender(t, a)
	secs, ok := ParseCard(card)
	if !ok {
		t.Fatalf("card does not parse:\n%s", card)
	}
	_, what, ok := CardAsk(secs)
	if want := `merge pull request #582 "feat(cart): add a delivery fee" into main`; !ok || what != want {
		t.Fatalf("headline %q, want %q", what, want)
	}
	if !strings.Contains(card, "    | Author: octo") {
		t.Errorf("author is not on the card:\n%s", card)
	}
}

// splitQuoted reads a merge headline the way a person does: the text between the first quote after the number and the
// first quote that is not escaped with a backslash. It returns that text (still escaped) and what follows the closing
// quote. ok is false when the headline has no closing quote.
func splitQuoted(headline string) (inner, rest string, ok bool) {
	const open = `merge pull request #582 "`
	if !strings.HasPrefix(headline, open) {
		return "", "", false
	}
	s := headline[len(open):]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // the next character is escaped
		case '"':
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// The title is the PR author's text. Whatever it holds, the headline reads: merge pull request #582 "<title>" into
// main, with the real closing quote where the sentence continues, and nothing but printable ASCII in between.
func TestMergeHeadlineEscapesTheTitle(t *testing.T) {
	for _, c := range []struct{ name, title, want string }{
		{"trailing backslash", `fix: a\`, `fix: a\\`},
		{"backslash before a quote", `fix: a\" b`, `fix: a\\\" b`},
		{"ascii quote", `fix: say "hi"`, `fix: say \"hi\"`},
		{"curly quotes", "docs: \u201Cx\u201D", `docs: \u{201C}x\u{201D}`},
		{"fullwidth quote", "docs: \uFF02x", `docs: \u{FF02}x`},
		{"double prime", "docs: x\u2033", `docs: x\u{2033}`},
		{"modifier letter double prime", "docs: x\u02BA", `docs: x\u{2BA}`},
		{"low and reversed quotes", "docs: \u201E\u201F\u301D\u301E", `docs: \u{201E}\u{201F}\u{301D}\u{301E}`},
		{"combining mark", "fix: e\u0301", `fix: e\u{301}`},
		{"combining enclosing", "fix: a\u20DD", `fix: a\u{20DD}`},
		{"bidi override", "feat: ok\u202E gnp.exe", `feat: ok\u{202E} gnp.exe`},
		{"bidi isolate", "feat: \u2066ok\u2069", `feat: \u{2066}ok\u{2069}`},
		{"zero width", "fix: a\u200Bb", `fix: a\u{200B}b`},
		{"a typed escape is not a real one", `fix: \u{202E}`, `fix: \\u{202E}`},
		{"injected second sentence", "docs: typo\u201D into main; merge pull request #900 \u201Cdocs: x",
			`docs: typo\u{201D} into main; merge pull request #900 \u{201C}docs: x`},
		{"injection with an ascii quote", `docs: typo" into main; merge pull request #900 "docs: x`,
			`docs: typo\" into main; merge pull request #900 \"docs: x`},
		{"non-ascii letters", "feat: a\u00F1adir caf\u00E9", `feat: a\u{F1}adir caf\u{E9}`},
		{"look-alike letter", "feat: \u0430dd", `feat: \u{430}dd`},
		{"a long title is not clipped", "feat: " + strings.Repeat("x", 200), "feat: " + strings.Repeat("x", 200)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := prApproval(c.title)
			got := wantsTo(a.Request, a.Evidence)
			inner, rest, ok := splitQuoted(got)
			if !ok || inner != c.want || rest != " into main" {
				t.Fatalf("headline %q:\n quoted %q (want %q), then %q (want %q), closed %v", got, inner, c.want, rest, " into main", ok)
			}
			for _, r := range got {
				if r < 0x20 || r > 0x7e {
					t.Fatalf("headline has the character U+%04X unescaped: %q", r, got)
				}
			}
			// the same on the card the console lists
			card := mustRender(t, a)
			secs, ok := ParseCard(card)
			if !ok {
				t.Fatalf("card does not parse:\n%s", card)
			}
			if _, what, ok := CardAsk(secs); !ok || what != got {
				t.Fatalf("CardAsk %q, want %q", what, got)
			}
		})
	}
}

// The title is shown whole and as the author wrote it in the evidence block, so a non-ASCII title is readable there
// even though the headline writes it in escapes.
func TestMergeCardShowsTheNonASCIITitleInTheEvidence(t *testing.T) {
	card := mustRender(t, prApproval("feat: a\u00F1adir caf\u00E9"))
	if !strings.Contains(card, "\n    | Title: feat: a\u00F1adir caf\u00E9\n") {
		t.Fatalf("title not in the evidence block:\n%s", card)
	}
	if !strings.Contains(card, `merge pull request #582 "feat: a\u{F1}adir caf\u{E9}" into main`) {
		t.Fatalf("headline:\n%s", card)
	}
}

// No title, or evidence that is not a title line: the sentence of the v2 cards, without a quoted part.
func TestMergeHeadlineWithoutATitle(t *testing.T) {
	for name, ev := range map[string][]Evidence{
		"no evidence":                 nil,
		"another block":               {{Title: "something else", Body: "Title: nope"}},
		"empty title":                 {{Title: EvidencePR, Body: EvidenceTitlePrefix + "\nAuthor: octo"}},
		"empty body":                  {{Title: EvidencePR, Body: ""}},
		"first line is not the title": {{Title: EvidencePR, Body: "Author: octo\nTitle: feat: x"}},
	} {
		if got := wantsTo(prApproval("x").Request, ev); got != "merge pull request #582 into main" {
			t.Errorf("%s: %q", name, got)
		}
	}
}
