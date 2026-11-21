package resend

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// ---- what is sent ----------------------------------------------------------------

// The message goes to Resend as plain text and as nothing else: the fields of the
// body are exactly the ones the connector sets, whatever the agent asked for.
func TestASendIsPlainTextAndNothingElse(t *testing.T) {
	e := newEnv(t, nil)
	p := with(nil)
	out := e.run(e.sendReq(p))
	res := mustSucceed(t, out)
	sent := e.fake.Sent()
	if len(sent) != 1 {
		t.Fatalf("the fake saw %d messages, want 1", len(sent))
	}
	want := []string{"bcc", "cc", "from", "subject", "text", "to"}
	if !reflect.DeepEqual(sent[0].Fields, want) {
		t.Errorf("fields of the body = %v, want exactly %v: no html, attachments, reply_to, scheduled_at, template, tags or headers", sent[0].Fields, want)
	}
	m := sent[0].Email
	if m.From != testSender || m.Subject != "Deploy finished" || m.Text != p["body"] || m.HTML != "" {
		t.Errorf("message = %+v", m)
	}
	if !reflect.DeepEqual(m.To, []string{"ops@example.com"}) || !reflect.DeepEqual(m.Cc, []string{"dev@team.example.com"}) || !reflect.DeepEqual(m.Bcc, []string{"lead@team.example.com"}) {
		t.Errorf("recipients = %v %v %v", m.To, m.Cc, m.Bcc)
	}
	if res["message_id"] != sent[0].ID || out.ExternalRef != "resend:email/"+sent[0].ID {
		t.Errorf("result %v, external ref %q", res, out.ExternalRef)
	}
	// Without cc and bcc the body has neither field.
	e.run(e.sendReq(mailParams()))
	if f := e.fake.Sent()[1].Fields; !reflect.DeepEqual(f, []string{"from", "subject", "text", "to"}) {
		t.Errorf("fields without cc and bcc = %v", f)
	}
	// Every request carries the headers Resend needs, and the key only in one.
	for _, r := range e.fake.Requests() {
		if r.UserAgent == "" || r.ContentType != "application/json" || r.Method != http.MethodPost || r.Path != "/emails" {
			t.Errorf("request = %+v", r)
		}
	}
}

// The key that sends is never the key that reads, and the other way round.
func TestEachKeyDoesItsOwnJobOnly(t *testing.T) {
	e := newEnv(t, nil)
	mustSucceed(t, e.run(e.sendReq(mailParams())))
	mustSucceed(t, e.run(request(OpStatus, statusEmail, nil, nil)))
	reqs, creds := e.fake.Requests(), e.fake.Credentials()
	if len(reqs) != 2 || len(creds) != 2 {
		t.Fatalf("requests %d credentials %d", len(reqs), len(creds))
	}
	if reqs[0].Method != http.MethodPost || creds[0] != testSendKey {
		t.Errorf("the send used %q", creds[0])
	}
	if reqs[1].Method != http.MethodGet || creds[1] != testStatusKey {
		t.Errorf("the status read used %q", creds[1])
	}
}

// Both keys are registered with the redaction check once they are used.
func TestBothKeysAreRegisteredWithTheRedactionCheck(t *testing.T) {
	e := newEnv(t, nil)
	if _, res := e.reg.Redact("x " + testSendKey); res.Blocked() {
		t.Fatal("the key is known before it is used: the test proves nothing")
	}
	mustSucceed(t, e.run(e.sendReq(mailParams())))
	mustSucceed(t, e.run(request(OpStatus, statusEmail, nil, nil)))
	for _, k := range []string{testSendKey, testStatusKey} {
		if _, res := e.reg.Redact("leak " + k); !res.Blocked() {
			t.Errorf("key %q is not masked by the redaction check", k[:8])
		}
	}
}

// ---- repeat safety ---------------------------------------------------------------

// One execution id is one message: Execute twice sends one, because the
// Idempotency-Key is the same and Resend answers the second from memory.
func TestARepeatOfOneExecutionSendsOnce(t *testing.T) {
	e := newEnv(t, nil)
	r := e.sendReq(mailParams())
	r.ExecutionID = "x-aaa111"
	first := mustSucceed(t, e.run(r))
	second := mustSucceed(t, e.run(r))
	if n := len(e.fake.Sent()); n != 1 {
		t.Fatalf("the fake sent %d messages for one execution, want 1", n)
	}
	if first["message_id"] != second["message_id"] {
		t.Errorf("the repeat answered with another id: %v / %v", first["message_id"], second["message_id"])
	}
	reqs := e.fake.Requests()
	if len(reqs) != 2 || reqs[0].IdempotencyKey != "chaperone-mail-send/x-aaa111" || reqs[1].IdempotencyKey != reqs[0].IdempotencyKey {
		t.Errorf("idempotency keys = %+v", reqs)
	}
	if e.fake.WriteCalls() != 2 || e.fake.WritesApplied() != 1 {
		t.Errorf("write calls %d applied %d, want 2 and 1", e.fake.WriteCalls(), e.fake.WritesApplied())
	}
	// Two executions are two keys and two messages: the key is not the content.
	r2 := e.sendReq(mailParams())
	r2.ExecutionID = "x-bbb222"
	mustSucceed(t, e.run(r2))
	if n := len(e.fake.Sent()); n != 2 {
		t.Errorf("two executions of the same message sent %d, want 2", n)
	}
}

// What the 24 hours mean. Resend keeps a key for 24 hours (Idempotency Keys, and
// Send Email). After that a repeat of the same execution sends again. The
// connector cannot prevent that: chapd does not run an Execute twice, so the only
// way to meet it is a path that does, and the runbook says so. This test fixes
// the behaviour so a change in either side shows.
func TestAfterTheKeyExpiresARepeatSendsAgain(t *testing.T) {
	e := newEnv(t, nil)
	r := e.sendReq(mailParams())
	r.ExecutionID = "x-ccc333"
	mustSucceed(t, e.run(r))
	e.fake.ExpireIdempotencyKeys()
	mustSucceed(t, e.run(r))
	if n := len(e.fake.Sent()); n != 2 {
		t.Fatalf("after the key expired the repeat sent %d messages in all, want 2 (that is what Resend's window means)", n)
	}
}

// A send whose answer is lost is `unconfirmed`, and the message was in fact sent:
// the outcome is the honest one. A repeat with the same execution id (which chapd
// never makes) would not send it twice.
func TestALostAnswerIsUnconfirmedAndARepeatDoesNotDouble(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.DropNext()
	r := e.sendReq(mailParams())
	r.ExecutionID = "x-ddd444"
	out := e.run(r)
	if !out.Unconfirmed || out.Failed {
		t.Fatalf("outcome = %+v, want unconfirmed", out)
	}
	if !has(errorText(out), "may or may not", "Emails page", testSender) {
		t.Errorf("the result does not say what to look up: %q", errorText(out))
	}
	if out.ExternalRef != "" {
		t.Errorf("an unconfirmed send has an external ref: %q", out.ExternalRef)
	}
	if n := len(e.fake.Sent()); n != 1 {
		t.Fatalf("the message was not sent once: %d", n)
	}
	mustSucceed(t, e.run(r))
	if n := len(e.fake.Sent()); n != 1 {
		t.Errorf("the repeat sent again: %d messages", n)
	}
}

// The same key with another body is Resend's 409. It means the key is in use, so a
// message may have gone: unconfirmed, never failed.
func TestAKeyUsedForAnotherBodyIsUnconfirmed(t *testing.T) {
	e := newEnv(t, nil)
	r := e.sendReq(mailParams())
	r.ExecutionID = "x-eee555"
	mustSucceed(t, e.run(r))
	other := mailParams()
	other["body"] = "A different body."
	r2 := e.sendReq(other)
	r2.ExecutionID = "x-eee555"
	out := e.run(r2)
	if !out.Unconfirmed || !has(errorText(out), "idempotency", "invalid_idempotent_request") {
		t.Fatalf("outcome = %+v", out)
	}
	if n := len(e.fake.Sent()); n != 1 {
		t.Errorf("sent %d", n)
	}
}

func TestARequestInProgressIsUnconfirmed(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.InProgress("chaperone-mail-send/x-fff666")
	r := e.sendReq(mailParams())
	r.ExecutionID = "x-fff666"
	out := e.run(r)
	if !out.Unconfirmed || !has(errorText(out), "concurrent_idempotent_requests") || len(e.fake.Sent()) != 0 {
		t.Fatalf("outcome = %+v, sent %d", out, len(e.fake.Sent()))
	}
}

func TestIdempotencyKeyFromAnExecutionId(t *testing.T) {
	for id, want := range map[string]string{
		"x-abc123":               "chaperone-mail-send/x-abc123",
		"x-a.b_c-1":              "chaperone-mail-send/x-a.b_c-1",
		"":                       "",
		"has space":              "",
		"slash/inside":           "",
		"line\nbreak":            "",
		strings.Repeat("a", 201): "",
	} {
		if got := IdempotencyKey(id); got != want {
			t.Errorf("IdempotencyKey(%q) = %q, want %q", id, got, want)
		}
	}
	if k := IdempotencyKey(strings.Repeat("a", 200)); len(k) > 256 || k == "" {
		t.Errorf("a longest execution id gives a key of %d characters", len(k))
	}
	// An execution id that cannot make a key sends nothing.
	e := newEnv(t, nil)
	r := e.sendReq(mailParams())
	r.ExecutionID = "has space"
	out := e.run(r)
	if !out.Failed || len(e.fake.Requests()) != 0 {
		t.Errorf("outcome %+v, requests %d", out, len(e.fake.Requests()))
	}
	// And one that is empty.
	r.ExecutionID = ""
	out, err := e.ads[OpSend].Execute(context.Background(), r)
	if err != nil || !out.Failed || len(e.fake.Requests()) != 0 {
		t.Errorf("empty execution id: %+v %v", out, err)
	}
}

// ---- the approval ------------------------------------------------------------------

func TestTheCardsEvidenceNamesTheMessageExactly(t *testing.T) {
	e := newEnv(t, nil)
	cr, err := e.check(e.sendReq(with(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Evidence) != 1 || cr.Evidence[0].Name != "mail.send message" {
		t.Fatalf("evidence = %+v", cr.Evidence)
	}
	text := cr.Evidence[0].Text
	for _, want := range []string{"Resend", "Sender: " + testSender, "Recipients: 3 (to 1, cc 1, bcc 1)", "project demo", "Body: 50 bytes, SHA-256 ", "Request to Resend: "} {
		if !strings.Contains(text, want) {
			t.Errorf("evidence lacks %q:\n%s", want, text)
		}
	}
	// Checking again is the same text: the card is re-derived at release.
	cr2, _ := e.check(e.sendReq(with(nil)))
	if cr2.Evidence[0].Text != text {
		t.Error("two Checks of one request give different evidence")
	}
	// Anything that changes the message changes the text.
	for name, change := range map[string]func(p map[string]any){
		"subject":   func(p map[string]any) { p["subject"] = "Deploy finished!" },
		"body":      func(p map[string]any) { p["body"] = "The deploy of 4f2b finished.\nNo action is needed.\n" },
		"recipient": func(p map[string]any) { p["to"] = []any{"x@team.example.com"} },
		"cc":        func(p map[string]any) { p["cc"] = []any{"y@team.example.com"} },
		"bcc":       func(p map[string]any) { p["bcc"] = []any{"z@team.example.com"} },
	} {
		p := with(nil)
		change(p)
		other, err := e.check(e.sendReq(p))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if other.Evidence[0].Text == text {
			t.Errorf("a changed %s leaves the evidence as it was", name)
		}
	}
}

// Under an approval Execute sends the approved message and no other.
func TestExecuteSendsOnlyWhatWasApproved(t *testing.T) {
	e := newEnv(t, nil)
	cr, err := e.check(e.sendReq(with(nil)))
	if err != nil {
		t.Fatal(err)
	}
	released := func(r *ops.Request) *ops.Request {
		r.ApprovedEvidence = append([]ops.Evidence(nil), cr.Evidence...)
		return r
	}
	// The approved message goes.
	mustSucceed(t, e.run(released(e.sendReq(with(nil)))))
	if len(e.fake.Sent()) != 1 {
		t.Fatal("the approved message was not sent")
	}
	// A changed sender, recipient, subject or body does not.
	e.pol.Senders = append(e.pol.Senders, "billing@mail.example.com")
	for name, mk := range map[string]func() *ops.Request{
		"sender":    func() *ops.Request { r := e.sendReq(with(nil)); r.Target.Ref = "billing@mail.example.com"; return r },
		"recipient": func() *ops.Request { return e.sendReq(with(map[string]any{"to": []any{"x@team.example.com"}})) },
		"subject":   func() *ops.Request { return e.sendReq(with(map[string]any{"subject": "Something else"})) },
		"body":      func() *ops.Request { return e.sendReq(with(map[string]any{"body": "Something else entirely."})) },
	} {
		out := e.run(released(mk()))
		if !out.Failed || !has(errorText(out), "approval_binding", "not the message that was approved", "nothing was sent") {
			t.Errorf("%s: outcome %+v", name, out)
		}
	}
	// Evidence of another name, or none of the right name, binds nothing: refuse.
	r := e.sendReq(with(nil))
	r.ApprovedEvidence = []ops.Evidence{{Name: "something else", Text: "x"}}
	if out := e.run(r); !out.Failed {
		t.Errorf("evidence of another name was accepted: %+v", out)
	}
	if n := len(e.fake.Sent()); n != 1 {
		t.Errorf("messages sent = %d, want only the approved one", n)
	}
}

// ---- refusals say no more than they should -------------------------------------------

func TestRefusalsNeverRepeatAnAddressThePolicyDoesNotList(t *testing.T) {
	e := newEnv(t, nil)
	for name, r := range map[string]*ops.Request{
		"recipient": e.sendReq(with(map[string]any{"to": []any{"stranger@evil.example.org"}})),
		"sender":    request(OpSend, "ceo@mail.example.com", mailParams(), nil),
		"cap":       e.sendReq(with(map[string]any{"to": many(6, "team.example.com"), "cc": nil, "bcc": nil})),
		"shape":     e.sendReq(with(map[string]any{"to": []any{"Stranger <stranger@evil.example.org>"}})),
		"twice":     e.sendReq(with(map[string]any{"cc": []any{"ops@example.com"}})),
	} {
		_, err := e.check(r)
		ref := wantRefusal(t, err, map[string]string{"recipient": ops.CodePolicyRefused, "sender": ops.CodePolicyRefused, "cap": ops.CodePolicyRefused, "shape": ops.CodeParamsInvalid, "twice": ops.CodeParamsInvalid}[name])
		for _, leaked := range []string{"stranger", "evil.example.org", "ceo@", "ua@team", "ops@example.com"} {
			if strings.Contains(ref.Why, leaked) {
				t.Errorf("%s: the refusal repeats %q: %s", name, leaked, ref.Why)
			}
		}
	}
	// Nothing was sent for any of them.
	if len(e.fake.Requests()) != 0 {
		t.Error("a refused request reached Resend")
	}
}

func TestRecipientRules(t *testing.T) {
	e := newEnv(t, nil)
	// The cap counts to, cc and bcc together.
	_, err := e.check(e.sendReq(with(map[string]any{"to": many(3, "team.example.com"), "cc": addrs("v", 2, "team.example.com"), "bcc": []any{"ops@example.com"}})))
	ref := wantRefusal(t, err, ops.CodePolicyRefused)
	if !has(ref.Why, "recipient_cap", "6 recipients", "at most 5") {
		t.Errorf("why = %s", ref.Why)
	}
	// Exactly the cap is fine.
	if _, err := e.check(e.sendReq(with(map[string]any{"to": many(5, "team.example.com"), "cc": nil, "bcc": nil}))); err != nil {
		t.Errorf("a message at the cap: %v", err)
	}
	// A listed domain is the whole domain and nothing under it, and a look-alike is not it.
	for _, addr := range []string{"x@mail.team.example.com", "x@teamxexample.com", "x@team.example.com.evil.org", "x@eam.example.com", "x@example.com"} {
		if _, err := e.check(e.sendReq(with(map[string]any{"to": []any{addr}, "cc": nil, "bcc": nil}))); err == nil {
			t.Errorf("%s was allowed", addr)
		}
	}
	// A lower cap in the policy is the cap in force.
	low := newEnv(t, func(p *policy.Resend) { p.MaxRecipients = 1 })
	if _, err := low.check(low.sendReq(with(nil))); err == nil {
		t.Error("a policy cap of 1 allowed 3 recipients")
	}
}

func TestSendNeedsTheBlockTheSenderAndTheCaller(t *testing.T) {
	e := newEnv(t, nil)
	// A block that is not usable refuses, with the reason.
	bad := newEnv(t, nil)
	bad.pol.Invalid = fmt.Errorf("its policy file demo.yaml has a resend block that cannot be used")
	_, err := bad.check(bad.sendReq(mailParams()))
	if ref := wantRefusal(t, err, ops.CodePolicyRefused); !strings.Contains(ref.Why, "cannot be used") {
		t.Errorf("why = %s", ref.Why)
	}
	// Only the orchestrator asks.
	for name, change := range map[string]func(*ops.Request){"run": asRun, "key": asKey, "nobody": func(q *ops.Request) { q.Caller = nil }} {
		_, err := e.check(request(OpSend, testSender, mailParams(), change))
		wantRefusal(t, err, ops.CodePolicyRefused)
		out := e.run(request(OpSend, testSender, mailParams(), change))
		if !out.Failed {
			t.Errorf("%s: Execute did not fail", name)
		}
	}
	if len(e.fake.Requests()) != 0 {
		t.Error("a refused caller reached Resend")
	}
}

func TestAttachmentsAreRefusedByName(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.check(e.sendReq(with(map[string]any{"attachments": []any{}})))
	if ref := wantRefusal(t, err, ops.CodeParamsInvalid); !has(ref.Why, "no attachments") {
		t.Errorf("why = %s", ref.Why)
	}
}

// ---- what Resend can say -----------------------------------------------------------------

func TestAnErrorFromResendIsReportedInOurWordsOnly(t *testing.T) {
	for _, c := range []struct {
		status      int
		name, retry string
		unconfirmed bool
		wantText    []string
	}{
		{422, "validation_error", "", false, []string{"HTTP 422", "validation_error", "nothing was sent"}},
		{400, "invalid_idempotency_key", "", false, []string{"HTTP 400", "nothing was sent"}},
		{403, "validation_error", "", false, []string{"HTTP 403", "nothing was sent"}},
		{401, "restricted_api_key", "", false, []string{"restricted to sending", "nothing was sent"}},
		{401, "missing_api_key", "", false, []string{"refused the API key", "nothing was sent"}},
		{429, "rate_limit_exceeded", "7", false, []string{"rate or quota", "rate_limit_exceeded", "retry in 7 s", "nothing was sent"}},
		{429, "daily_quota_exceeded", "", false, []string{"daily_quota_exceeded", "nothing was sent"}},
		{404, "not_found", "", false, []string{"not found", "nothing was sent"}},
		{500, "application_error", "", true, []string{"HTTP 500", "may or may not"}},
		{503, "service_unavailable", "", true, []string{"HTTP 503", "may or may not"}},
		{422, "a_type_nobody_documented\u202e", "", false, []string{"HTTP 422", ", other)"}},
	} {
		e := newEnv(t, nil)
		e.fake.FailNext(c.status, c.name, c.retry)
		out := e.run(e.sendReq(mailParams()))
		if out.Failed == c.unconfirmed || out.Unconfirmed != c.unconfirmed {
			t.Errorf("%d %s: outcome failed=%v unconfirmed=%v", c.status, c.name, out.Failed, out.Unconfirmed)
		}
		text := errorText(out)
		for _, w := range c.wantText {
			if !strings.Contains(text, w) {
				t.Errorf("%d %s: %q lacks %q", c.status, c.name, text, w)
			}
		}
		// What Resend wrote in its message is never repeated.
		if strings.Contains(asJSON(t, out.Result), "planted failure") {
			t.Errorf("%d %s: the result repeats Resend's message: %v", c.status, c.name, out.Result)
		}
		if out.ExternalRef != "" {
			t.Errorf("%d %s: external ref %q", c.status, c.name, out.ExternalRef)
		}
	}
}

// A redirect is not followed, whatever HTTP client the connector is given: the
// fake sees one request.
func TestARedirectIsNotFollowed(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.RedirectNext()
	out := e.run(e.sendReq(mailParams()))
	if !out.Failed || !has(errorText(out), "redirect", "nothing was sent") {
		t.Fatalf("outcome = %+v", out)
	}
	if n := len(e.fake.Requests()); n != 1 {
		t.Errorf("the fake saw %d requests; the redirect was followed", n)
	}
}

// A sending key restricted to one domain cannot send from another: Resend refuses
// and nothing goes. The policy would have to list the sender for the request to
// get that far.
func TestASenderOutsideTheKeysDomainIsRefusedByResend(t *testing.T) {
	e := newEnv(t, func(p *policy.Resend) { p.Senders = append(p.Senders, "alerts@other.example.org") })
	out := e.run(request(OpSend, "alerts@other.example.org", mailParams(), nil))
	if !out.Failed || !has(errorText(out), "HTTP 403", "nothing was sent") || len(e.fake.Sent()) != 0 {
		t.Fatalf("outcome = %+v sent %d", out, len(e.fake.Sent()))
	}
}

// The key and Resend's message, which the careless fake repeats, appear in no
// result, error or refusal.
func TestAHostileResendCannotMakeUsEchoTheKey(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.Hostile("rotated-" + testSendKey)
	out := e.run(e.sendReq(mailParams()))
	st := e.run(request(OpStatus, statusEmail, nil, nil))
	for _, o := range []ops.Outcome{out, st} {
		if !o.Failed {
			t.Errorf("outcome = %+v", o)
		}
		all := asJSON(t, o.Result)
		for _, secret := range []string{testSendKey, testStatusKey, "rotated-", "API key is invalid"} {
			if strings.Contains(all, secret) {
				t.Errorf("the result repeats %q: %s", secret, all)
			}
		}
	}
	if _, err := e.check(e.sendReq(mailParams())); err != nil {
		t.Errorf("Check reads no Resend and must not fail on a hostile one: %v", err)
	}
}

// The id Resend answers with is its text: cleaned, capped, and withheld when it
// looks like a secret. Nothing is decided from it.
func TestTheMessageIdIsCleanedAndNeverTrusted(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.NextID("ab\u202ecd\x07ef")
	out := e.run(e.sendReq(mailParams()))
	res := mustSucceed(t, out)
	id, _ := res["message_id"].(string)
	if id != "ab cd ef" || res["untrusted_text"] != true {
		t.Errorf("message_id = %q, result %v", id, res)
	}
	e2 := newEnv(t, nil)
	e2.fake.NextID("ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
	out = e2.run(e2.sendReq(mailParams()))
	res = mustSucceed(t, out)
	if res["withheld"] != true || strings.Contains(asJSON(t, res), "ghp_") || strings.Contains(out.ExternalRef, "ghp_") {
		t.Errorf("a secret-shaped id was not withheld: %v %q", res, out.ExternalRef)
	}
	// An answer with no id leaves the send unconfirmed: it was accepted.
	e3 := newEnv(t, nil)
	e3.fake.NextID(" ")
	if out := e3.run(e3.sendReq(mailParams())); !out.Unconfirmed {
		t.Errorf("an empty id: %+v", out)
	}
}

func TestNoKeyMeansNoCardAndNoSend(t *testing.T) {
	e := newEnv(t, nil)
	client, err := NewClient(ClientConfig{
		SendKey: func(context.Context) (string, error) { return "", ErrNoSendKey },
		HTTP:    e.fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ads, err := Adapters(Config{Client: client, Policy: func(string) *policy.Resend { return rigPolicy() }, Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ads[OpSend].Check(context.Background(), e.sendReq(mailParams()))
	if ref := wantRefusal(t, err, ops.CodePolicyRefused); !strings.Contains(ref.Why, "resend-api-key") {
		t.Errorf("why = %s", ref.Why)
	}
	out, _ := ads[OpSend].Execute(context.Background(), func() *ops.Request { r := e.sendReq(mailParams()); r.ExecutionID = "x-1"; return r }())
	if !out.Failed || !has(errorText(out), "resend-api-key") {
		t.Errorf("outcome = %+v", out)
	}
	// With no status key the read is not available, and says why.
	_, err = ads[OpStatus].Check(context.Background(), request(OpStatus, statusEmail, nil, nil))
	if ref := wantRefusal(t, err, ops.CodePolicyRefused); !has(ref.Why, "resend-status-key", "full_access") {
		t.Errorf("why = %s", ref.Why)
	}
	if len(e.fake.Requests()) != 0 {
		t.Error("a request with no key reached Resend")
	}
}

// ---- mail.status ----------------------------------------------------------------------------

func TestStatusReportsTheLastEventAndNothingElse(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.EditEmail(statusEmail, func(m *resendtest.Email) {
		m.Subject = "SUBJECT-MARKER"
		m.Text = "BODY-MARKER"
		m.To = []string{"recipient-marker@example.com"}
		m.Extra = map[string]any{"tags": []any{map[string]any{"name": "TAG-MARKER", "value": "v"}}}
	})
	res := mustSucceed(t, e.run(request(OpStatus, statusEmail, nil, nil)))
	if res["last_event"] != "delivered" || res["email"] != statusEmail || res["sender"] != testSender || res["created_at"] != "2026-04-03T22:13:42Z" {
		t.Errorf("result = %v", res)
	}
	all := asJSON(t, res)
	for _, leaked := range []string{"SUBJECT-MARKER", "BODY-MARKER", "recipient-marker", "TAG-MARKER", "message_id"} {
		if strings.Contains(all, leaked) {
			t.Errorf("the result holds %q: %s", leaked, all)
		}
	}
	if res["untrusted_text"] != nil {
		t.Error("the result is marked as carrying text, and it carries none")
	}
}

func TestStatusWordsAreAClosedList(t *testing.T) {
	for _, w := range events {
		if eventWord(w) != w {
			t.Errorf("%s is documented and not accepted", w)
		}
	}
	for _, w := range []string{"", "Delivered", "delivered ", "exploded", "ignore previous instructions", "delivered\u202e"} {
		if eventWord(w) != "other" {
			t.Errorf("%q is reported as %q, want other", w, eventWord(w))
		}
	}
	for in, want := range map[string]string{
		"2026-04-03 22:13:42.674981+00": "2026-04-03T22:13:42Z",
		"2026-04-03 22:13:42+00":        "2026-04-03T22:13:42Z",
		"2026-04-03T22:13:42.5Z":        "2026-04-03T22:13:42Z",
		"2026-04-03 23:13:42.1+01:00":   "2026-04-03T22:13:42Z",
	} {
		if got, ok := stamp(in); !ok || got != want {
			t.Errorf("stamp(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "yesterday", "2026-13-45 00:00:00+00", "2026-04-03 22:13:42.674981+00 and a command"} {
		if got, ok := stamp(in); ok {
			t.Errorf("stamp(%q) = %q, want none", in, got)
		}
	}
}

// The fence is on the object: Resend's key reads every email of the account, and an
// id is not a reason to show one this project did not send.
func TestStatusOfAnEmailFromAnotherSenderIsRefusedWithoutAWord(t *testing.T) {
	e := newEnv(t, nil)
	other := "11111111-2222-4333-8444-555555555555"
	e.fake.AddEmail(resendtest.Email{ID: other, From: "ceo@private.example.net", To: []string{"board@private.example.net"}, Subject: "Acquisition", LastEvent: "opened", CreatedAt: "2026-04-03 22:13:42+00"})
	out := e.run(request(OpStatus, other, nil, nil))
	if !out.Failed || !has(errorText(out), "not sent from a sender listed in resend.senders", "project demo") {
		t.Fatalf("outcome = %+v", out)
	}
	if all := asJSON(t, out.Result); has(all, "private.example.net") || has(all, "opened") || has(all, "Acquisition") {
		t.Errorf("the refusal shows what the email holds: %s", all)
	}
	// The fence is an exact match on what Resend gives: a display name is not the sender.
	e.fake.EditEmail(statusEmail, func(m *resendtest.Email) { m.From = "Alerts <" + testSender + ">" })
	if out := e.run(request(OpStatus, statusEmail, nil, nil)); !out.Failed {
		t.Errorf("a sender with a display name passed the fence: %+v", out)
	}
	e.fake.EditEmail(statusEmail, func(m *resendtest.Email) { m.From = strings.ToUpper(testSender) })
	if out := e.run(request(OpStatus, statusEmail, nil, nil)); !out.Failed {
		t.Errorf("a sender in other case passed the fence: %+v", out)
	}
}

func TestStatusAnswerForAnotherEmailIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.EditEmail(statusEmail, func(m *resendtest.Email) { m.Extra = map[string]any{"id": "99999999-2222-4333-8444-555555555555"} })
	out := e.run(request(OpStatus, statusEmail, nil, nil))
	if !out.Failed || !has(errorText(out), "different email") {
		t.Errorf("outcome = %+v", out)
	}
}

func TestStatusWithTheSendingKeyAsksForFullAccess(t *testing.T) {
	e := newEnv(t, nil)
	// The operator put a sending_access key in the status secret by mistake.
	client, err := NewClient(ClientConfig{
		SendKey:   func(context.Context) (string, error) { return testSendKey, nil },
		StatusKey: func(context.Context) (string, error) { return testSendKey, nil },
		HTTP:      e.fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ads, err := Adapters(Config{Client: client, Policy: func(string) *policy.Resend { return rigPolicy() }, Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	r := request(OpStatus, statusEmail, nil, nil)
	r.ExecutionID = "x-1"
	out, _ := ads[OpStatus].Execute(context.Background(), r)
	if !out.Failed || !has(errorText(out), "restricted to sending", "Full access") {
		t.Errorf("outcome = %+v", out)
	}
}

func TestStatusOfAnUnknownEmail(t *testing.T) {
	e := newEnv(t, nil)
	out := e.run(request(OpStatus, "00000000-0000-4000-8000-00000000dead", nil, nil))
	if !out.Failed || !has(errorText(out), "no email with that id") {
		t.Errorf("outcome = %+v", out)
	}
}

func TestStatusIsAReadAndSendsNoWrite(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.check(request(OpStatus, statusEmail, nil, nil)); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, e.run(request(OpStatus, statusEmail, nil, nil)))
	if e.fake.WriteCalls() != 0 {
		t.Errorf("a read sent %d writes", e.fake.WriteCalls())
	}
	for _, r := range e.fake.Requests() {
		if r.Method != http.MethodGet {
			t.Errorf("request %+v", r)
		}
	}
}

func TestAdaptersNeedWhatTheyUse(t *testing.T) {
	if _, err := Adapters(Config{}); err == nil {
		t.Error("Adapters with no client, policy or redactor")
	}
	e := newEnv(t, nil)
	cl, _ := NewClient(ClientConfig{SendKey: func(context.Context) (string, error) { return testSendKey, nil }})
	if _, err := Adapters(Config{Client: cl, Policy: func(string) *policy.Resend { return nil }}); err == nil {
		t.Error("Adapters with no redactor: a connector that cannot tell a secret must not start")
	}
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Error("a client with no send key")
	}
	_ = e
}
