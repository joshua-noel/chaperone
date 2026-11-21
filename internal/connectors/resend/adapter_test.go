package resend

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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

// The key is registered with the redaction check once it is used.
func TestTheKeyIsRegisteredWithTheRedactionCheck(t *testing.T) {
	e := newEnv(t, nil)
	if _, res := e.reg.Redact("x " + testSendKey); res.Blocked() {
		t.Fatal("the key is known before it is used: the test proves nothing")
	}
	mustSucceed(t, e.run(e.sendReq(mailParams())))
	if _, res := e.reg.Redact("leak " + testSendKey); !res.Blocked() {
		t.Error("the key is not masked by the redaction check")
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
		{401, "restricted_api_key", "", false, []string{"refused the API key", "Sending access", "nothing was sent"}},
		{401, "missing_api_key", "", false, []string{"refused the API key", "nothing was sent"}},
		{429, "rate_limit_exceeded", "7", false, []string{"rate or quota", "rate_limit_exceeded", "retry in 7 s", "nothing was sent"}},
		{429, "daily_quota_exceeded", "", false, []string{"daily_quota_exceeded", "nothing was sent"}},
		{404, "not_found", "", false, []string{"HTTP 404", "not_found", "nothing was sent"}},
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

	for _, o := range []ops.Outcome{out} {
		if !o.Failed {
			t.Errorf("outcome = %+v", o)
		}
		all := asJSON(t, o.Result)
		for _, secret := range []string{testSendKey, "rotated-", "API key is invalid"} {
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
	if len(e.fake.Requests()) != 0 {
		t.Error("a request with no key reached Resend")
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

// ---- the transport may replay one request, and that is safe ----------------------------

type connLog struct {
	mu     sync.Mutex
	reused []bool
}

func (l *connLog) add(b bool) { l.mu.Lock(); l.reused = append(l.reused, b); l.mu.Unlock() }
func (l *connLog) reset()     { l.mu.Lock(); l.reused = nil; l.mu.Unlock() }
func (l *connLog) get() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bool(nil), l.reused...)
}

// tracingTransport records, for every connection a request takes, whether it was a
// warm one that the transport had used before.
type tracingTransport struct {
	base http.RoundTripper
	log  *connLog
}

func (t tracingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { t.log.add(i.Reused) }}
	return t.base.RoundTrip(r.WithContext(httptrace.WithClientTrace(r.Context(), tr)))
}

// The adapter never repeats a send, but Go's HTTP transport does replay a request that
// carries an Idempotency-Key and a rebuildable body when a warm keep-alive connection
// drops after the server took the message. The replay is the identical request: same
// body, same key. Resend answers it from the first, so there are two POSTs and one
// message. This test pins that, and with it the reason the key is sent on every send.
//
// Whether a request meets a warm connection depends on the transport putting the first
// connection back in its pool in time. The test records the connection each request
// took and tries again until it meets one; it fails if it never does, and never passes
// without having seen the replay.
func TestAWarmConnectionThatDropsIsReplayedWithTheSameKeyAndSendsOnce(t *testing.T) {
	e := newEnv(t, nil)
	log := &connLog{}
	hc := e.fake.HTTPClient()
	hc.Transport = tracingTransport{base: hc.Transport, log: log}
	cl, err := NewClient(ClientConfig{SendKey: func(context.Context) (string, error) { return testSendKey, nil }, Registry: e.reg, HTTP: hc})
	if err != nil {
		t.Fatal(err)
	}
	ads, err := Adapters(Config{Client: cl, Policy: func(string) *policy.Resend { return e.pol }, Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	send := func(exec string) ops.Outcome {
		r := e.sendReq(mailParams())
		r.ExecutionID = exec
		out, err := ads[OpSend].Execute(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for i := range 50 {
		mustSucceed(t, send(fmt.Sprintf("x-warm-%d", i))) // leaves a connection to reuse
		before, reqsBefore := len(e.fake.Sent()), len(e.fake.Requests())
		e.fake.DropNext()
		log.reset()
		out := send(fmt.Sprintf("x-drop-%d", i))
		conns := log.get()
		if len(conns) == 0 || !conns[0] {
			time.Sleep(5 * time.Millisecond) // the first request met a new connection: no replay is possible; try again
			continue
		}
		if len(conns) != 2 {
			t.Fatalf("the first request took a warm connection, and the connections were %v: want it replayed once", conns)
		}
		mustSucceed(t, out) // the replay got Resend's answer
		reqs := e.fake.Requests()[reqsBefore:]
		if len(reqs) != 2 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/emails" {
			t.Fatalf("the fake saw %+v, want two POSTs", reqs)
		}
		if reqs[0].IdempotencyKey == "" || reqs[0].IdempotencyKey != reqs[1].IdempotencyKey || !bytes.Equal(reqs[0].Body, reqs[1].Body) {
			t.Errorf("the replay is not the identical request: keys %q %q, bodies equal %v", reqs[0].IdempotencyKey, reqs[1].IdempotencyKey, bytes.Equal(reqs[0].Body, reqs[1].Body))
		}
		if n := len(e.fake.Sent()) - before; n != 1 {
			t.Errorf("two POSTs made %d messages, want 1", n)
		}
		return
	}
	t.Fatal("no request met a warm connection in 50 tries: the test proved nothing")
}

// ---- the key ------------------------------------------------------------------------

// A stored key that holds a byte outside `!` to `~` is refused up front, as not sent,
// with a message that says the key is malformed. Go would refuse it as a header value
// before writing anything, which would read as a send that may have gone.
func TestAMalformedStoredKeyIsRefusedAsNotSent(t *testing.T) {
	for name, key := range map[string]string{
		"a line break inside": "re_abc\ndef", "a NUL": "re_abc\x00def", "a space inside": "re_abc def", "a tab inside": "re_abc\tdef",
		"a DEL": "re_abc\x7fdef", "a byte above ASCII": "re_abc\xe9def", "a carriage return inside": "re_abc\rdef",
	} {
		e := newEnv(t, nil)
		cl, err := NewClient(ClientConfig{SendKey: func(context.Context) (string, error) { return key, nil }, HTTP: e.fake.HTTPClient()})
		if err != nil {
			t.Fatal(err)
		}
		ads, err := Adapters(Config{Client: cl, Policy: func(string) *policy.Resend { return e.pol }, Redactor: e.reg})
		if err != nil {
			t.Fatal(err)
		}
		r := e.sendReq(mailParams())
		r.ExecutionID = "x-1"
		out, _ := ads[OpSend].Execute(context.Background(), r)
		if !out.Failed || out.Unconfirmed || !has(errorText(out), "malformed", "import resend-api-key again", "nothing was sent") || has(errorText(out), "may or may not") {
			t.Errorf("%s: outcome %+v", name, out)
		}
		if strings.Contains(asJSON(t, out.Result), "abc") {
			t.Errorf("%s: the result holds part of the key", name)
		}
		// Check refuses before a card is made.
		_, err = ads[OpSend].Check(context.Background(), e.sendReq(mailParams()))
		if ref := wantRefusal(t, err, ops.CodePolicyRefused); !strings.Contains(ref.Why, "malformed") {
			t.Errorf("%s: why = %s", name, ref.Why)
		}
		if len(e.fake.Requests()) != 0 {
			t.Errorf("%s: a request was made", name)
		}
	}
	// A key with a trailing line break is trimmed, as before, and works.
	e := newEnv(t, nil)
	cl, _ := NewClient(ClientConfig{SendKey: func(context.Context) (string, error) { return testSendKey + "\r\n", nil }, HTTP: e.fake.HTTPClient()})
	if _, err := cl.Send(context.Background(), Message{From: testSender, To: []string{"ops@example.com"}, Subject: "s", Text: "t"}, "chaperone-mail-send/x-1"); err != nil {
		t.Errorf("a key with a trailing line break: %v", err)
	}
}

// The error names Resend documents (its Errors page) or its SDK lists are seen as they
// are; a name outside the list is "other". The status decides what the adapter does, so
// a 422 is a refusal like a 400.
func TestTheErrorNamesOfTheDocumentationAreKnown(t *testing.T) {
	names := []string{
		"validation_error", "invalid_idempotency_key", "missing_api_key", "restricted_api_key", "invalid_api_key", "invalid_permission",
		"suspended_api_key", "not_found", "method_not_allowed", "invalid_idempotent_request", "concurrent_idempotent_requests",
		"invalid_attachment", "invalid_from_address", "invalid_access", "invalid_parameter", "invalid_region", "missing_required_field",
		"missing_required_parameter", "monthly_quota_exceeded", "daily_quota_exceeded", "rate_limit_exceeded", "email_above_quota",
		"security_error", "application_error", "internal_server_error", "service_unavailable", "dns_lookup_failed", "resource_locked",
	}
	for _, n := range names {
		if !errorCodes[n] {
			t.Errorf("%s is documented and not in the list", n)
		}
	}
	e := newEnv(t, nil)
	for _, status := range []int{400, 422} {
		e.fake.FailNext(status, "invalid_from_address", "")
		out := e.run(e.sendReq(mailParams()))
		if !out.Failed || out.Unconfirmed || !has(errorText(out), fmt.Sprintf("HTTP %d", status), "invalid_from_address", "nothing was sent") {
			t.Errorf("%d: outcome %+v", status, out)
		}
	}
	e.fake.FailNext(500, "internal_server_error", "")
	if out := e.run(e.sendReq(mailParams())); !out.Unconfirmed || !has(errorText(out), "internal_server_error") {
		t.Errorf("500: %+v", out)
	}
}
