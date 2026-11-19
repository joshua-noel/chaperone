package console

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// tLedger records the events the approvals engine appends.
type tLedger struct {
	mu  sync.Mutex
	evs []approvals.LedgerEvent
}

// AppendTx refuses an event the spec schema would refuse, as the real ledger
// does: a test that records a draft the ledger rejects passes here and fails in chapd.
func (l *tLedger) AppendTx(_ context.Context, _ *store.Tx, ev approvals.LedgerEvent) error {
	sev := map[string]int{"": 9, "INFO": 9, "WARN": 13, "ERROR": 17}[ev.Severity]
	if sev == 0 {
		return fmt.Errorf("tLedger: severity %q", ev.Severity)
	}
	body := ev.Body
	hash := "sha256:" + strings.Repeat("1", 64)
	e := spec.Event{SpecVersion: spec.SpecVersion, Chain: "test", Seq: 1, PrevHash: hash, Hash: hash, TimeUnixNano: "1700000000000000000",
		TraceID: spec.TraceID("test"), SpanID: "0123456789abcdef", SeverityNumber: sev, SeverityText: ev.Severity, EventName: ev.Name,
		Resource: spec.Resource{ServiceName: "chaperone", ServiceInstanceID: "test"}, RunID: ev.RunID, Project: ev.Project, Attributes: ev.Attributes}
	if e.SeverityText == "" {
		e.SeverityText = "INFO"
	}
	if e.Attributes == nil {
		e.Attributes = map[string]any{}
	}
	if body != "" {
		e.Body = &body
	}
	tree, err := spec.Tree(e)
	if err != nil {
		return err
	}
	if err := spec.Validate(spec.SchemaEvent, tree); err != nil {
		return fmt.Errorf("tLedger: event %s rejected by the spec: %w", ev.Name, err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, ev)
	return nil
}

func (l *tLedger) named(name string) []approvals.LedgerEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []approvals.LedgerEvent
	for _, e := range l.evs {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// apprRig is a console with the approvals engine attached, over the real
// WebAuthn verifier, plus a signed-in browser at the PC origin.
type apprRig struct {
	*rig
	e      *approvals.Engine
	led    *tLedger
	mu     sync.Mutex
	stops  []approvals.Stop
	alerts []approvals.Alert
	seq    int
}

var zero = uint32(0)

func newApprRig(t *testing.T, resolve func(context.Context, string) (approvals.Actor, bool), origins ...Origin) *apprRig {
	t.Helper()
	return newApprRigCfg(t, resolve, nil, origins...)
}

func newApprRigCfg(t *testing.T, resolve func(context.Context, string) (approvals.Actor, bool), mut func(*Config), origins ...Origin) *apprRig {
	t.Helper()
	ar := &apprRig{rig: newRigCfg(t, mut, origins...), led: &tLedger{}}
	e, err := approvals.New(approvals.Config{
		DB: ar.db, Ledger: ar.led, Catalog: approvals.PhaseOneCatalog(), Verifier: ar.con,
		Now: func() time.Time { ar.rig.mu.Lock(); defer ar.rig.mu.Unlock(); return ar.rig.now },
		Stop: func(_ context.Context, _ *store.Tx, s approvals.Stop) error {
			ar.mu.Lock()
			ar.stops = append(ar.stops, s)
			ar.mu.Unlock()
			return nil
		},
		Alert: func(a approvals.Alert) { ar.mu.Lock(); ar.alerts = append(ar.alerts, a); ar.mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	ar.e = e
	if err := ar.con.UseApprovals(e, ApprovalsOptions{ResolveToken: resolve}); err != nil {
		t.Fatal(err)
	}
	return ar
}

// signedIn enrols the first passkey and signs in; the authenticator keeps its
// signature counter at 0, as a platform authenticator may.
func (ar *apprRig) signedIn() (*browser, *authenticator) {
	ar.t.Helper()
	b := ar.browser(pcOrigin)
	a := mustEnrolled(ar.t, ar.rig, b)
	if code, out := b.login(a, opts{signCount: &zero}); code != 200 {
		ar.t.Fatalf("login: %d %v", code, out)
	}
	return b, a
}

func (ar *apprRig) request(mut func(*spec.Request)) *approvals.Approval {
	ar.t.Helper()
	ar.mu.Lock()
	ar.seq++
	n := ar.seq
	ar.mu.Unlock()
	ts := func(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }
	now := ar.rig.now
	req := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: fmt.Sprintf("q-%06d", n),
		Requester: spec.Requester{Kind: "run", RunID: "r-7f3a", TokenJTI: "n8Gf3kQ2xV7bTz1LwA9cYd", Profile: "host-interim"},
		Project:   "acme-shop", Op: "deploy", Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"},
		Params: map[string]any{"sha": fmt.Sprintf("%040x", n)}, Reason: "Ship the fix <b>& more</b>",
		RequestedAt: ts(now), ExpiresAt: ts(now.Add(time.Hour)),
	}
	if mut != nil {
		mut(&req)
	}
	var err error
	if req.OpHash, err = spec.OpHash(req); err != nil {
		ar.t.Fatal(err)
	}
	var res approvals.Result
	if err := ar.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = ar.e.RequestTx(ctx, tx, approvals.RequestInput{Request: req, PolicyVersion: "baseline-2026.10.1",
			Checks: []spec.ApprovalCheck{{Name: "backup.fresh", Passed: true, Detail: "verified"}}})
		return res.Effects, err
	}); err != nil {
		ar.t.Fatal(err)
	}
	if res.Refusal != nil {
		ar.t.Fatalf("request refused: %v", res.Refusal)
	}
	return res.Approval
}

func (ar *apprRig) state(id string) approvals.State {
	ar.t.Helper()
	a, err := ar.e.Get(context.Background(), id)
	if err != nil || a == nil {
		ar.t.Fatalf("get %s: %v", id, err)
	}
	return a.State
}

func (ar *apprRig) snapshot() ([]approvals.Stop, []approvals.Alert) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	return append([]approvals.Stop(nil), ar.stops...), append([]approvals.Alert(nil), ar.alerts...)
}

// postH posts JSON with the CSRF header and more headers.
func (b *browser) postH(path string, body []byte, csrf string, hdr map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	h := map[string]string{"X-CSRF-Token": csrf}
	for k, v := range hdr {
		h[k] = v
	}
	return b.do("POST", path, body, h)
}

func decode(rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

type begun struct {
	chID    string
	options json.RawMessage
	display string
}

func (ar *apprRig) begin(b *browser, id string) begun {
	ar.t.Helper()
	rec := b.postH("/approvals/"+id+"/begin", nil, b.csrf(), nil)
	if rec.Code != 200 {
		ar.t.Fatalf("begin %s: %d %s", id, rec.Code, rec.Body)
	}
	out := decode(rec)
	return begun{chID: str(out["challenge_id"]), options: out["options"], display: str(out["display_sha256"])}
}

func (ar *apprRig) finish(b *browser, id string, bg begun, assertion []byte) *httptest.ResponseRecorder {
	ar.t.Helper()
	return b.postH("/approvals/"+id+"/finish", assertion, b.csrf(), map[string]string{"X-Challenge-ID": bg.chID})
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) map[string]json.RawMessage {
	t.Helper()
	out := decode(rec)
	if rec.Code != status || str(out["error"]) != code {
		t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, code)
	}
	return out
}

// cardPre captures the card element of a page: its id, its display_sha256 and its inner markup. The element is
// followed by the fingerprint fold, so the lazy match ends at the element's own closing tag.
var cardPre = regexp.MustCompile(`(?s)<div class="approval-text" id="card-([^"]+)" data-display-sha256="([^"]+)">(.*?)</div>\s*(?:<p class="phone-code">.*?</p>\s*)?<details class="approval-fp">`)

var tagRE = regexp.MustCompile(`<[^>]*>`)

// cardTextOf is what a browser's textContent gives for the card element: the markup stripped, the entities decoded.
// Every character of the text must come from the card, so the markup may add tags and nothing else.
func cardTextOf(inner string) string { return html.UnescapeString(tagRE.ReplaceAllString(inner, "")) }

// ---- the whole path, with the real WebAuthn verifier ----

func TestApproveWithHelloEndToEnd(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)

	// The page: the card text the server rendered, in a <pre>, with its hash.
	rec := b.do("GET", "/approvals", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("GET /approvals: %d", rec.Code)
	}
	page := rec.Body.String()
	m := cardPre.FindStringSubmatch(page)
	if m == nil || m[1] != card.ID {
		t.Fatalf("no card for %s on the page:\n%s", card.ID, page)
	}
	// What a browser renders is the text after HTML decoding; hash that.
	rendered := cardTextOf(m[3])
	if rendered != card.CardText {
		t.Fatalf("the page text is not the card text:\n%q\n%q", rendered, card.CardText)
	}
	if got := spec.SHA256Tagged([]byte(rendered)); got != m[2] || got != card.DisplaySHA256 {
		t.Fatalf("hash of the rendered text %s, data attribute %s, display_sha256 %s", got, m[2], card.DisplaySHA256)
	}
	if !strings.Contains(page, "Approve with your passkey") || strings.Contains(page, "CRITICAL") {
		t.Fatalf("page: %s", page)
	}
	// The agent's reason is shown as text, never as markup.
	if strings.Contains(page, "<b>& more</b>") || !strings.Contains(rendered, "<b>& more</b>") {
		t.Fatal("the reason must be HTML-escaped on the page and plain in the card text")
	}

	bg := ar.begin(b, card.ID)
	if bg.display != card.DisplaySHA256 {
		t.Fatalf("begin display_sha256 %s", bg.display)
	}
	var opt struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			RPID             string `json:"rpId"`
			Allow            []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(bg.options, &opt); err != nil {
		t.Fatal(err)
	}
	if opt.PublicKey.UserVerification != "required" || opt.PublicKey.RPID != "localhost" || len(opt.PublicKey.Allow) != 1 {
		t.Fatalf("options: %+v", opt)
	}
	out := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	if out.Code != 200 || str(decode(out)["state"]) != "approved" {
		t.Fatalf("finish: %d %s", out.Code, out.Body)
	}

	done, err := ar.e.Get(context.Background(), card.ID)
	if err != nil || done.State != approvals.StateApproved || done.Record == nil {
		t.Fatalf("%+v %v", done, err)
	}
	rc := done.Record
	if rc.Shown.DisplaySHA256 != m[2] {
		t.Fatalf("shown.display_sha256 %s is not the hash of the text the page rendered %s", rc.Shown.DisplaySHA256, m[2])
	}
	// The challenge the browser signed is the spec challenge of the approval.
	raw, _ := hex.DecodeString(strings.TrimPrefix(rc.ChallengeSHA256, "sha256:"))
	if want := b64.EncodeToString(raw); opt.PublicKey.Challenge != want {
		t.Fatalf("the browser was asked to sign %s, the approval's challenge is %s", opt.PublicKey.Challenge, want)
	}
	if h, _ := spec.ApprovalChallenge(rc); h != rc.ChallengeSHA256 {
		t.Fatal("challenge_sha256 is not recomputable from the record")
	}
	if len(rc.Confirmations) != 1 || rc.Confirmations[0].Channel != "pc" || rc.Confirmations[0].CredentialID != b64.EncodeToString(auth.credID) ||
		rc.Approver.ID != "operator" {
		t.Fatalf("record: %+v", rc)
	}
	var clientData []byte
	_ = ar.db.SQL().QueryRow(`SELECT assertion_json FROM approval_assertions WHERE approval_id = ?`, card.ID).Scan(&clientData)
	if spec.SHA256Tagged(clientData) != rc.Confirmations[0].AssertionSHA256 {
		t.Fatal("the stored assertion does not hash to assertion_sha256")
	}
	evs := ar.led.named("op.approve")
	if len(evs) != 1 || evs[0].Attributes["factory.decision"] != "approved" || !strings.Contains(evs[0].Body, rc.Confirmations[0].AssertionSHA256) {
		t.Fatalf("ledger: %+v", evs)
	}

	// The op state machine releases it, once.
	req := done.Request
	consume := func() error {
		return ar.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
			return ar.e.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: card.ID, Request: req})
		})
	}
	if err := consume(); err != nil {
		t.Fatal(err)
	}
	if err := consume(); err == nil || !strings.Contains(err.Error(), approvals.CodeConsumed) {
		t.Fatalf("second consume: %v", err)
	}

	// The page now lists nothing pending and the decision under Recent.
	page = b.do("GET", "/approvals", nil, nil).Body.String()
	if strings.Contains(page, `class="approval-text"`) || !strings.Contains(page, "approved and used") {
		t.Fatalf("page after approval: %s", page)
	}
}

func TestCriticalCardIsLabelledOnThePage(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(func(q *spec.Request) {
		q.Op, q.Target, q.Params = "secrets.write", spec.Target{Adapter: "vault", Ref: "gh-app-key"}, map[string]any{"name": "gh-app-key"}
	})
	page := b.do("GET", "/approvals", nil, nil).Body.String()
	if !strings.Contains(page, `data-risk="critical"`) || !strings.Contains(page, "CRITICAL OPERATION") || !strings.Contains(page, "approval-critical") {
		t.Fatalf("a critical card must say CRITICAL:\n%s", page)
	}
	// One device approves it.
	bg := ar.begin(b, card.ID)
	if rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, alerts := ar.snapshot(); len(alerts) != 2 || alerts[0].Stage != "requested" || alerts[1].Stage != "approved" {
		t.Fatalf("alerts: %+v", alerts)
	}
}

func TestSignedOutSeesNothingAndDecidesNothing(t *testing.T) {
	ar := newApprRig(t, nil)
	_, _ = ar.signedIn()
	card := ar.request(nil)
	out := ar.browser(pcOrigin)
	if rec := out.do("GET", "/approvals", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed out GET /approvals: %d", rec.Code)
	}
	for _, p := range []string{"begin", "finish", "deny"} {
		rec := out.postH("/approvals/"+card.ID+"/"+p, []byte(`{"reason":"x"}`), out.csrf(), nil)
		wantCode(t, rec, http.StatusUnauthorized, "signed_out")
	}
	if ar.state(card.ID) != approvals.StatePending {
		t.Fatal("state changed")
	}
	// Without the engine attached there are no routes at all.
	plain := newRig(t)
	if rec := plain.browser(pcOrigin).do("GET", "/approvals", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no engine: %d", rec.Code)
	}
}

func TestTheSessionAloneApprovesNothing(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)

	// An honest login assertion (made for the library's random login challenge)
	// is not an assertion over the approval challenge.
	cer, loginOpts := b.begin("/login/begin", nil)
	_ = cer
	rec := ar.finish(b, card.ID, bg, auth.get(loginOpts, pcOrigin.URL, opts{signCount: &zero}))
	out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion)
	if str(out["why"]) != ReasonChallenge {
		t.Fatalf("why %s", out["why"])
	}
	if ar.state(card.ID) != approvals.StatePending {
		t.Fatal("a login assertion approved a card")
	}
	// No assertion at all, a garbage body, a missing or unknown challenge id.
	bg2 := ar.begin(b, card.ID)
	wantCode(t, ar.finish(b, card.ID, bg2, nil), http.StatusForbidden, approvals.CodeAssertion)
	bg3 := ar.begin(b, card.ID)
	wantCode(t, ar.finish(b, card.ID, bg3, []byte(`{"id":"x"}`)), http.StatusForbidden, approvals.CodeAssertion)
	rec = b.postH("/approvals/"+card.ID+"/finish", auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}), b.csrf(), nil)
	wantCode(t, rec, http.StatusBadRequest, approvals.CodeChallenge)
	rec = ar.finish(b, card.ID, begun{chID: b64.EncodeToString(make([]byte, 16))}, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	wantCode(t, rec, http.StatusBadRequest, approvals.CodeChallenge)
	if ar.state(card.ID) != approvals.StatePending {
		t.Fatal("approved without an assertion")
	}
}

func TestBadAssertionsAreRefused(t *testing.T) {
	five, three := uint32(5), uint32(3)
	for name, tc := range map[string]struct {
		o      opts
		reason string
	}{
		"no user verification": {opts{signCount: &zero, noUV: true}, ReasonUV},
		"no user presence":     {opts{signCount: &zero, noUP: true}, ReasonUP},
		"another origin":       {opts{signCount: &zero, origin: "http://localhost:9999"}, ReasonOrigin},
		"another key":          {opts{signCount: &zero, wrongKey: true}, ReasonSignature},
		"another challenge":    {opts{signCount: &zero, challenge: b64.EncodeToString(make([]byte, 32))}, ReasonChallenge},
	} {
		t.Run(name, func(t *testing.T) {
			ar := newApprRig(t, nil)
			b, auth := ar.signedIn()
			card := ar.request(nil)
			bg := ar.begin(b, card.ID)
			rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, tc.o))
			out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion)
			if str(out["why"]) != tc.reason {
				t.Fatalf("why %s, want %s (%+v)", out["why"], tc.reason, ar.events())
			}
			if e := ar.last(); e.Name != EventRefused || e.Reason != ReasonAssertion || e.Detail != tc.reason || e.Ceremony != "approve" {
				t.Fatalf("event %+v", e)
			}
			if ar.state(card.ID) != approvals.StatePending || len(ar.led.named("op.approve")) != 0 {
				t.Fatal("a refused assertion changed something")
			}
		})
	}
	t.Run("a cloned authenticator", func(t *testing.T) {
		ar := newApprRig(t, nil)
		b, auth := ar.signedIn()
		c1, c2 := ar.request(nil), ar.request(nil)
		bg := ar.begin(b, c1.ID)
		if rec := ar.finish(b, c1.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &five})); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		bg = ar.begin(b, c2.ID)
		rec := ar.finish(b, c2.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &three}))
		if out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion); str(out["why"]) != ReasonClone {
			t.Fatalf("%s", rec.Body)
		}
	})
}

func TestAssertionForAnotherRequestIsRefused(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	a, c := ar.request(nil), ar.request(nil)
	bgA, bgC := ar.begin(b, a.ID), ar.begin(b, c.ID)
	sigA := auth.get(bgA.options, pcOrigin.URL, opts{signCount: &zero})

	// A's assertion on C's card with C's challenge handle: the signature covers A's challenge.
	rec := ar.finish(b, c.ID, bgC, sigA)
	if out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion); str(out["why"]) != ReasonChallenge {
		t.Fatalf("%s", rec.Body)
	}
	// A's challenge handle on C's card.
	bgA2 := ar.begin(b, a.ID)
	wantCode(t, ar.finish(b, c.ID, bgA2, auth.get(bgA2.options, pcOrigin.URL, opts{signCount: &zero})), http.StatusBadRequest, approvals.CodeWrongRequest)
	if ar.state(a.ID) != approvals.StatePending || ar.state(c.ID) != approvals.StatePending {
		t.Fatal("a refused assertion changed a state")
	}
	// The assertion for A still works for A... once. (bgA was never used above.)
	if rec := ar.finish(b, a.ID, bgA, sigA); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := ar.finish(b, a.ID, bgA, sigA); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
}

func TestChallengeBelongsToTheBrowserThatBeganIt(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)
	// A second browser with the same session cookie but another csrf cookie.
	other := ar.browser(pcOrigin)
	for k, v := range b.cookies {
		if k != csrfCookie {
			other.cookies[k] = v
		}
	}
	rec := ar.finish(other, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	wantCode(t, rec, http.StatusBadRequest, approvals.CodeChallenge)
	if ar.state(card.ID) != approvals.StatePending {
		t.Fatal("approved from another browser")
	}
}

func TestDenyWithAReason(t *testing.T) {
	ar := newApprRig(t, nil)
	b, _ := ar.signedIn()
	card := ar.request(nil)
	wantCode(t, b.postH("/approvals/"+card.ID+"/deny", []byte(`{"reason":"  "}`), b.csrf(), nil), http.StatusBadRequest, approvals.CodeParamsInvalid)
	wantCode(t, b.postH("/approvals/"+card.ID+"/deny", []byte(`not json`), b.csrf(), nil), http.StatusBadRequest, ReasonMalformed)
	wantCode(t, b.postH("/approvals/a-nothere/deny", []byte(`{"reason":"no"}`), b.csrf(), nil), http.StatusNotFound, approvals.CodeNoSuchApproval)
	rec := b.postH("/approvals/"+card.ID+"/deny", []byte(`{"reason":"wrong target"}`), b.csrf(), nil)
	if rec.Code != 200 || str(decode(rec)["state"]) != "denied" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	got, _ := ar.e.Get(context.Background(), card.ID)
	if got.State != approvals.StateDenied || got.Reason != "wrong target" || got.Record.Decision != "denied" || got.Record.Reason != "wrong target" || len(got.Record.Confirmations) != 0 {
		t.Fatalf("%+v", got)
	}
	if evs := ar.led.named("op.approve"); len(evs) != 1 || evs[0].Attributes["factory.decision"] != "denied" {
		t.Fatalf("%+v", evs)
	}
	// A second decision on a decided card.
	wantCode(t, b.postH("/approvals/"+card.ID+"/deny", []byte(`{"reason":"again"}`), b.csrf(), nil), http.StatusConflict, approvals.CodeDenied)
	// Sticky deny: asking again is refused for the cooldown.
	ar.advance(time.Minute)
	req := got.Request
	req.RequestID = "q-again1"
	var res approvals.Result
	_ = ar.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = ar.e.RequestTx(ctx, tx, approvals.RequestInput{Request: req, PolicyVersion: "baseline-2026.10.1"})
		return res.Effects, err
	})
	if res.Refusal == nil || res.Refusal.Code != approvals.CodeDenied {
		t.Fatalf("sticky deny: %+v", res)
	}
}

func TestATokenCannotDecideAnApproval(t *testing.T) {
	resolve := func(_ context.Context, tok string) (approvals.Actor, bool) {
		if tok == "chap_run_resolved" {
			return approvals.Actor{Kind: approvals.ActorRun, RunID: "r-7f3a"}, true
		}
		return approvals.Actor{}, false
	}
	ar := newApprRig(t, resolve)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	anon := ar.browser(pcOrigin) // the agent has no session at all
	for name, tc := range map[string]struct {
		hdr  string
		kind string
		run  string
	}{
		"a run token":              {"Bearer chap_run_whatever", "run", ""},
		"a run token, resolved":    {"Bearer chap_run_resolved", "run", "r-7f3a"},
		"the orchestrator's token": {"Bearer chap_orch_whatever", "orchestrator", ""},
		"a token that is no token": {"Basic Zm9vOmJhcg==", "run", ""},
	} {
		for _, who := range []struct {
			label string
			br    *browser
		}{{"without a session", anon}, {"with the operator's session cookie", b}} {
			t.Run(name+" "+who.label, func(t *testing.T) {
				ar.mu.Lock()
				ar.stops = nil
				ar.mu.Unlock()
				hdr := map[string]string{"Authorization": tc.hdr}
				csrf := who.br.csrf()
				for _, p := range []string{"begin", "finish", "deny"} {
					h := map[string]string{"Authorization": tc.hdr, "X-Challenge-ID": b64.EncodeToString(make([]byte, 16))}
					rec := who.br.postH("/approvals/"+card.ID+"/"+p, []byte(`{"reason":"I approve myself"}`), csrf, h)
					wantCode(t, rec, http.StatusForbidden, approvals.CodeBreach)
				}
				_ = hdr
				stops, _ := ar.snapshot()
				if len(stops) != 3 || stops[0].Code != approvals.StopBreach || stops[0].RequesterKind != tc.kind || stops[0].RunID != tc.run {
					t.Fatalf("stops: %+v", stops)
				}
				if ar.state(card.ID) != approvals.StatePending {
					t.Fatal("a token decided an approval")
				}
			})
		}
	}
	// The operator, without a token header, still can.
	bg := ar.begin(b, card.ID)
	if rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestTenConcurrentApprovalsConsumeExactlyOnce(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	csrf := b.csrf()

	// Ten browsers (ten challenges, ten assertions) answer at the same moment.
	const n = 10
	type attempt struct {
		bg        begun
		assertion []byte
	}
	var attempts []attempt
	for range n {
		bg := ar.begin(b, card.ID)
		attempts = append(attempts, attempt{bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})})
	}
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, at := range attempts {
		wg.Add(1)
		browser := &browser{t: t, h: b.h, host: b.host, origin: b.origin, cookies: map[string]string{}}
		for k, v := range b.cookies {
			browser.cookies[k] = v
		}
		go func() {
			defer wg.Done()
			<-start
			rec := browser.postH("/approvals/"+card.ID+"/finish", at.assertion, csrf, map[string]string{"X-Challenge-ID": at.bg.chID})
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}()
	}
	close(start)
	wg.Wait()
	won := 0
	for i := range codes {
		switch {
		case codes[i] == 200:
			won++
		case codes[i] == http.StatusConflict && strings.Contains(bodies[i], approvals.CodeConsumed):
		default:
			t.Errorf("attempt %d: %d %s", i, codes[i], bodies[i])
		}
	}
	if won != 1 {
		t.Fatalf("%d of 10 concurrent approvals won; exactly one must", won)
	}
	if evs := ar.led.named("op.approve"); len(evs) != 1 {
		t.Fatalf("op.approve events: %d", len(evs))
	}
	var rows int
	_ = ar.db.SQL().QueryRow(`SELECT count(*) FROM approval_assertions`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("stored assertions: %d", rows)
	}
}

func TestExpiredCardCannotBeApproved(t *testing.T) {
	ar := newApprRig(t, nil)
	b, auth := ar.signedIn()
	card := ar.request(nil)
	bg := ar.begin(b, card.ID)
	ar.advance(16 * time.Minute) // deploy: 15 minutes
	rec := ar.finish(b, card.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero}))
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusGone {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if ar.state(card.ID) == approvals.StateApproved {
		t.Fatal("an expired card was approved")
	}
	bg = ar.begin2(b, card.ID)
	_ = bg
}

// begin2 is begin that expects a refusal with status 410 (the card is gone).
func (ar *apprRig) begin2(b *browser, id string) begun {
	ar.t.Helper()
	rec := b.postH("/approvals/"+id+"/begin", nil, b.csrf(), nil)
	wantCode(ar.t, rec, http.StatusGone, approvals.CodeExpired)
	return begun{}
}

func TestPhoneAssertionIsNotAcceptedYet(t *testing.T) {
	// An engine built without PhoneOrigins has no phone channel: an assertion made
	// at the phone origin verifies but is not enabled as a channel.
	ar := newApprRig(t, nil, pcOrigin, phoneOrigin)
	pc := ar.browser(pcOrigin)
	_ = mustEnrolled(t, ar.rig, pc)
	var id int64
	if err := ar.db.SQL().QueryRow(`SELECT id FROM approvers`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tok, err := IssueEnrollment(context.Background(), ar.db, &id, time.Minute, ar.rig.now)
	if err != nil {
		t.Fatal(err)
	}
	phone := ar.browser(phoneOrigin)
	req, _ := json.Marshal(map[string]string{"token": tok, "label": "Phone"})
	cer, options := phone.begin("/enroll/begin", req)
	pa := newAuthenticator(t, phoneOrigin.RPID)
	if code, out := phone.post("/enroll/finish", pa.create(options, phoneOrigin.URL, opts{}), cer); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := phone.login(pa, opts{signCount: &zero}); code != 200 {
		t.Fatal(code, out)
	}
	card := ar.request(nil)
	bg := ar.begin(phone, card.ID)
	rec := ar.finish(phone, card.ID, bg, pa.get(bg.options, phoneOrigin.URL, opts{signCount: &zero}))
	if out := wantCode(t, rec, http.StatusForbidden, approvals.CodeAssertion); str(out["why"]) != "channel_not_enabled" {
		t.Fatalf("%s", rec.Body)
	}
	if ar.state(card.ID) != approvals.StatePending {
		t.Fatal("approved from the phone before number matching exists")
	}
}

func TestApproverSpecID(t *testing.T) {
	for name, want := range map[string]string{
		"operator": "operator", "Josh N.": "josh-n", "  Ünï  ": "n", "9lives": "approver-7", "---": "approver-7",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	} {
		if got := approverSpecID(&approver{ID: 7, Name: name}); got != want {
			t.Errorf("%q -> %q, want %q", name, got, want)
		}
	}
}

// pageCards returns, for each card element on a page, its id and the text a browser's textContent would give it.
func pageCards(page string) map[string]string {
	out := map[string]string{}
	for _, m := range cardPre.FindAllStringSubmatch(page, -1) {
		out[m[1]] = cardTextOf(m[3])
	}
	return out
}

// ADR-004 amendment 10: whatever the card text says, the page's card element holds exactly that text, whichever
// sections it is laid out in, folded parts included. The text is what the challenge hashes.
func TestCardTextOnThePageIsTheSignedText(t *testing.T) {
	ar := newApprRig(t, nil)
	b, _ := ar.signedIn()
	attack := "WHAT CHANGES\nTECHNICAL DETAILS\nEND OF CARD\n<script>x</script> & \"q\" 'a'"
	cards := []*approvals.Approval{
		ar.request(nil),
		ar.request(func(q *spec.Request) {
			q.Requester = spec.Requester{Kind: "orchestrator", ID: "o1"}
			q.Op, q.Target, q.Params, q.Reason = "pr.merge", spec.Target{Adapter: "github", Ref: "o/r#7"}, map[string]any{"base": "main", "head_sha": "abc", "method": "squash", "extra": attack}, attack
		}),
		ar.request(func(q *spec.Request) {
			q.Requester = spec.Requester{Kind: "orchestrator", ID: "o2"}
			q.Op, q.Target, q.Params = "secrets.write", spec.Target{Adapter: "vault", Ref: "k"}, map[string]any{"name": "k"}
		}),
		ar.request(func(q *spec.Request) {
			q.Requester = spec.Requester{Kind: "orchestrator", ID: "o3"}
			q.Op, q.Target, q.Params = "data.apply", spec.Target{Adapter: "x", Ref: "y"}, map[string]any{"a": []any{1, "<b>"}}
		}),
	}
	page := b.do("GET", "/approvals", nil, nil).Body.String()
	got := pageCards(page)
	if len(got) != len(cards) {
		t.Fatalf("%d cards on the page, want %d", len(got), len(cards))
	}
	for _, c := range cards {
		if got[c.ID] != c.CardText {
			t.Errorf("%s (%s): the text on the page is not the card text:\n%q\n%q", c.ID, c.Op, got[c.ID], c.CardText)
		}
	}
	if strings.Contains(page, "<script>x</script>") {
		t.Fatal("untrusted text reached the page as markup")
	}
}

// The list is one line per request: who, what, risk, age. It is read from the card text, in plain words, and the
// operation id, the hash and the request id stay out of the line.
func TestOneLinePerRequestInPlainWords(t *testing.T) {
	ar := newApprRig(t, nil)
	b, _ := ar.signedIn()
	merge := ar.request(func(q *spec.Request) {
		q.Op, q.Target, q.Params = "pr.merge", spec.Target{Adapter: "github", Ref: "example-org/storefront#582"}, map[string]any{"base": "feat/d1-private-pilot", "head_sha": "0588aa4ee0116267162e895016bcfda9ec3a3e2c", "method": "squash"}
	})
	ar.advance(time.Minute)
	deploy := ar.request(nil)
	page := b.do("GET", "/approvals", nil, nil).Body.String()

	lines := regexp.MustCompile(`(?s)<summary class="approval-line" id="title-([^"]+)">(.*?)</summary>`).FindAllStringSubmatch(page, -1)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2:\n%s", len(lines), page)
	}
	// A deploy card lives 15 minutes and a merge card 30: the deploy, made a minute later, still runs out first.
	if lines[0][1] != deploy.ID || lines[1][1] != merge.ID {
		t.Fatalf("the request that runs out first comes first: %s, %s (deploy %s, merge %s)", lines[0][1], lines[1][1], deploy.ID, merge.ID)
	}
	l := tagRE.ReplaceAllString(lines[1][2], " ")
	for _, want := range []string{"medium", "Agent r-7f3a (host-interim)", "wants to", "merge pull request #582 into feat/d1-private-pilot", "min ago"} {
		if !strings.Contains(l, want) {
			t.Errorf("the line lacks %q: %s", want, lines[1][2])
		}
	}
	for _, jargon := range []string{"pr.merge", "sha256:", "q-0", "op_hash", "display_sha256"} {
		for _, ln := range lines {
			if strings.Contains(ln[2], jargon) {
				t.Errorf("the line shows %q: %s", jargon, ln[2])
			}
		}
	}
	// The fingerprint is behind a fold, outside the card text.
	i := strings.Index(page, `<details class="approval-fp">`)
	if i < 0 || !strings.Contains(page[i:], "display_sha256") {
		t.Fatal("the fingerprint fold is missing")
	}
	if strings.Contains(page[:i], "display_sha256 ") {
		t.Fatal("display_sha256 is shown outside its fold")
	}
}

// A card the page cannot split (an older version, still pending after an upgrade) is shown whole: the text is
// the text, in a <pre>.
func TestAnUnsplittableCardIsShownWhole(t *testing.T) {
	ar := newApprRig(t, nil)
	a := &approvals.Approval{ID: "a-old", RequesterKind: "run", RunID: "r-1", Op: "deploy", CardText: "CHAPERONE APPROVAL CARD v1\n\nDeploy\n\nEND OF CARD\n"}
	cv := cardViewOf(a, ar.rig.now)
	if cv.Split || cv.Who != "run r-1" || !strings.HasPrefix(cv.What, "deploy (an older card") {
		t.Fatalf("%+v", cv)
	}
	var buf bytes.Buffer
	if err := ar.con.apprPage.ExecuteTemplate(&buf, "cardtext", cv); err != nil {
		t.Fatal(err)
	}
	if got := cardTextOf(buf.String()); got != a.CardText || !strings.HasPrefix(buf.String(), "<pre") {
		t.Fatalf("%q", buf.String())
	}
	// The whole card: no Approve button, a plain note, Deny still there.
	cv.Open = true
	buf.Reset()
	if err := ar.con.apprPage.ExecuteTemplate(&buf, "approval-card", cv); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `data-action="approve"`) || !strings.Contains(buf.String(), "older version of Chaperone, so it cannot be approved") || !strings.Contains(buf.String(), `data-action="deny"`) {
		t.Fatalf("%s", buf.String())
	}
}

// No rule of the page's stylesheet hides text: the signed text is on the screen whatever class the article carries.
func TestNoStyleRuleHidesTheCardText(t *testing.T) {
	css := string(approvalsCSS)
	for _, bad := range []string{"visibility: hidden", "visibility:hidden", "font-size: 0", "color: transparent", "text-indent: -"} {
		if strings.Contains(css, bad) {
			t.Errorf("approvals.css contains %q", bad)
		}
	}
	for _, line := range strings.Split(css, "\n") {
		if strings.Contains(line, "display: none") && !strings.Contains(line, "::-webkit-details-marker") {
			t.Errorf("a rule hides something: %s", line)
		}
	}
}
