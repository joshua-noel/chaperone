package redteam

// RT-24 with the real Google connectors (ticket L1-16). On 22 Oct an agent sent
// the demo email from the operator's personal account with no approval. These
// replays attack the real `mail.send` and `drive.share` adapters (the ones
// cmd/chapd installs) over a fake Google (googletest): no network, no real
// account. Threat model: TB4-T2 (a high-class op without a human), TB4-T5
// (data leaves the host through an op). Red-team list: RT-24, RT-12 (mail
// attachments), RT-25.
//
// What must hold:
//   - mail.send and drive.share are disabled in the shipped baseline;
//   - a request that names a recipient off the project's allowlist is refused
//     before a card exists, however it is asked;
//   - the message that goes out is byte for byte the message on the card (the
//     SHA-256 of the rendered MIME is on the card), and one changed character
//     after the approval is APPROVAL_HASH_MISMATCH;
//   - a secret in the subject, body or an attachment is REDACTION_BLOCKED;
//   - an attachment that is not the one hashed on the card is never sent;
//   - a Drive share above the project's role cap is refused;
//   - a revoked Google grant fails closed and raises an alert.
//
// To see them fail, remove the matching control in
// internal/connectors/google; mutation_test.go does exactly that.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

const (
	gAccount = "operator@example.com"
	gFriend  = "gilliano@example.com"
	gFile    = "1AbCdEfGhIjKlMnOpQrS"
)

type gAlerts struct {
	mu   sync.Mutex
	keys []string
}

func (a *gAlerts) RaiseGoogleAlert(_ context.Context, key, _ string) {
	a.mu.Lock()
	a.keys = append(a.keys, key)
	a.mu.Unlock()
}

func (a *gAlerts) n(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := 0
	for _, k := range a.keys {
		if k == key {
			c++
		}
	}
	return c
}

// gworld is a fake Google, signed in once, and the two real adapters over it.
type gworld struct {
	fake   *googletest.Server
	src    *google.Source
	gmail  *google.Gmail
	drive  *google.Drive
	pol    *policy.Google
	alerts *gAlerts
	mu     sync.Mutex
	atts   map[string][]byte
}

func (w *gworld) Get(sum string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if b, ok := w.atts[sum]; ok {
		return b, nil
	}
	return nil, google.ErrNoAttachment
}

func (w *gworld) stage(b []byte) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	sum := google.SumHex(b)
	w.atts[sum] = b
	return sum
}

// newGWorld builds the world over the rig's own vault and clock, so the same
// redaction registry masks what the connector holds.
func newGWorld(t *testing.T, g *rig) *gworld {
	t.Helper()
	ctx := context.Background()
	w := &gworld{fake: googletest.New(t), alerts: &gAlerts{}, atts: map[string][]byte{}}
	w.fake.Now = g.clock
	w.fake.AddFile(googletest.File{ID: gFile, Name: "Q3 plan", MimeType: "application/vnd.google-apps.document", CanShare: true})
	ep := google.Endpoints{Auth: w.fake.URL + "/auth", Token: w.fake.URL + "/token", Revoke: w.fake.URL + "/revoke", Gmail: w.fake.URL, Drive: w.fake.URL}
	w.pol = &policy.Google{}
	w.pol.Mail.AllowRecipients = []string{gFriend}
	w.pol.Drive.AllowRecipients = []string{gFriend}
	w.pol.Drive.MaxRole = "commenter"

	cc := google.ClientCreds{ClientID: googletest.ClientID, ClientSecret: googletest.ClientSecret}
	if err := google.SaveClient(ctx, g.vault, cc); err != nil {
		t.Fatal(err)
	}
	var err error
	w.src, err = google.NewSource(google.SourceConfig{Secrets: g.vault, Registry: g.reg, Endpoints: ep, Alert: w.alerts, Now: g.clock})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := google.Connect(ctx, google.ConnectConfig{
		Client: cc, Scopes: []string{google.ScopeGmailSend, google.ScopeDrive}, Endpoints: ep, Now: g.clock, Timeout: 10 * time.Second,
		OpenURL: func(u string) error { return w.fake.Approve(u, nil) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.src.Connected(ctx, ts); err != nil {
		t.Fatal(err)
	}
	pf := func(p string) *policy.Google {
		if p != rigProject {
			return nil
		}
		return w.pol
	}
	if w.gmail, err = google.NewGmail(google.GmailConfig{Source: w.src, Policy: pf, Attachments: w, Redactor: g.reg, Endpoints: ep}); err != nil {
		t.Fatal(err)
	}
	if w.drive, err = google.NewDrive(google.DriveConfig{Source: w.src, Policy: pf, Endpoints: ep}); err != nil {
		t.Fatal(err)
	}
	return w
}

// googleRig is the red-team rig with the real adapters for mail.send and
// drive.share and a stand-in approvals store.
func googleRig(t *testing.T, enable ...string) (*rig, *gworld, *fakeApprovals) {
	t.Helper()
	ap := &fakeApprovals{}
	var w *gworld
	g := newRig(t, rigOpts{enable: enable, approvals: ap, adapters: func(g *rig) map[string]ops.Adapter {
		w = newGWorld(t, g)
		return map[string]ops.Adapter{"mail.send": w.gmail, "drive.share": w.drive}
	}})
	return g, w, ap
}

func mailBody(params map[string]any) map[string]any {
	m := opBody("mail.send", gAccount, params)
	m["target"] = map[string]any{"adapter": "google", "ref": gAccount}
	return m
}

func shareBody(params map[string]any) map[string]any {
	m := opBody("drive.share", gAccount, params)
	m["target"] = map[string]any{"adapter": "google", "ref": gAccount}
	return m
}

func gMail(to string) map[string]any {
	return map[string]any{"to": []any{to}, "subject": "Demo follow-up", "body": "Hello from the demo.\nSee you Monday."}
}

func gShare(role string, to ...string) map[string]any {
	rc := make([]any, len(to))
	for i, a := range to {
		rc[i] = a
	}
	return map[string]any{"file_id": gFile, "file_name": "Q3 plan", "recipients": rc, "role": role, "link_visibility": "restricted"}
}

// asApproval turns an op body into a POST /v0/approvals body.
func asApproval(m map[string]any) map[string]any {
	a := map[string]any{"kind": "op", "reason": "red-team"}
	for k, v := range m {
		a[k] = v
	}
	return a
}

func TestRT24MailAndDriveStayDisabledInTheBaseline(t *testing.T) {
	g, w, _ := googleRig(t) // nothing enabled: the shipped baseline
	run, _ := g.mint("mail.send", "drive.share")
	for name, body := range map[string]map[string]any{"mail.send": mailBody(gMail(gFriend)), "drive.share": shareBody(gShare("reader", gFriend))} {
		st, resp := g.call("POST", "/v0/ops", run, body)
		if st != 403 {
			t.Fatalf("%s: %d %v", name, st, resp)
		}
		mustDenial(t, resp, "OP_DISABLED")
		// An approval request is no way round it.
		st, resp = g.call("POST", "/v0/approvals", run, asApproval(body))
		if st < 400 {
			t.Fatalf("%s approval request on a disabled op: %d %v", name, st, resp)
		}
	}
	if len(w.fake.Sent()) != 0 || len(w.fake.Permissions()) != 0 {
		t.Fatal("something left the building through a disabled op")
	}
	cat, pack, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	_ = cat
	for _, op := range []string{"mail.send", "drive.share"} {
		if pack.Ops[op].Enabled {
			t.Errorf("%s is enabled in the shipped baseline; enabling is a operator-approved policy PR", op)
		}
	}
	g.mustLedgerOK()
}

func TestRT24GoogleDemoEmailReplay(t *testing.T) {
	g, w, ap := googleRig(t, "mail.send")
	run, _ := g.mint("mail.send")
	mail := mailBody(gMail(gFriend))

	// The 22 Oct shape: the agent just sends it. Ten times, as the run and as
	// the orchestrator: refused, nothing leaves.
	for i := range 10 {
		st, body := g.call("POST", "/v0/ops", run, mail)
		if st != 403 {
			t.Fatalf("attempt %d: %d %v", i, st, body)
		}
		mustDenial(t, body, "OP_APPROVAL_REQUIRED")
	}
	orch := mailBody(gMail(gFriend))
	orch["project"] = rigProject
	if st, body := g.call("POST", "/v0/ops", g.OrchToken, orch); st != 403 {
		t.Fatalf("orchestrator: %d %v", st, body)
	} else {
		mustDenial(t, body, "OP_APPROVAL_REQUIRED")
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatal("the demo email went out without an approval")
	}

	// Control: the operator is asked once, sees a card, approves it.
	st, op := g.call("POST", "/v0/approvals", run, asApproval(mail))
	if st != 202 || op["state"] != "pending_approval" {
		t.Fatalf("%d %v", st, op)
	}
	aid := str(op["approval"].(map[string]any), "id")
	if len(w.fake.Sent()) != 0 {
		t.Fatal("the email went out before anyone decided")
	}

	// One character changed under the card's approval id: the approval does not
	// carry (the op hash covers every param).
	body := "Hello from the demo.\nSee you Monday."
	oneChar := map[string]map[string]any{
		"one character of the body":    {"to": []any{gFriend}, "subject": "Demo follow-up", "body": body + "!"},
		"one character of the subject": {"to": []any{gFriend}, "subject": "Demo follow-up.", "body": body},
		"a trailing space":             {"to": []any{gFriend}, "subject": "Demo follow-up", "body": body + " "},
	}
	for name, p := range oneChar {
		m := mailBody(p)
		m["approval_id"] = aid
		st, resp := g.call("POST", "/v0/ops", run, m)
		if st != 409 {
			t.Fatalf("%s: %d %v", name, st, resp)
		}
		mustDenial(t, resp, "APPROVAL_HASH_MISMATCH")
	}
	// A message to someone off the list is refused outright, approval or not.
	m := mailBody(map[string]any{"to": []any{gFriend, "x@example.net"}, "subject": "Demo follow-up", "body": body})
	m["approval_id"] = aid
	if st, resp := g.call("POST", "/v0/ops", run, m); st < 400 {
		t.Fatalf("a second recipient rode the first card: %d %v", st, resp)
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatal("a changed message went out under the first approval")
	}

	// Approved: exactly the approved message goes, once, and its hash is the card's.
	g.decide(t, ap, str(op, "id"), aid, true)
	waitOpState(t, g, run, str(op, "id"), "succeeded")
	sent := w.fake.Sent()
	if len(sent) != 1 {
		t.Fatalf("%d messages sent after one approval", len(sent))
	}
	for _, want := range []string{"To: " + gFriend, "Subject: Demo follow-up", gAccount} {
		if !bytes.Contains(sent[0].Raw, []byte(want)) {
			t.Errorf("the sent message lacks %q:\n%s", want, sent[0].Raw)
		}
	}
	again := mailBody(gMail(gFriend))
	again["approval_id"] = aid
	g.call("POST", "/v0/ops", run, again)
	if n := len(w.fake.Sent()); n != 1 {
		t.Fatalf("one approval sent %d messages", n)
	}
	// After the approval and the send: one character changed is still
	// APPROVAL_HASH_MISMATCH, and nothing more goes out.
	for name, p := range oneChar {
		m := mailBody(p)
		m["approval_id"] = aid
		st, resp := g.call("POST", "/v0/ops", run, m)
		if st != 409 {
			t.Fatalf("after approval, %s: %d %v", name, st, resp)
		}
		mustDenial(t, resp, "APPROVAL_HASH_MISMATCH")
	}
	if n := len(w.fake.Sent()); n != 1 {
		t.Fatalf("%d messages sent", n)
	}
	g.mustLedgerOK()
}

// A recipient off the allowlist is refused before a card exists.
func TestRT24OffListRecipientNeverGetsACard(t *testing.T) {
	g, w, ap := googleRig(t, "mail.send")
	run, _ := g.mint("mail.send")
	for name, p := range map[string]map[string]any{
		"the attacker's address":   gMail("attacker@example.net"),
		"one bad among good":       {"to": []any{gFriend, "attacker@example.net"}, "subject": "s", "body": "b"},
		"bcc":                      {"to": []any{gFriend}, "bcc": []any{"attacker@example.net"}, "subject": "s", "body": "b"},
		"suffix of an allowed one": gMail("attacker@" + "evil." + "example.com"),
		"a display name":           gMail("Gil <" + gFriend + ">"),
		"header injection":         gMail(gFriend + "\r\nBcc: attacker@example.net"),
	} {
		for _, path := range []string{"/v0/ops", "/v0/approvals"} {
			body := mailBody(p)
			if path == "/v0/approvals" {
				body = asApproval(body)
			}
			st, resp := g.call("POST", path, run, body)
			if st < 400 {
				t.Fatalf("%s via %s: %d %v", name, path, st, resp)
			}
		}
	}
	if ap.cards() != 0 {
		t.Fatalf("%d approval cards exist for requests that must be refused", ap.cards())
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatal("something was sent")
	}
	st, resp := g.call("POST", "/v0/approvals", run, asApproval(mailBody(gMail("attacker@example.net"))))
	if st != 403 {
		t.Fatalf("%d %v", st, resp)
	}
	mustDenial(t, resp, "OP_POLICY_REFUSED")
	// Control: the listed address gets its card.
	if st, resp := g.call("POST", "/v0/approvals", run, asApproval(mailBody(gMail(gFriend)))); st != 202 {
		t.Fatalf("control: %d %v", st, resp)
	}
	g.mustLedgerOK()
}

// A secret in the message is refused, not sent and not stored.
func TestRT24SecretInMailIsRefused(t *testing.T) {
	g, w, ap := googleRig(t, "mail.send")
	run, _ := g.mint("mail.send")
	pat := "ghp_" + strings.Repeat("Z", 36)
	keyFile := w.stage([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"))
	for name, p := range map[string]map[string]any{
		"in the body": {"to": []any{gFriend}, "subject": "s", "body": "token: " + pat},
		"in an attachment": {"to": []any{gFriend}, "subject": "s", "body": "see file",
			"attachments": []any{map[string]any{"name": "notes.txt", "sha256": keyFile}}},
	} {
		st, resp := g.call("POST", "/v0/approvals", run, asApproval(mailBody(p)))
		if st < 400 {
			t.Fatalf("%s: %d %v", name, st, resp)
		}
		if strings.Contains(fmt.Sprint(resp), pat) || strings.Contains(fmt.Sprint(resp), "MIIEowIBAAKCAQEA") {
			t.Fatalf("%s: the denial quotes the secret: %v", name, resp)
		}
	}
	if ap.cards() != 0 || len(w.fake.Sent()) != 0 {
		t.Fatal("a card or a send exists for a message that holds a secret")
	}
	g.mu.Lock()
	seen := append([]string(nil), g.seen...)
	g.mu.Unlock()
	for _, s := range seen {
		if strings.Contains(s, pat) {
			t.Fatal("a response echoed the secret")
		}
	}
}

// The attachment on the card is the attachment that is sent.
func TestRT24SwappedAttachmentIsNotSent(t *testing.T) {
	g, w, ap := googleRig(t, "mail.send")
	run, _ := g.mint("mail.send")
	sum := w.stage([]byte("the figures the operator approved"))
	p := gMail(gFriend)
	p["attachments"] = []any{map[string]any{"name": "figures.txt", "sha256": sum}}
	st, op := g.call("POST", "/v0/approvals", run, asApproval(mailBody(p)))
	if st != 202 {
		t.Fatalf("%d %v", st, op)
	}
	// Between the card and the release, the staged file is replaced.
	w.mu.Lock()
	w.atts[sum] = []byte("something else entirely")
	w.mu.Unlock()
	aid := str(op["approval"].(map[string]any), "id")
	g.decide(t, ap, str(op, "id"), aid, true)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, body := g.call("GET", "/v0/ops/"+str(op, "id"), run, nil)
		if s := body["state"]; s == "failed" || s == "refused" || s == "succeeded" || s == "unconfirmed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, body := g.call("GET", "/v0/ops/"+str(op, "id"), run, nil)
	if body["state"] != "failed" && body["state"] != "refused" {
		t.Fatalf("a swapped attachment must end refused or failed, got %v", body["state"])
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatal("a message with a swapped attachment was sent")
	}
	g.mustLedgerOK()
}

func TestRT24DriveRoleCapAndAllowlist(t *testing.T) {
	g, w, ap := googleRig(t, "drive.share")
	run, _ := g.mint("drive.share")
	for name, p := range map[string]map[string]any{
		"writer over the commenter cap": gShare("writer", gFriend),
		"owner":                         gShare("owner", gFriend),
		"off the allowlist":             gShare("reader", "attacker@example.net"),
		"anyone with the link": func() map[string]any {
			m := gShare("reader", gFriend)
			m["link_visibility"] = "anyone"
			return m
		}(),
	} {
		st, resp := g.call("POST", "/v0/approvals", run, asApproval(shareBody(p)))
		if st < 400 {
			t.Fatalf("%s: %d %v", name, st, resp)
		}
	}
	if ap.cards() != 0 || len(w.fake.Permissions()) != 0 {
		t.Fatal("a card or a permission exists for a share that must be refused")
	}
	// Control: the cap itself is allowed, approved and done once, with no
	// notification mail and as a named person.
	st, op := g.call("POST", "/v0/approvals", run, asApproval(shareBody(gShare("commenter", gFriend))))
	if st != 202 {
		t.Fatalf("control: %d %v", st, op)
	}
	g.decide(t, ap, str(op, "id"), str(op["approval"].(map[string]any), "id"), true)
	waitOpState(t, g, run, str(op, "id"), "succeeded")
	perms := w.fake.Permissions()
	if len(perms) != 1 || perms[0].Role != "commenter" || perms[0].Type != "user" || perms[0].Notify || perms[0].Email != gFriend {
		t.Fatalf("permissions: %+v", perms)
	}
	g.mustLedgerOK()
}

func TestRT24RevokedGoogleGrantFailsClosed(t *testing.T) {
	g, w, _ := googleRig(t, "mail.send")
	run, _ := g.mint("mail.send")
	w.fake.RevokeAll()
	w.fake.ExpireAccess()
	// The monitor (or the next use) finds out and raises the alert.
	google.Monitor{Source: w.src}.Probe(context.Background())
	if w.alerts.n(google.AlertReauth) != 1 {
		t.Fatalf("no alert for a revoked grant: %v", w.alerts.keys)
	}
	st, resp := g.call("POST", "/v0/approvals", run, asApproval(mailBody(gMail(gFriend))))
	if st != 403 {
		t.Fatalf("%d %v", st, resp)
	}
	mustDenial(t, resp, "OP_POLICY_REFUSED")
	if !strings.Contains(fmt.Sprint(resp["why"]), "connect google") {
		t.Errorf("the denial must say how to fix it: %v", resp["why"])
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatal("sent with a revoked grant")
	}
}

// The card carries the whole message, and the approval is bound to it. This
// uses the real approvals engine (real card text, real op hash).
func TestRT24CardShowsTheRenderedMessage(t *testing.T) {
	_, w, _ := googleRig(t, "mail.send")
	x := newEng(t, approvals.Limits{PerRun: 50, PerProject: 50, Total: 100})
	sum := w.stage([]byte("a,b\n1,2\n"))
	params := map[string]any{
		"to": []any{gFriend}, "subject": "Q3 numbers", "body": "Hi Gilliano,\nthe numbers are attached.\nThanks",
		"attachments": []any{map[string]any{"name": "numbers.csv", "sha256": sum}},
	}
	r := x.req(func(r *spec.Request) {
		r.Op = "mail.send"
		r.Target = spec.Target{Adapter: "google", Ref: gAccount}
		r.Params = params
	})
	cr, err := w.gmail.Check(context.Background(), &ops.Request{
		ID: r.RequestID, Op: "mail.send", Project: rigProject, Target: r.Target, Params: params,
	})
	if err != nil {
		t.Fatal(err)
	}
	var ev []approvals.Evidence
	for _, e := range cr.Evidence {
		ev = append(ev, approvals.Evidence{Title: e.Name, Body: e.Text})
	}
	var res approvals.Result
	err = x.e.Atomic(context.Background(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = x.e.RequestTx(ctx, tx, approvals.RequestInput{Request: r, PolicyVersion: engPolicy, Checks: checksOK(), Evidence: ev})
		return res.Effects, err
	})
	if err != nil || res.Refusal != nil {
		t.Fatalf("%v %v", err, res.Refusal)
	}
	a := res.Approval
	for _, want := range []string{
		"send an email to " + gFriend, "Sent from account: google / " + gAccount, gFriend, "Q3 numbers",
		"    | Hi Gilliano,", "    | the numbers are attached.", "numbers.csv", sum, "Rendered message:",
	} {
		if !strings.Contains(a.CardText, want) {
			t.Errorf("the card lacks %q:\n%s", want, a.CardText)
		}
	}
	// The hash on the card is the hash of the bytes Gmail receives.
	var cardHash string
	for _, l := range strings.Split(a.CardText, "\n") {
		if _, after, ok := strings.Cut(l, "Rendered message: "); ok {
			_, h, _ := strings.Cut(after, "SHA-256 ")
			cardHash = strings.TrimSpace(h)
		}
	}
	if cardHash == "" {
		t.Fatalf("no rendered hash on the card:\n%s", a.CardText)
	}
	x.mustApprove(a)
	out, err := w.gmail.Execute(context.Background(), &ops.Request{
		ID: r.RequestID, Op: "mail.send", Project: rigProject, Target: r.Target, Params: params, ExecutionID: "x-1",
	})
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("%+v %v", out, err)
	}
	got := sha256.Sum256(w.fake.Sent()[0].Raw)
	if hex.EncodeToString(got[:]) != cardHash {
		t.Fatalf("the hash of the message Gmail received is not the hash on the card")
	}

	// One character changed after the approval: the engine refuses it.
	changed := r
	changed.Params = map[string]any{
		"to": []any{gFriend}, "subject": "Q3 numbers", "body": "Hi Gilliano,\nthe numbers are attached.\nThanks!",
		"attachments": params["attachments"],
	}
	wantCode(t, x.consume(a, changed), approvals.CodeHashMismatch)
}
