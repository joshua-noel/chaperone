package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/store"
)

// The Agents screen with the keys package behind it: the owner revokes an agent's key (the human stop), cancels a
// waiting enrolment, and is told when the policy has every key operation off.

type nopKeyLedger struct{}

func (nopKeyLedger) AppendTx(context.Context, *store.Tx, ops.Event) error { return nil }

type agentsRig struct {
	*scrRig
	store *keys.Store
	dec   *keys.Decider
}

// newAgentsRig is the screens rig with the Agents screen wired to a real keys store (and no ops service: nothing
// here starts a card).
func newAgentsRig(t *testing.T) *agentsRig {
	t.Helper()
	sr := newScrRig(t)
	ks, err := keys.New(keys.Config{
		DB: sr.db, Ledger: nopKeyLedger{}, PolicyVersion: func() string { return "test-policy" },
		Now: func() time.Time { return sr.rig.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	dec := keys.NewDecider(ks, nil)
	cfg := ScreensConfig{Version: "test", Runs: sr.runs, Orch: sr.orch, Ledger: sr.led, Policy: sr.pol, Projects: []string{"acme-shop"}, Keys: dec}
	if err := sr.con.UseScreens(cfg); err != nil {
		t.Fatal(err)
	}
	return &agentsRig{scrRig: sr, store: ks, dec: dec}
}

var keySeq int

// seedKey writes a claimed, live key of an agent for owner and returns its id.
func (ar *agentsRig) seedKey(owner, label string) string {
	ar.t.Helper()
	keySeq++
	suffix := strings.Repeat("0", 4) + string(rune('a'+keySeq%26))
	approval, request := "a-9"+suffix, "q-9"+suffix
	now := ar.rig.now.Unix()
	if _, err := ar.db.SQL().Exec(`INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, project, op, op_hash, class,
        policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix, request_expires_unix,
        decided_unix, approver, nonce, challenge_sha256, record_json)
        VALUES (?, ?, 'orchestrator', 'main', 'acme-shop', 'keys.issue', ?, 'high', 'p', '{}', '[]', '[]', 'card', ?, 'approved', 1, 2, 3, 'approver.operator', 'n', 'sha256:c', '{}')`,
		approval, request, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)); err != nil {
		ar.t.Fatal(err)
	}
	g := keys.Grant{
		Project: "acme-shop", Owner: owner, HolderKind: keys.HolderAgent, Holder: label,
		Ops: []string{"pr.view"}, Units: []string{"acme/shop"}, TTLHours: 24,
		ApprovalID: approval, RequestID: request, GrantedBy: "approver.operator", Claimant: "agent:" + owner + "/" + label,
	}
	k, err := ar.store.Issue(context.Background(), g)
	if err != nil {
		ar.t.Fatal(err)
	}
	if _, _, err := ar.store.Claim(context.Background(), k.ID, g.Claimant); err != nil {
		ar.t.Fatal(err)
	}
	_ = now
	return k.ID
}

func TestAgentsRoutesNeedACSRFTokenAndASession(t *testing.T) {
	ar := newAgentsRig(t)
	key := ar.seedKey("person:operator", "scout")
	b, _ := ar.signedIn()
	for _, p := range []string{"/agents/keys/" + key + "/revoke", "/agents/enrolments/en-0123456789abcdef/cancel"} {
		// A post with no CSRF header never reaches the handler.
		if rec := b.do("POST", p, nil, map[string]string{"HX-Request": "true"}); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without a CSRF token: %d", p, rec.Code)
		}
		// A post from another origin is refused too.
		if rec := b.do("POST", p, nil, map[string]string{"X-CSRF-Token": b.csrf(), "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "HX-Request": "true"}); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s from another origin: %d", p, rec.Code)
		}
	}
	if k, _ := ar.store.Get(context.Background(), key); k.State != "live" {
		t.Errorf("a refused post revoked the key: %+v", k)
	}
	// Signed out: a POST is an unauthorised htmx call, not a revoke.
	out := ar.browser(pcOrigin)
	if rec := out.do("POST", "/agents/keys/"+key+"/revoke", nil, map[string]string{"HX-Request": "true"}); rec.Code == http.StatusNoContent || rec.Code == http.StatusOK {
		t.Errorf("a signed-out revoke: %d", rec.Code)
	}
	if k, _ := ar.store.Get(context.Background(), key); k.State != "live" {
		t.Errorf("a signed-out post revoked the key: %+v", k)
	}
}

// The Revoke button is there for a live key, and a session is enough (revoking only takes access away): the key
// is revoked, the agent is stopped for good, and another person's key looks like no key.
func TestTheOwnerRevokesAnAgentKeyAtTheConsole(t *testing.T) {
	ar := newAgentsRig(t)
	mine := ar.seedKey("person:operator", "scout")
	theirs := ar.seedKey("person:someone-else", "bot")
	other := ar.seedKey("keymaker", "bot2") // owned by an orchestrator
	b, _ := ar.signedIn()

	page := get(t, b, "/agents")
	// Your own agent's key, and the key an orchestrator built (with its owner shown), are listed: the operator can
	// always see and end every key an orchestrator owns. Another person's agent looks like no agent.
	mustHave(t, "agents page", page, `hx-post="/agents/keys/`+mine+`/revoke"`, `aria-label="Revoke the key of scout"`, "stopped for good",
		`hx-post="/agents/keys/`+other+`/revoke"`, `aria-label="Revoke the key of bot2"`, `data-label="Owner">keymaker<`, `data-label="Owner">you<`)
	mustNotHave(t, "agents page", page, theirs)

	rec := hxPost(b, "/agents/keys/"+theirs+"/revoke", url.Values{})
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoke of another person's key: %d %s", rec.Code, rec.Body)
	}
	if k, _ := ar.store.Get(context.Background(), theirs); k.State != "live" || k.StoppedByHuman {
		t.Errorf("another person's key was changed: %+v", k)
	}
	// The key of an orchestrator is revoked at the console too, and that is not a stop of anything.
	if rec := hxPost(b, "/agents/keys/"+other+"/revoke", url.Values{}); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke of an orchestrator's key: %d %s", rec.Code, rec.Body)
	}
	if k, _ := ar.store.Get(context.Background(), other); k.State != "revoked" || k.StoppedByHuman {
		t.Errorf("the orchestrator's key after the console revoke: %+v", k)
	}
	if stopped, _ := ar.store.AgentStopped(context.Background(), "keymaker", "bot2"); stopped {
		t.Error("revoking an orchestrator's key stopped its agent for good")
	}
	rec = hxPost(b, "/agents/keys/"+mine+"/revoke", url.Values{})
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Redirect") != "/agents" {
		t.Fatalf("revoke: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	k, _ := ar.store.Get(context.Background(), mine)
	if k.State != "revoked" || !k.StoppedByHuman {
		t.Errorf("the key after the console revoke: %+v", k)
	}
	if stopped, _ := ar.store.AgentStopped(context.Background(), "person:operator", "scout"); !stopped {
		t.Error("the agent is not stopped")
	}
	if !strings.Contains(ar.logs.String(), "operator revoked an agent key") {
		t.Errorf("the revoke is not logged:\n%s", ar.logs)
	}
	// A revoked key has no button; a second post says it is already revoked.
	mustNotHave(t, "agents page after", get(t, b, "/agents"), `/agents/keys/`+mine+`/revoke`)
	if rec := hxPost(b, "/agents/keys/"+mine+"/revoke", url.Values{}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already revoked") {
		t.Errorf("a second revoke: %d %s", rec.Code, rec.Body)
	}
}

// Waiting enrolments are listed with their label, project and age, and Cancel ends one.
func TestWaitingEnrolmentsAreListedAndCanBeCancelled(t *testing.T) {
	ar := newAgentsRig(t)
	ctx := context.Background()
	start, err := ar.store.StartEnrolment(ctx, "acme-shop", "scout")
	if err != nil {
		t.Fatal(err)
	}
	ar.rig.advance(3 * time.Minute)
	b, _ := ar.signedIn()
	page := get(t, b, "/agents")
	mustHave(t, "agents page", page, "Agents waiting to be enrolled", "<code>scout</code>", "acme-shop", "3 min ago", `/agents/enrolments/`+start.ID+`/cancel`,
		`aria-label="Cancel the enrolment of scout"`)
	rec := hxPost(b, "/agents/enrolments/"+start.ID+"/cancel", url.Values{})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	mustNotHave(t, "agents page after", get(t, b, "/agents"), "Agents waiting to be enrolled")
	if poll, err := ar.store.PollEnrolment(ctx, start.ID, start.DeviceCode); err != nil || poll.State != "expired" {
		t.Errorf("the agent after the cancel: %+v %v", poll, err)
	}
	if rec := hxPost(b, "/agents/enrolments/"+start.ID+"/cancel", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("a second cancel: %d", rec.Code)
	}
}

// With all three key operations off in the policy, the page says keys are off, and still lets the owner revoke.
func TestAgentsPageSaysKeysAreOffWhenEveryKeyOperationIsOff(t *testing.T) {
	ar := newAgentsRig(t)
	key := ar.seedKey("person:operator", "scout")
	b, _ := ar.signedIn()
	page := get(t, b, "/agents")
	mustHave(t, "off page", page, "Agent keys are off", `id="keys-policy-off"`, `/agents/keys/`+key+`/revoke`)
	if ar.sr().keyOpsEnabled() {
		t.Error("the baseline has a key operation on")
	}
}

func (ar *agentsRig) sr() *screens { return ar.con.scr }

// With one key operation on in the baseline there is no "off" banner.
func TestAgentsPageHasNoOffBannerWhenAKeyOperationIsOn(t *testing.T) {
	ar := newAgentsRig(t)
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	on := strings.Replace(string(policy.BaselineBytes()), "keys.request:         { enabled: false", "keys.request:         { enabled: true", 1)
	if on == string(policy.BaselineBytes()) {
		t.Fatal("the baseline line for keys.request changed: update this test")
	}
	pack, err := policy.LoadBaseline([]byte(on), cat)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ScreensConfig{Version: "test", Runs: ar.runs, Orch: ar.orch, Ledger: ar.led, Policy: policy.NewEngine(cat, pack, ""), Keys: ar.dec}
	if err := ar.con.UseScreens(cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := ar.signedIn()
	mustNotHave(t, "on page", get(t, b, "/agents"), "Agent keys are off", "keys-policy-off")
	// The page is never framed, like every page with a state-changing control.
	rec := b.do("GET", "/agents", nil, nil)
	if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("the Agents page can be framed: %v", rec.Header())
	}
}
