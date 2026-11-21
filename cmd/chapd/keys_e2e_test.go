package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// Tracer 1 of custom keys, end to end on the real chapd: the real ledger, policy pack, approvals engine and op
// pipeline over a fake GitHub, with the Windows Hello stand-in as the verifier.
//
//	keymaker asks for a key (a card) -> the operator signs it with Hello -> the op runs and writes the key's row
//	-> keymaker claims the key once -> a call under the key goes through policy and the ledger like any other
//	-> a high op under the key raises a card, which the key cannot decide -> revoke -> the next call is refused.

type keysE2E struct {
	*apprE2E
	maker string // the keymaker orchestrator's token
}

func newKeysE2E(t *testing.T) *keysE2E {
	t.Helper()
	var maker string
	e := newApprE2E(t, func(cfg *Config, dir, db string) {
		cfg.baselineYAML = []byte(strings.NewReplacer(
			"keys.issue:           { enabled: false", "keys.issue:           { enabled: true",
		).Replace(string(policy.BaselineBytes())))
		file := filepath.Join(dir, "keymaker.token")
		var out, errb bytes.Buffer
		if code := orchCmd([]string{"issue", "-db", db, "-instance", "test", "-id", "keymaker", "-project", "storefront",
			"-ops", "keys.issue,pr.view,pr.diff", "-token-file", file, "-days", "1"}, &out, &errb); code != 0 {
			t.Fatalf("orch issue keymaker: %d %s", code, errb.String())
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		maker = strings.TrimSpace(string(raw))
	})
	return &keysE2E{apprE2E: e, maker: maker}
}

func (e *keysE2E) issueBody(extra map[string]any) map[string]any {
	params := map[string]any{
		"holder": "scout", "holder_kind": "agent", "ops": []any{"pr.diff", "pr.view"},
		"units": []any{"example-org/storefront"}, "ttl_hours": 24, "rate_per_hour": 300,
	}
	for k, v := range extra {
		if v == nil {
			delete(params, k)
		} else {
			params[k] = v
		}
	}
	return map[string]any{
		"op": "keys.issue", "project": "storefront", "reason": "scout reads pull requests",
		"target": map[string]any{"adapter": "chaperone", "ref": "key:scout"}, "params": params,
	}
}

// grant asks for a key, signs the card, waits for the op and returns the key's id.
func (e *keysE2E) grant(extra map[string]any) string {
	e.t.Helper()
	body := e.issueBody(extra)
	body["kind"] = "op"
	st, op := e.call("POST", "/v0/approvals", e.maker, body)
	if st != http.StatusAccepted || op["state"] != "pending_approval" {
		e.t.Fatalf("request the key: %d %v", st, op)
	}
	aid := approvalOf(e.t, op)
	if _, err := e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) }); err != nil {
		e.t.Fatal(err)
	}
	done := e.waitMaker(op["id"].(string), "succeeded")
	res, _ := done["result"].(map[string]any)
	id, _ := res["key_id"].(string)
	if id == "" {
		e.t.Fatalf("the grant has no key id: %v", done)
	}
	return id
}

// waitMaker waits for an op of the keymaker orchestrator to reach a state.
func (e *keysE2E) waitMaker(id, want string) map[string]any {
	e.t.Helper()
	var last map[string]any
	for range 300 {
		_, last = e.call("GET", "/v0/ops/"+id, e.maker, nil)
		if last["state"] == want {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("op %s is %v, want %s: %v", id, last["state"], want, last)
	return nil
}

func (e *keysE2E) view(token string, n int) (int, map[string]any) {
	return e.call("POST", "/v0/ops", token, map[string]any{
		"op": "pr.view", "project": "storefront",
		"target": map[string]any{"adapter": "github", "ref": "example-org/storefront#" + strconv.Itoa(n)}, "params": map[string]any{},
	})
}

func TestE2EAKeyYouBuildYourself(t *testing.T) {
	e := newKeysE2E(t)
	n, _ := e.mediumPR("agent/for-scout")
	ctx := context.Background()

	// 1. Asked for directly, a key is a card: nothing is made before the operator signs.
	st, body := e.call("POST", "/v0/ops", e.maker, e.issueBody(nil))
	if st != http.StatusForbidden {
		t.Fatalf("direct keys.issue: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_APPROVAL_REQUIRED")
	req := e.issueBody(nil)
	req["kind"] = "op"
	st, op := e.call("POST", "/v0/approvals", e.maker, req)
	if st != http.StatusAccepted {
		t.Fatalf("request: %d %v", st, op)
	}
	aid := approvalOf(t, op)
	card := e.card(aid)
	if card.Op != "keys.issue" || card.Class != approvals.ClassHigh || card.State != approvals.StatePending {
		t.Fatalf("card: %+v", card)
	}
	// The card says, in the text the operator signs, who gets what, where, for how long and how fast.
	for _, want := range []string{
		"give agent scout a key that can use pr.diff, pr.view on example-org/storefront",
		"The key can do exactly these", "Repositories", "example-org/storefront",
		"Lasts (hours, from approval): 24", "Calls an hour at most: 300",
		"What this key can do", "It cannot approve anything, issue or revoke other keys, or do a critical action",
	} {
		if !strings.Contains(card.CardText, want) {
			t.Errorf("the card does not say %q:\n%s", want, card.CardText)
		}
	}
	if strings.Contains(card.CardText, "chap_key_") {
		t.Error("the card holds a key")
	}
	var keysBefore int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM keys`).Scan(&keysBefore)
	if keysBefore != 0 {
		t.Fatalf("%d keys exist before the card was signed", keysBefore)
	}

	// 2. Hello signs it; the op runs and writes the key's row (no token yet).
	if _, err := e.helloApprove(aid, func(ch *approvals.Challenge) []byte { return answerFor(ch.Raw) }); err != nil {
		t.Fatal(err)
	}
	done := e.waitMaker(op["id"].(string), "succeeded")
	res, _ := done["result"].(map[string]any)
	keyID, _ := res["key_id"].(string)
	if !strings.HasPrefix(keyID, "k-") || res["claim_deadline"] == "" {
		t.Fatalf("result: %v", res)
	}
	st, listed := e.call("GET", "/v0/keys", e.maker, nil)
	items, _ := listed["items"].([]any)
	if st != http.StatusOK || len(items) != 1 {
		t.Fatalf("list: %d %v", st, listed)
	}
	k := items[0].(map[string]any)
	if k["state"] != "granted" || k["holder"] != "scout" || k["owner"] != "keymaker" || k["granted_by"] == "" || k["approval_id"] != aid || k["fingerprint"] != nil {
		t.Errorf("granted key: %v", k)
	}
	if st, _ := e.view("chap_key_"+strings.Repeat("A", 43), n); st != http.StatusUnauthorized {
		t.Errorf("a made-up key was accepted: %d", st)
	}

	// 3. The claim: only the caller that asked, once; the token is in that one body and nowhere else.
	if st, _ := e.call("POST", "/v0/keys/"+keyID+"/claim", e.token, nil); st != http.StatusNotFound {
		t.Errorf("another orchestrator claimed the key: %d", st)
	}
	st, claimed := e.call("POST", "/v0/keys/"+keyID+"/claim", e.maker, nil)
	if st != http.StatusOK {
		t.Fatalf("claim: %d %v", st, claimed)
	}
	token, _ := claimed["token"].(string)
	if !strings.HasPrefix(token, "chap_key_") || len(token) != len("chap_key_")+43 {
		t.Fatalf("the claim has no token")
	}
	if st, again := e.call("POST", "/v0/keys/"+keyID+"/claim", e.maker, nil); st != http.StatusConflict {
		t.Errorf("a second claim: %d %v", st, again)
	}
	if st, body := e.call("GET", "/v0/keys/"+keyID, e.maker, nil); st != http.StatusOK || body["state"] != "live" || body["fingerprint"] == "" {
		t.Errorf("claimed key: %d %v", st, body)
	}

	// 4. A call under the key goes through the same pipeline: policy, op row, ledger.
	st, view := e.view(token, n)
	if st != http.StatusOK || view["outcome"] != "succeeded" {
		t.Fatalf("pr.view under the key: %d %v", st, view)
	}
	rq := view["requester"].(map[string]any)
	if rq["kind"] != "key" || rq["key_id"] != keyID || rq["owner"] != "keymaker" || rq["holder"] != "scout" {
		t.Errorf("requester: %v", rq)
	}
	// ... but only inside its list, its project and its repository.
	if st, body := e.call("POST", "/v0/ops", token, map[string]any{
		"op": "pr.checks", "project": "storefront", "target": map[string]any{"adapter": "github", "ref": "example-org/storefront#" + strconv.Itoa(n)}, "params": map[string]any{},
	}); st != http.StatusForbidden {
		t.Errorf("an op outside the key's list: %d %v", st, body)
	} else {
		mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	}
	if st, body := e.call("POST", "/v0/ops", token, map[string]any{
		"op": "pr.view", "project": "storefront", "target": map[string]any{"adapter": "github", "ref": "example-org/elsewhere#1"}, "params": map[string]any{},
	}); st != http.StatusForbidden {
		t.Errorf("another repository: %d %v", st, body)
	} else {
		mustValidDenial(t, body, "SCOPE_PATH")
	}

	// 5. A key never approves, never issues, never reads secrets: refused, and the refusal is ledgered.
	for _, op := range []string{"keys.issue", "secrets.write", "repo.settings", "policy.activate", "approvers.enroll"} {
		st, body := e.call("POST", "/v0/ops", token, map[string]any{
			"op": op, "project": "storefront", "target": map[string]any{"adapter": "chaperone", "ref": "x"}, "params": map[string]any{},
		})
		if st != http.StatusForbidden {
			t.Errorf("%s under a key: %d %v", op, st, body)
			continue
		}
		mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	}
	if cards, _ := e.app.Approvals.Pending(ctx); len(cards) != 0 {
		t.Errorf("a refused op left %d cards", len(cards))
	}
	// A token cannot decide an approval: a key that tries is a POLICY_BREACH, like a run token.
	req2 := e.issueBody(map[string]any{"holder": "other"})
	req2["kind"] = "op"
	_, op2 := e.call("POST", "/v0/approvals", e.maker, req2)
	aid2 := approvalOf(t, op2)
	_, err := e.app.Approvals.BeginDecision(ctx, approvals.BeginInput{ApprovalID: aid2, Actor: approvals.Actor{Kind: approvals.ActorKey, ID: keyID}, Origin: testOrigin, Binding: []byte("b")})
	wantRefusal(t, err, approvals.CodeBreach)
	if e.card(aid2).State != approvals.StatePending {
		t.Error("a key decided a card")
	}

	// 6. Every call is in the ledger against the key, and the chain verifies.
	var asKey int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.request' AND event LIKE '%key.` + keyID + `%'`).Scan(&asKey)
	if asKey < 2 {
		t.Errorf("op.request events of the key: %d", asKey)
	}
	var claimEvents, tokenInLedger int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event LIKE '%keys.claim%'`).Scan(&claimEvents)
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event LIKE '%` + strings.TrimPrefix(token, "chap_key_") + `%'`).Scan(&tokenInLedger)
	if claimEvents == 0 || tokenInLedger != 0 {
		t.Errorf("claim events %d, token in the ledger %d", claimEvents, tokenInLedger)
	}

	// 7. Revoke: the next call is refused, and the revoke is in the ledger.
	if st, body := e.call("POST", "/v0/keys/"+keyID+"/revoke", e.maker, nil); st != http.StatusOK || body["state"] != "revoked" {
		t.Fatalf("revoke: %d %v", st, body)
	}
	st, body = e.view(token, n)
	if st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Fatalf("the next call under a revoked key: %d %v", st, body)
	}
	mustValidDenial(t, body, "TOKEN_REVOKED")
	if st, again := e.call("POST", "/v0/keys/"+keyID+"/revoke", e.maker, nil); st != http.StatusConflict {
		t.Errorf("revoking twice: %d %v", st, again)
	}
	rep, err := e.app.Ledger.Verify(ctx, false)
	if err != nil || !rep.OK() {
		t.Fatalf("ledger verify: %v %v", err, rep.Problems())
	}
}

// P2-2: a key built directly holds only what its orchestrator's own token holds. The keymaker holds keys.issue, pr.view
// and pr.diff, so a key with pr.checks is refused before any card is made.
func TestE2EADirectKeyCannotHoldWhatItsOrchestratorDoesNot(t *testing.T) {
	e := newKeysE2E(t)
	req := e.issueBody(map[string]any{"ops": []any{"pr.checks", "pr.view"}})
	st, body := e.call("POST", "/v0/ops", e.maker, req)
	if st != http.StatusForbidden {
		t.Fatalf("direct keys.issue: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if why, _ := body["why"].(string); !strings.Contains(why, "pr.checks") || !strings.Contains(why, "your own token") {
		t.Errorf("why = %v", body["why"])
	}
	req["kind"] = "op"
	if st, body := e.call("POST", "/v0/approvals", e.maker, req); st != http.StatusForbidden {
		t.Errorf("a card for a key beyond its orchestrator: %d %v", st, body)
	}
	if cards, _ := e.app.Approvals.Pending(context.Background()); len(cards) != 0 {
		t.Errorf("%d cards were made", len(cards))
	}
	// What it holds itself is fine.
	if id := e.grant(nil); id == "" {
		t.Error("no key for ops the orchestrator holds")
	}
}

// A revoke with a token is never a human stop: the orchestrator that owns a key may revoke it, the key stops
// working at once, and the agent is not stopped, so a new key can be asked for. The human stop is the owner's
// revoke at the console (TestE2EAgentAsksOwnerTaps).
func TestE2EARevokeByAnOrchestratorIsNotAHumanStop(t *testing.T) {
	e := newKeysE2E(t)
	n, _ := e.mediumPR("agent/for-scout")
	id := e.grant(nil)
	_, claimed := e.call("POST", "/v0/keys/"+id+"/claim", e.maker, nil)
	token, _ := claimed["token"].(string)
	if st, _ := e.view(token, n); st != http.StatusOK {
		t.Fatalf("the key does not work: %d", st)
	}
	if st, body := e.call("POST", "/v0/keys/"+id+"/revoke", e.maker, nil); st != http.StatusOK || body["state"] != "revoked" || body["stopped_by_human"] == true {
		t.Fatalf("revoke: %d %v", st, body)
	}
	st, body := e.view(token, n)
	mustValidDenial(t, body, "TOKEN_REVOKED")
	if strings.Contains(body["why"].(string), "stopped by a human") || st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Errorf("the revoked key is told: %d %v", st, body["why"])
	}
	// The agent is not stopped: the same request for a key is a card again.
	req := e.issueBody(nil)
	req["kind"] = "op"
	if st, body := e.call("POST", "/v0/approvals", e.maker, req); st != http.StatusAccepted {
		t.Errorf("a card for the same agent after the revoke: %d %v", st, body)
	}
	var stopped int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM key_agents`).Scan(&stopped)
	if stopped != 0 {
		t.Errorf("%d agents were stopped by a token's revoke", stopped)
	}
}

// Operator decisions at the op boundary: critical never, the 7- and 30-day limits, a key that is not in its project.
func TestE2EKeyRulesRefuseBeforeACardIsMade(t *testing.T) {
	e := newKeysE2E(t)
	for _, c := range []struct {
		name  string
		extra map[string]any
		why   string
	}{
		{"a critical op", map[string]any{"ops": []any{"pr.view", "repo.settings"}}, "can never be in a key"},
		{"keys.issue itself", map[string]any{"ops": []any{"keys.issue"}}, "can never be in a key"},
		{"31 days", map[string]any{"ttl_hours": 31 * 24}, "at most 30 days"},
		{"no lifetime stated", map[string]any{"ttl_hours": nil}, "are required"},
		{"ops out of order", map[string]any{"ops": []any{"pr.view", "pr.diff"}}, "sorted order"},
		{"a rate above the default", map[string]any{"rate_per_hour": 301}, "lowered, never raised"},
		{"another repository", map[string]any{"units": []any{"example-org/elsewhere"}}, "cannot cover"},
		{"no repository for a pull-request op", map[string]any{"units": nil}, "names the repository"},
		{"a param nobody defined", map[string]any{"owner": "someone-else"}, "unknown param"},
	} {
		body := e.issueBody(c.extra)
		body["kind"] = "op"
		st, got := e.call("POST", "/v0/approvals", e.maker, body)
		if st != http.StatusForbidden && st != http.StatusBadRequest {
			t.Errorf("%s: %d %v", c.name, st, got)
			continue
		}
		if why, _ := got["why"].(string); !strings.Contains(why, c.why) {
			t.Errorf("%s: why = %q, want %q", c.name, got["why"], c.why)
		}
	}
	if cards, _ := e.app.Approvals.Pending(context.Background()); len(cards) != 0 {
		t.Errorf("%d cards were made for refused requests", len(cards))
	}
}

// A key built by an orchestrator is the orchestrator's to see and revoke, so it must not outlive the orchestrator's
// access to it. When the operator revokes the orchestrator, every key it owns is revoked in the same transaction
// (by chapd, not a human stop, in the ledger), and the operator sees the key at the console and can end it there
// whoever owns it.
func TestE2EAKeyEndsWithItsOrchestratorAndTheOperatorCanAlwaysRevokeIt(t *testing.T) {
	e := newKeysE2E(t)
	ctx := context.Background()
	n, _ := e.mediumPR("agent/orphan")
	id := e.grant(nil)
	_, claimed := e.call("POST", "/v0/keys/"+id+"/claim", e.maker, nil)
	token, _ := claimed["token"].(string)
	if st, _ := e.view(token, n); st != http.StatusOK {
		t.Fatalf("the key does not work: %d", st)
	}
	// The console lists it, with its owner, before anything is revoked.
	list, err := e.app.KeyDecider.Keys(ctx, "operator")
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].Owner != "keymaker" {
		t.Fatalf("the console's keys: %+v %v", list, err)
	}

	// The operator revokes the orchestrator (the console's Revoke orchestrator button).
	if err := e.app.Orch.Revoke(ctx, "keymaker", "console"); err != nil {
		t.Fatal(err)
	}
	st, body := e.view(token, n)
	if st == http.StatusOK {
		t.Fatalf("the key of a revoked orchestrator still works: %v", body)
	}
	mustValidDenial(t, body, "TOKEN_REVOKED")
	k, err := e.app.Keys.Get(ctx, id)
	if err != nil || k.State != "revoked" || k.StoppedByHuman || k.RevokedBy != "chapd" {
		t.Errorf("the key after the orchestrator was revoked: %+v %v", k, err)
	}
	var stopped int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM key_agents`).Scan(&stopped)
	if stopped != 0 {
		t.Errorf("%d agents stopped by the cascade", stopped)
	}
	var events int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.request' AND event LIKE '%keys.revoke%' AND event LIKE '%` + id + `%'`).Scan(&events)
	if events != 1 {
		t.Errorf("%d ledger events for the revoke of the key, want 1", events)
	}
	// Another orchestrator still gets "no such key", and the operator still sees the key at the console.
	if st, _ := e.call("POST", "/v0/keys/"+id+"/revoke", e.token, nil); st != http.StatusNotFound {
		t.Errorf("another orchestrator's revoke: %d", st)
	}
	if list, _ := e.app.KeyDecider.Keys(ctx, "operator"); len(list) != 1 || list[0].State != "revoked" {
		t.Errorf("the console's keys after: %+v", list)
	}
}

// A key that outlives its orchestrator some other way (its token expired: nothing revoked it) is the operator's to end
// at the console, and that is not a stop of the agent.
func TestE2ETheOperatorRevokesAnOrchestratorsKeyAtTheConsole(t *testing.T) {
	e := newKeysE2E(t)
	n, _ := e.mediumPR("agent/console")
	id := e.grant(nil)
	_, claimed := e.call("POST", "/v0/keys/"+id+"/claim", e.maker, nil)
	token, _ := claimed["token"].(string)
	k, err := e.app.KeyDecider.Revoke(context.Background(), "operator", id)
	if err != nil || k.State != "revoked" || k.StoppedByHuman || k.RevokedBy != "person.operator" {
		t.Fatalf("the operator's revoke of an orchestrator's key: %+v %v", k, err)
	}
	if st, body := e.view(token, n); st == http.StatusOK {
		t.Fatalf("the key still works: %v", body)
	}
}

// Re-issuing an orchestrator's token without one of its projects revokes the keys it owns in that project, and leaves
// the keys in the projects it keeps.
func TestE2EAKeyInADroppedProjectIsRevokedWhenTheTokenIsReissued(t *testing.T) {
	e := newKeysE2E(t)
	ctx := context.Background()
	n, _ := e.mediumPR("agent/dropped")
	id := e.grant(nil)
	_, claimed := e.call("POST", "/v0/keys/"+id+"/claim", e.maker, nil)
	token, _ := claimed["token"].(string)

	// The same projects and ops again: the key stays.
	if _, err := e.app.Orch.Issue(ctx, runtoken.IssueParams{ID: "keymaker", Scope: runtoken.OrchScope{Projects: []string{"storefront", "sideproject"}, Ops: []string{"keys.issue", "pr.view", "pr.diff"}}, Days: 1}); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.view(token, n); st != http.StatusOK {
		t.Fatalf("a re-issue that kept the project revoked the key: %d", st)
	}
	// Without storefront: the key in storefront goes with it.
	if _, err := e.app.Orch.Issue(ctx, runtoken.IssueParams{ID: "keymaker", Scope: runtoken.OrchScope{Projects: []string{"sideproject"}, Ops: []string{"keys.issue", "pr.view", "pr.diff"}}, Days: 1}); err != nil {
		t.Fatal(err)
	}
	st, body := e.view(token, n)
	if st == http.StatusOK {
		t.Fatalf("the key in a dropped project still works: %v", body)
	}
	mustValidDenial(t, body, "TOKEN_REVOKED")
	if k, _ := e.app.Keys.Get(ctx, id); k.State != "revoked" || k.StoppedByHuman || k.RevokedBy != "chapd" {
		t.Errorf("the key in the dropped project: %+v", k)
	}
}
