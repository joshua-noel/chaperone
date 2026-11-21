package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// Regression tests for the security review of custom keys.

func httpReq() *http.Request { return httptest.NewRequest(http.MethodGet, "/v0/keys", nil) }

func orchCaller(id string, scopeOps []string, projects ...string) *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: id, Projects: projects, ScopeOps: scopeOps}
}

// P2-1: an orchestrator sees and revokes only the keys and requests it owns, in its own projects. The scenario of
// the review: an orchestrator that holds only pr.merge, next to a person's agent.
func TestAnOrchestratorSeesAndRevokesOnlyWhatItOwns(t *testing.T) {
	g := newRig(t)
	g.who = "operator"
	ctx := context.Background()
	a := NewAdmin(g.s)

	// The person's agent: a key owned by person:operator, and a request that carries the agent's own words.
	personKey, _ := g.boot(operatorOwner, "scout")
	if _, _, err := g.s.CreateRequest(ctx, nreq(personKey, func(n *NewRequest) { n.Reason = "SECRET-PLAN: the acquisition" })); err != nil {
		t.Fatal(err)
	}
	// The orchestrator's own key, and another orchestrator's.
	_, mine := g.issueAndClaim(func(x *Grant) { x.Holder, x.HolderKind = "bot", HolderAgent })
	otherKey, err := g.s.Issue(ctx, g.grant(func(x *Grant) { x.Owner, x.Claimant, x.Holder = "other", "orchestrator:other", "bot2" }))
	if err != nil {
		t.Fatal(err)
	}
	_, theirs, err := g.s.Claim(ctx, otherKey.ID, "orchestrator:other")
	if err != nil {
		t.Fatal(err)
	}

	main := orchCaller("main", []string{"pr.merge"}, "acme-shop")

	list, err := a.List(main, httpReq())
	if err != nil || len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("main lists %v, %v; want only %s", list, err, mine.ID)
	}
	reqs, err := a.Requests(main, httpReq())
	if err != nil || len(reqs) != 0 {
		t.Errorf("main reads %d requests of the person's agent: %v %v", len(reqs), reqs, err)
	}
	pending, _ := g.s.ListRequests(ctx, operatorOwner, "", true)
	if len(pending) != 1 {
		t.Fatalf("the request is missing: %v", pending)
	}
	if _, err := a.Request(main, pending[0].ID, httpReq()); !errors.Is(err, ops.ErrKeyNotFound) {
		t.Errorf("main reads the person's request: %v", err)
	}
	for _, id := range []string{personKey, theirs.ID} {
		if _, err := a.Get(main, id, httpReq()); !errors.Is(err, ops.ErrKeyNotFound) {
			t.Errorf("main reads %s: %v", id, err)
		}
		if _, err := a.Revoke(main, id, httpReq()); !errors.Is(err, ops.ErrKeyNotFound) {
			t.Errorf("main revokes %s: %v", id, err)
		}
		if k, _ := g.s.Get(ctx, id); k.State != "live" || k.StoppedByHuman {
			t.Errorf("%s was changed by a refused revoke: %+v", id, k)
		}
	}
	if stopped, _ := g.s.AgentStopped(ctx, operatorOwner, "scout"); stopped {
		t.Error("the person's agent was stopped by an orchestrator")
	}

	// An orchestrator of the same name but another project sees nothing of the key.
	elsewhere := orchCaller("main", []string{"pr.merge"}, "other-project")
	if list, _ := a.List(elsewhere, httpReq()); len(list) != 0 {
		t.Errorf("another project sees %v", list)
	}
	if _, err := a.Revoke(elsewhere, mine.ID, httpReq()); !errors.Is(err, ops.ErrKeyNotFound) {
		t.Errorf("another project revokes the key: %v", err)
	}
	// An orchestrator with no id owns nothing, and is never read as "every owner".
	if _, err := a.List(orchCaller("", nil, "acme-shop"), httpReq()); !errors.Is(err, ops.ErrKeyForbidden) {
		t.Errorf("an orchestrator with no id: %v", err)
	}

	// Its own key it may revoke, and that is never a human stop, even for an agent's key.
	k, err := a.Revoke(main, mine.ID, httpReq())
	if err != nil || k.State != "revoked" || k.StoppedByHuman {
		t.Fatalf("revoke of its own key: %+v %v", k, err)
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "bot"); stopped {
		t.Error("a revoke by a token stopped the agent")
	}
}

// P2-1: the console path is the human stop. The owner's session revokes; another person's key looks like no key.
func TestTheOwnerRevokesAtTheConsoleAndThatStopsTheAgent(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	d := NewDecider(g.s, nil)
	key, _ := g.boot(operatorOwner, "scout")
	_, orchKey := g.issueAndClaim(nil) // owned by the orchestrator "main"

	if _, err := d.Revoke(ctx, "someone-else", key); !errors.Is(err, ErrNotFound) {
		t.Errorf("another person revokes: %v", err)
	}
	// A key an orchestrator owns is the operator's to end too, and ending it is not a stop.
	if k, err := d.Revoke(ctx, "operator", orchKey.ID); err != nil || k.State != "revoked" || k.StoppedByHuman {
		t.Errorf("a person revokes an orchestrator's key: %+v %v", k, err)
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "scout"); stopped {
		t.Error("the operator's revoke of an orchestrator's key stopped its agent")
	}
	k, err := d.Revoke(ctx, "operator", key)
	if err != nil || k.State != "revoked" || !k.StoppedByHuman {
		t.Fatalf("revoke: %+v %v", k, err)
	}
	if stopped, _ := g.s.AgentStopped(ctx, operatorOwner, "scout"); !stopped {
		t.Error("the agent was not stopped")
	}
	var rev bool
	for _, e := range g.led.named("op.request") {
		if e.Attributes["factory.op"] == "keys.revoke" && e.Attributes["factory.orchestrator.id"] == "person.operator" {
			rev = true
		}
	}
	if !rev {
		t.Error("the console revoke is not in the ledger under the person's id")
	}
	var re *RuleError
	if _, err := d.Revoke(ctx, "operator", key); !errors.As(err, &re) {
		t.Errorf("a second revoke: %v", err)
	}
}

// P2-2: a key built directly holds only what its orchestrator's own token holds.
func TestADirectKeyCannotHoldWhatItsOrchestratorDoesNot(t *testing.T) {
	g := newRig(t)
	a := newAdapter(t, g, nil)
	ctx := context.Background()
	req := issueReq(g, nil) // pr.diff, pr.view
	req.Caller.ScopeOps = []string{"keys.issue", "pr.view"}
	_, err := a.Check(ctx, req)
	ref := refusalOf(t, err)
	if !strings.Contains(ref.Why, "pr.diff") || !strings.Contains(ref.Why, "your own token") {
		t.Errorf("refusal: %q", ref.Why)
	}
	if _, err := a.Execute(ctx, req); err != nil {
		t.Fatal(err) // Execute reports a refusal as a failed outcome, never as a key
	}
	var n int
	if err := g.db.SQL().QueryRow(`SELECT count(*) FROM keys`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a key was written: %d %v", n, err)
	}
	// With the op in its own scope (exact, or by a pattern) it is allowed.
	for _, scope := range [][]string{{"keys.issue", "pr.diff", "pr.view"}, {"keys.issue", "pr.*"}} {
		req := issueReq(g, nil)
		req.Caller.ScopeOps = scope
		if _, err := a.Check(ctx, req); err != nil {
			t.Errorf("scope %v: %v", scope, err)
		}
	}
}

// P3-1: a label is capped so that the id the ledger holds for the agent always fits (63 characters).
func TestAnOverLongLabelIsRefusedAtEnrolmentAndEveryDerivedIdFits(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	long := "s" + strings.Repeat("x", MaxLabel) // MaxLabel + 1
	_, err := g.s.StartEnrolment(ctx, "acme-shop", long)
	var ref *EnrolRefusal
	if !errors.As(err, &ref) || ref.Status != 400 || !strings.Contains(ref.Why, "at most 40 characters") {
		t.Errorf("a %d-character label: %v", len(long), err)
	}
	fits := "s" + strings.Repeat("x", MaxLabel-1)
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", fits); err != nil {
		t.Errorf("a %d-character label: %v", len(fits), err)
	}
	// The agent with the longest label claims its own key: the ledger takes the events (every event is checked
	// against the spec's pattern for an id by the recording ledger).
	other := "t" + strings.Repeat("y", MaxLabel-1)
	g.boot(operatorOwner, other)

	// Whatever the owner's id, the derived id is a ledger id; two long ids stay apart.
	idRE := regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	owner := "person:" + strings.Repeat("a", 63)
	seen := map[string]string{}
	for _, label := range []string{fits, other, "a", "scout"} {
		for _, callerKey := range []string{agentClaimant(owner, label), agentClaimant(operatorOwner, label), "person:" + strings.Repeat("b", 63), "enrol:en-0123456789abcdef"} {
			id := claimerID(callerKey)
			if !idRE.MatchString(id) {
				t.Errorf("claimerID(%q) = %q is not a ledger id", callerKey, id)
			}
			if prev, dup := seen[id]; dup && prev != callerKey {
				t.Errorf("%q and %q share the id %q", prev, callerKey, id)
			}
			seen[id] = callerKey
		}
	}
}

// P3-2: the agent's reason is cleaned with the shared cleaner: bidirectional and zero-width characters go.
func TestAgentReasonLosesBidiAndZeroWidthCharacters(t *testing.T) {
	got := plainText("please \u202egnirotinom\u202c read only\u200b\u2066x\u2069\ufeff\nsecond line\x00", 500)
	for _, r := range got {
		if strings.ContainsRune("\u202e\u202c\u200b\u2066\u2069\ufeff\n\x00", r) {
			t.Errorf("%q still holds %U", got, r)
		}
	}
	if !strings.Contains(got, "please") || !strings.Contains(got, "read only") || !strings.Contains(got, "second line") {
		t.Errorf("the words are gone: %q", got)
	}
	// A cut stays on a rune boundary.
	if got := plainText(strings.Repeat("é", 300), 11); got != strings.Repeat("é", 5)+"..." {
		t.Errorf("cut: %q", got)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// P3-3: a refused enrolment start (the cap, or a label that already waits) is written down once a minute, and the
// waiting enrolments are listed and can be cancelled.
func TestRefusedEnrolmentStartsAreWrittenDownOnceAMinuteAndWaitingOnesCanBeCancelled(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	logs := &lockedBuf{}
	g.s.cfg.Log = slog.New(slog.NewTextHandler(logs, nil))
	refusals := func() int {
		n := 0
		for _, e := range g.led.named("op.request") {
			if e.Attributes["factory.op"] == "keys.enrol" {
				n++
			}
		}
		return n
	}
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err != nil {
		t.Fatal(err)
	}
	// The same label again: refused (409), and written down once for the whole minute, whoever asks.
	for range 5 {
		var ref *EnrolRefusal
		if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); !errors.As(err, &ref) || ref.Status != 409 {
			t.Fatalf("a label that waits: %v", err)
		}
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d warnings in a minute, want 1:\n%s", n, logs.String())
	}
	if n := refusals(); n != 1 {
		t.Errorf("%d ledger events in a minute, want 1", n)
	}
	for _, e := range g.led.named("op.result") {
		if e.Attributes["factory.cause_code"] == "ENROLMENT_REFUSED" && e.Attributes["factory.outcome"] != "refused" {
			t.Errorf("the refusal is written as %v", e.Attributes["factory.outcome"])
		}
	}
	// A minute later the next refusal is written down again.
	g.now = g.now.Add(61 * time.Second)
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err == nil {
		t.Fatal("expected a refusal")
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 2 || refusals() != 2 {
		t.Errorf("after a minute: %d warnings, %d events, want 2 and 2", n, refusals())
	}
	// The cap (429) is written down too.
	g.now = g.now.Add(2 * time.Minute)
	for _, label := range []string{"a1", "a2", "a3", "a4"} {
		if _, err := g.s.StartEnrolment(ctx, "acme-shop", label); err != nil {
			t.Fatal(err)
		}
	}
	var ref *EnrolRefusal
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "a5"); !errors.As(err, &ref) || ref.Status != 429 {
		t.Fatalf("the cap: %v", err)
	}
	if refusals() != 3 || !strings.Contains(logs.String(), "too many enrolments") {
		t.Errorf("the cap was not written down: %d events\n%s", refusals(), logs.String())
	}

	// The waiting ones are listed, oldest first, with their age; Cancel ends one and its agent is told.
	d := NewDecider(g.s, nil)
	list, err := d.WaitingEnrolments(ctx)
	if err != nil || len(list) != 5 || list[0].Label != "scout" || list[0].Project != "acme-shop" || !list[0].CreatedAt.Before(list[1].CreatedAt) {
		t.Fatalf("waiting: %+v %v", list, err)
	}
	if err := d.CancelEnrol(ctx, "operator", list[0].ID); err != nil {
		t.Fatal(err)
	}
	if after, _ := d.WaitingEnrolments(ctx); len(after) != 4 {
		t.Errorf("after the cancel: %d waiting", len(after))
	}
	if err := d.CancelEnrol(ctx, "operator", list[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second cancel: %v", err)
	}
	if err := d.CancelEnrol(ctx, "operator", "en-nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown enrolment: %v", err)
	}
	// With the slot free again the label can start once more.
	if _, err := g.s.StartEnrolment(ctx, "acme-shop", "scout"); err != nil {
		t.Errorf("after the cancel: %v", err)
	}
}

// P3-6: the sensitivity of a key is worked out again from its ops when it is used, and a life longer than the limit
// for it is refused, whatever the row says. (The database has its own CHECK for 30 days, and for 7 days when the row
// says sensitive; the row that says "not sensitive" and holds a risky op is the one only this check catches.)
func TestVerifyReworksSensitivityAndTheLongestLife(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	cat, _, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	g.s.cfg.Catalog = cat
	insert := func(id string, opList string, sensitive int, days int) string {
		t.Helper()
		ap, rq := g.approved()
		now := g.now.Unix()
		secret := Prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{id[len(id)-1]}, 32))
		if _, err := g.db.SQL().Exec(`INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour,
            issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id, token_sha256, fingerprint, claimed_at)
            VALUES (?, 'acme-shop', 'main', 'person', 'bob', ?, '[]', ?, 300, ?, ?, ?, 'orchestrator:main', 'a', 'approved', ?, ?, ?, 'abcd1234', ?)`,
			id, opList, sensitive, now, now+int64(days)*86400, now+3600, ap, rq, tokenHash(secret), now); err != nil {
			t.Fatal(err)
		}
		return secret
	}
	cases := []struct {
		id        string
		ops       string
		sensitive int
		days      int
		ok        bool
	}{
		{"k-0000000000000a01", `["deploy"]`, 0, 30, false}, // a risky op, the row says "not sensitive", 30 days
		{"k-0000000000000a02", `["deploy"]`, 0, 7, true},   // the limit for a sensitive key
		{"k-0000000000000a03", `["health"]`, 1, 7, true},   // the row's own flag can only add to it
		{"k-0000000000000a04", `["health"]`, 0, 30, true},  // routine, the 30-day limit
		{"k-0000000000000a06", `["deploy", "health"]`, 0, 8, false},
	}
	for _, c := range cases {
		secret := insert(c.id, c.ops, c.sensitive, c.days)
		_, err := g.s.VerifyKey(ctx, secret)
		if (err == nil) != c.ok {
			t.Errorf("%s ops %s sensitive %d for %d days: %v, want ok=%v", c.id, c.ops, c.sensitive, c.days, err, c.ok)
		}
		var ve *ops.VerifyError
		if err != nil && (!errors.As(err, &ve) || ve.Code != ops.CodeTokenInvalid || !strings.Contains(ve.Detail, "longer than")) {
			t.Errorf("%s: %v", c.id, err)
		}
	}
}

// P3-4, P3-5: the key store answers the ops service, inside the release transaction, whether a key may still act.
func TestLiveRefusesARevokedExpiredOrUnclaimedKey(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	_, info := g.issueAndClaim(nil)
	live := func(id string) error { return g.s.Live(ctx, g.db.SQL(), id) }
	if err := live(info.ID); err != nil {
		t.Fatalf("a live key: %v", err)
	}
	g.now = g.now.Add(25 * time.Hour)
	var ref *ops.Refusal
	if err := live(info.ID); !errors.As(err, &ref) || ref.Code != ops.CodeTokenExpired {
		t.Errorf("an expired key: %v", err)
	}
	g.now = g.now.Add(-25 * time.Hour)
	if _, err := g.s.Revoke(ctx, info.ID, "orchestrator:main", false); err != nil {
		t.Fatal(err)
	}
	if err := live(info.ID); !errors.As(err, &ref) || ref.Code != ops.CodeTokenRevoked {
		t.Errorf("a revoked key: %v", err)
	}
	granted, err := g.s.Issue(ctx, g.grant(func(x *Grant) { x.Holder = "other" }))
	if err != nil {
		t.Fatal(err)
	}
	if err := live(granted.ID); !errors.As(err, &ref) || ref.Code != ops.CodeTokenRevoked {
		t.Errorf("a key nobody claimed: %v", err)
	}
	if err := live("k-ffffffffffffffff"); !errors.As(err, &ref) {
		t.Errorf("a key that does not exist: %v", err)
	}
}
