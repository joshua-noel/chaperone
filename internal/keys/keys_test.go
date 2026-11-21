package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

type recLedger struct {
	t      *testing.T
	mu     sync.Mutex
	events []ops.Event
}

func (l *recLedger) AppendTx(_ context.Context, _ *store.Tx, e ops.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	validateEvent(l.t, e)
	l.events = append(l.events, e)
	return nil
}

func (l *recLedger) named(name string) []ops.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []ops.Event
	for _, e := range l.events {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// validateEvent checks an event against the pinned spec's ledger-event schema: attributes are closed per name.
func validateEvent(t *testing.T, e ops.Event) {
	t.Helper()
	doc := map[string]any{
		"spec_version": "0", "chain": "chaperone.test", "seq": float64(1),
		"prev_hash":      "sha256:" + strings.Repeat("1", 64),
		"hash":           "sha256:" + strings.Repeat("2", 64),
		"time_unix_nano": "1790000000000000000", "trace_id": spec.TraceID("r-test"), "span_id": "00f067aa0ba902b7",
		"severity_number": float64(9), "event_name": e.Name,
		"resource":   map[string]any{"service.name": "chaperone", "service.instance.id": "test"},
		"project":    e.Project,
		"attributes": e.Attributes,
	}
	if e.Body != "" {
		doc["body"] = e.Body
	}
	if err := spec.Validate(spec.SchemaEvent, doc); err != nil {
		t.Errorf("event %s does not validate against the spec: %v\nattributes: %v", e.Name, err, e.Attributes)
	}
}

type sink struct {
	mu   sync.Mutex
	vals map[string]string
}

func (s *sink) Set(id string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vals == nil {
		s.vals = map[string]string{}
	}
	s.vals[id] = string(v)
	return nil
}

type rig struct {
	t      *testing.T
	db     *store.DB
	s      *Store
	led    *recLedger
	sink   *sink
	now    time.Time
	hooked []string
	who    string // the approver id the approvals this rig makes are signed by; "" means approver.operator
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, db: db, led: &recLedger{t: t}, sink: &sink{}, now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	g.s, err = New(Config{
		DB: db, Ledger: g.led, Redact: g.sink, PolicyVersion: func() string { return "test-policy" }, Now: func() time.Time { return g.now },
		TxRevoke: func(_ context.Context, _ *store.Tx, id string) error { g.hooked = append(g.hooked, id); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var apprSeq int

// approved inserts an approved keys.issue approval row so a key can name it (the foreign key is real).
func (g *rig) approved() (approvalID, requestID string) {
	g.t.Helper()
	apprSeq++
	approvalID, requestID = "a-"+pad(apprSeq), "q-"+pad(apprSeq)
	_, err := g.db.SQL().Exec(`INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, project, op, op_hash, class,
        policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix, request_expires_unix,
        decided_unix, approver, nonce, challenge_sha256, record_json)
        VALUES (?, ?, 'orchestrator', 'main', 'acme-shop', 'keys.issue', ?, 'high', 'p', '{}', '[]', '[]', 'card', ?, 'approved', 1, 2, 3, ?, 'n', 'sha256:c', '{}')`,
		approvalID, requestID, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), g.signer())
	if err != nil {
		g.t.Fatal(err)
	}
	return
}

func pad(n int) string { return strings.Repeat("0", 6-len(itoa(n))) + itoa(n) }
func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (g *rig) grant(mod func(*Grant)) Grant {
	g.t.Helper()
	ap, rq := g.approved()
	gr := Grant{
		Project: "acme-shop", Owner: "main", HolderKind: HolderAgent, Holder: "scout",
		Ops: []string{"pr.view", "pr.diff"}, Units: []string{"acme/shop"}, TTLHours: 24,
		ApprovalID: ap, RequestID: rq, GrantedBy: "approver.operator", Claimant: "orchestrator:main",
	}
	if mod != nil {
		mod(&gr)
	}
	return gr
}

func (g *rig) issueAndClaim(mod func(*Grant)) (token string, info ops.KeyInfo) {
	g.t.Helper()
	ctx := context.Background()
	k, err := g.s.Issue(ctx, g.grant(mod))
	if err != nil {
		g.t.Fatal(err)
	}
	token, info, err = g.s.Claim(ctx, k.ID, "orchestrator:main")
	if err != nil {
		g.t.Fatal(err)
	}
	return
}

// ---- the operator's limits ---------------------------------------------------------

func TestLimitsAreTheOperatorsAndAreTableTested(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		name      string
		ttl       time.Duration
		sensitive bool
		ok        bool
	}{
		{"default 24 hours", 24 * time.Hour, false, true},
		{"30 days is the maximum", 30 * day, false, true},
		{"31 days is too long", 31 * day, false, false},
		{"never is not a thing", 100 * 365 * day, false, false},
		{"7 days for a sensitive key", 7 * day, true, true},
		{"8 days for a sensitive key is too long", 8 * day, true, false},
		{"30 days for a sensitive key is too long", 30 * day, true, false},
		{"under an hour", 30 * time.Minute, false, false},
	} {
		if err := Limits(c.ttl, c.sensitive); (err == nil) != c.ok {
			t.Errorf("%s: Limits = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// The same numbers are in Shape (the card and the row use it) and in the database.
	g := Grant{Project: "acme-shop", HolderKind: HolderAgent, Holder: "scout", Ops: []string{"pr.view"}, Units: []string{"a/b"}, TTLHours: 31 * 24}
	if err := g.Shape(); err == nil {
		t.Error("Shape accepted 31 days")
	}
	g = Grant{Project: "acme-shop", HolderKind: HolderAgent, Holder: "scout", Ops: []string{"deploy"}, TTLHours: 8 * 24, Sensitive: true}
	if err := g.Shape(); err == nil {
		t.Error("Shape accepted 8 days for a sensitive key")
	}
	g = Grant{Project: "acme-shop", HolderKind: HolderAgent, Holder: "scout", Ops: []string{"deploy"}, Rate: 301}
	if err := g.Shape(); err == nil {
		t.Error("Shape accepted a rate above the default (a rate is lowered, never raised)")
	}
}

func TestDatabaseRefusesTooLongAKeyWhateverTheCodeSays(t *testing.T) {
	g := newRig(t)
	ap, rq := g.approved()
	insert := func(id string, sensitive int, days int) error {
		now := g.now.Unix()
		_, err := g.db.SQL().Exec(`INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour,
            issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id)
            VALUES (?, 'acme-shop', 'main', 'agent', 'scout', '["pr.view"]', '[]', ?, 300, ?, ?, ?, 'orchestrator:main', 'a', 'approved', ?, ?)`,
			id, sensitive, now, now+int64(days)*86400, now+3600, ap, rq+id)
		return err
	}
	if err := insert("k-00000000000000a1", 0, 30); err != nil {
		t.Fatalf("30 days: %v", err)
	}
	if err := insert("k-00000000000000a2", 0, 31); err == nil {
		t.Error("the database accepted a 31-day key")
	}
	if err := insert("k-00000000000000a3", 1, 8); err == nil {
		t.Error("the database accepted an 8-day sensitive key")
	}
	if err := insert("k-00000000000000a4", 1, 7); err != nil {
		t.Errorf("7-day sensitive key: %v", err)
	}
}

// ---- issue, claim, verify ------------------------------------------------------------

func TestIssueMakesNoTokenAndClaimMakesItOnceAndStoresOnlyItsHash(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	k, err := g.s.Issue(ctx, g.grant(nil))
	if err != nil {
		t.Fatal(err)
	}
	if k.State != "granted" || k.Fingerprint != "" || k.ClaimedAt != "" || k.Holder != "scout" || k.Owner != "main" {
		t.Fatalf("issued: %+v", k)
	}
	var hash *string
	if err := g.db.SQL().QueryRow(`SELECT token_sha256 FROM keys WHERE id = ?`, k.ID).Scan(&hash); err != nil || hash != nil {
		t.Fatalf("a token hash exists before the claim: %v %v", hash, err)
	}
	// Another caller cannot claim it; it looks like no key.
	if _, _, err := g.s.Claim(ctx, k.ID, "orchestrator:other"); !errors.Is(err, ErrNotFound) {
		t.Errorf("claim by another caller: %v", err)
	}
	token, info, err := g.s.Claim(ctx, k.ID, "orchestrator:main")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, Prefix) || len(token) != len(Prefix)+secretChars {
		t.Fatalf("token shape: %q", token[:12])
	}
	if info.State != "live" || len(info.Fingerprint) != 8 || info.ClaimedAt == "" {
		t.Errorf("claimed: %+v", info)
	}
	// The token went to the redaction sink before the row committed, under the key's id.
	if g.sink.vals["key-"+k.ID] != token {
		t.Error("the token was not registered with the redaction sink")
	}
	// A second claim is refused, whoever asks.
	if _, _, err := g.s.Claim(ctx, k.ID, "orchestrator:main"); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("second claim: %v", err)
	}
	// Only the hash is stored: the plaintext is in no column of any table, and in no ledger event.
	if hash := tokenHash(token); info.Fingerprint != hash[:8] {
		t.Errorf("fingerprint %q is not the first 8 of the hash", info.Fingerprint)
	}
	secret := strings.TrimPrefix(token, Prefix)
	for _, table := range []string{"keys", "key_agents", "approvals", "ops"} {
		rows, err := g.db.SQL().Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				if strings.Contains(strings.ToLower(toString(v)), strings.ToLower(secret)) {
					t.Errorf("the token is in %s.%s", table, cols[i])
				}
			}
		}
		rows.Close()
	}
	g.led.mu.Lock()
	for _, e := range g.led.events {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), secret) {
			t.Errorf("the token is in the ledger event %s", e.Name)
		}
	}
	g.led.mu.Unlock()
	if evs := g.led.named("op.request"); len(evs) != 1 || evs[0].Attributes["factory.op"] != "keys.claim" {
		t.Errorf("claim events: %v", evs)
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func TestIssueIsIdempotentPerRequest(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	gr := g.grant(nil)
	a, err := g.s.Issue(ctx, gr)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.s.Issue(ctx, gr)
	if err != nil || a.ID != b.ID {
		t.Fatalf("second issue of the same op: %v %q %q", err, a.ID, b.ID)
	}
	if n := countKeys(t, g.db); n != 1 {
		t.Errorf("keys = %d", n)
	}
}

func countKeys(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestVerifyAndItsRefusals(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, info := g.issueAndClaim(nil)
	c, err := g.s.VerifyKey(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != ops.KindKey || c.KeyID != info.ID || c.Project != "acme-shop" || c.KeyOwner != "main" || c.KeyHolder != "scout" ||
		strings.Join(c.KeyOps, ",") != "pr.diff,pr.view" || strings.Join(c.KeyUnits, ",") != "acme/shop" || c.KeyRate != 300 || c.Fingerprint != info.Fingerprint {
		t.Errorf("caller = %+v", c)
	}
	refusal := func(bearer string) *ops.VerifyError {
		_, err := g.s.VerifyKey(ctx, bearer)
		var ve *ops.VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("VerifyKey(%.14s...) = %v, want a VerifyError", bearer, err)
		}
		return ve
	}
	for _, bad := range []string{"", "chap_key_", "chap_key_short", Prefix + strings.Repeat("A", secretChars), Prefix + strings.Repeat("!", secretChars), "chap_orch_" + strings.Repeat("A", 43)} {
		if ve := refusal(bad); ve.Code != ops.CodeTokenInvalid || ve.Key != nil {
			t.Errorf("%q: %v", bad, ve)
		}
	}
	// A hash-near token (one character changed) is unknown, never "close enough".
	flipped := token[:len(token)-1] + map[bool]string{true: "B", false: "A"}[token[len(token)-1] == 'A']
	if ve := refusal(flipped); ve.Code != ops.CodeTokenInvalid {
		t.Errorf("flipped: %v", ve)
	}
	// Expired: recognised, named, TOKEN_EXPIRED.
	g.now = g.now.Add(25 * time.Hour)
	if ve := refusal(token); ve.Code != ops.CodeTokenExpired || ve.Key == nil || ve.Key.KeyID != info.ID {
		t.Errorf("expired: %v", ve)
	}
	g.now = g.now.Add(-25 * time.Hour)
	// Revoked: recognised, named, TOKEN_REVOKED.
	if _, err := g.s.Revoke(ctx, info.ID, "orchestrator:main", false); err != nil {
		t.Fatal(err)
	}
	if ve := refusal(token); ve.Code != ops.CodeTokenRevoked || ve.Key == nil || ve.Key.KeyID != info.ID || strings.Contains(ve.Detail, "stopped by a human") {
		t.Errorf("revoked: %v", ve)
	}
}

func TestVerifyCutsARowDownToWhatAKeyMayHold(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, info := g.issueAndClaim(nil)
	// The scope columns are immutable by trigger: a hand edit by UPDATE is refused.
	if _, err := g.db.SQL().Exec(`UPDATE keys SET ops_json = '["repo.settings"]' WHERE id = ?`, info.ID); err == nil {
		t.Fatal("the database let a key's ops be rewritten")
	}
	// A row that lists a critical or never-in-key op (a bug, or an insert by someone who can write the database) is
	// cut down at verify: the key cannot gain such an op. That is all this proves: the trigger above can be dropped
	// by anyone who can write the database, and a row can name another project or a longer life (TestVerifyReworksSensitivityAndTheLongestLife).
	ap, rq := g.approved()
	now := g.now.Unix()
	secret := Prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if _, err := g.db.SQL().Exec(`INSERT INTO keys (id, project, owner_id, holder_kind, holder, ops_json, units_json, sensitive, rate_per_hour,
        issued_at, expires_at, claim_deadline, claimant, granted_by, grant_kind, approval_id, request_id, token_sha256, fingerprint, claimed_at)
        VALUES ('k-00000000000000ff', 'acme-shop', 'main', 'person', 'bob', '["repo.settings","secrets.write","keys.issue","pr.view","health"]', '[]', 0, 300,
        ?, ?, ?, 'orchestrator:main', 'a', 'approved', ?, ?, ?, 'abcd1234', ?)`, now, now+3600, now+3600, ap, rq, tokenHash(secret), now); err != nil {
		t.Fatal(err)
	}
	c, err := g.s.VerifyKey(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.KeyOps, ",") != "pr.view,health" {
		t.Errorf("a key whose row lists a critical op holds %v", c.KeyOps)
	}
	_ = token
}

func TestLastUseIsWrittenAtMostOnceAMinute(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, info := g.issueAndClaim(nil)
	read := func() int64 {
		var n int64
		g.db.SQL().QueryRow(`SELECT COALESCE(last_used_at,0) FROM keys WHERE id = ?`, info.ID).Scan(&n)
		return n
	}
	g.s.VerifyKey(ctx, token)
	first := read()
	g.now = g.now.Add(10 * time.Second)
	g.s.VerifyKey(ctx, token)
	if read() != first {
		t.Error("last_used_at was rewritten inside a minute")
	}
	g.now = g.now.Add(2 * time.Minute)
	g.s.VerifyKey(ctx, token)
	if read() == first {
		t.Error("last_used_at was not refreshed after a minute")
	}
}

// ---- claim window ---------------------------------------------------------------------

func TestUnclaimedKeyIsRevokedAtItsDeadline(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	k, err := g.s.Issue(ctx, g.grant(nil))
	if err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(ClaimWindow + time.Second)
	if _, _, err := g.s.Claim(ctx, k.ID, "orchestrator:main"); !errors.Is(err, ErrClaimExpired) {
		t.Fatalf("late claim: %v", err)
	}
	got, err := g.s.Get(ctx, k.ID)
	if err != nil || got.State != "revoked" || got.RevokedBy != "chapd" {
		t.Errorf("after the deadline: %+v %v", got, err)
	}
	var hash *string
	g.db.SQL().QueryRow(`SELECT token_sha256 FROM keys WHERE id = ?`, k.ID).Scan(&hash)
	if hash != nil {
		t.Error("a token was made for a key claimed after its deadline")
	}
	revokes := g.led.named("op.request")
	found := false
	for _, e := range revokes {
		found = found || e.Attributes["factory.op"] == "keys.revoke"
	}
	if !found {
		t.Error("the unclaimed revoke is not in the ledger")
	}
	if n, err := g.s.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("sweep after the revoke: %d %v", n, err)
	}
}

// ---- revoke, and a stopped agent stays stopped -----------------------------------------

func TestRevokeIsInstantCancelsPendingWorkAndIsLedgered(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, info := g.issueAndClaim(nil)
	if _, err := g.s.VerifyKey(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.Revoke(ctx, info.ID, "orchestrator:main", true); err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.VerifyKey(ctx, token); err == nil {
		t.Fatal("a revoked key still verifies")
	}
	if len(g.hooked) != 1 || g.hooked[0] != info.ID {
		t.Errorf("pending ops of the key were not cancelled: %v", g.hooked)
	}
	var found bool
	for _, e := range g.led.named("op.request") {
		if e.Attributes["factory.op"] == "keys.revoke" {
			found = true
			if e.Attributes["factory.orchestrator.id"] != "main" || !strings.Contains(e.Body, info.ID) {
				t.Errorf("revoke event: %v %q", e.Attributes, e.Body)
			}
		}
	}
	if !found {
		t.Error("no keys.revoke event")
	}
	if _, err := g.s.Revoke(ctx, info.ID, "orchestrator:main", true); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoking twice: %v", err)
	}
	// A key revoking itself is written down as the key.
	token2, info2 := g.issueAndClaim(func(g *Grant) { g.Holder = "other-agent" })
	_ = token2
	if _, err := g.s.Revoke(ctx, info2.ID, "key:"+info2.ID, false); err != nil {
		t.Fatal(err)
	}
	last := g.led.named("op.request")
	if e := last[len(last)-1]; e.Attributes["factory.orchestrator.id"] != "key."+info2.ID {
		t.Errorf("self revoke attributes: %v", e.Attributes)
	}
}

// Operator decision: an agent a human stopped may not be given a key again until its owner resumes it.
func TestStoppedAgentCannotGetAKeyAgain(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, info := g.issueAndClaim(nil)

	// The key revoking itself does not stop the agent.
	_, info2 := g.issueAndClaim(func(g *Grant) { g.Holder = "careful" })
	if _, err := g.s.Revoke(ctx, info2.ID, "key:"+info2.ID, false); err != nil {
		t.Fatal(err)
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "careful"); stopped {
		t.Error("a key that revoked itself stopped its agent")
	}
	if _, err := g.s.Issue(ctx, g.grant(func(g *Grant) { g.Holder = "careful" })); err != nil {
		t.Errorf("a new key for an agent that merely finished: %v", err)
	}

	// A human revoke stops it.
	if _, err := g.s.Revoke(ctx, info.ID, "orchestrator:main", true); err != nil {
		t.Fatal(err)
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "scout"); !stopped {
		t.Fatal("the agent was not stopped by a human revoke")
	}
	_, err := g.s.Issue(ctx, g.grant(nil))
	var re *RuleError
	if !errors.As(err, &re) || !strings.Contains(re.Why, "stopped by a human: ask your owner") {
		t.Fatalf("a stopped agent got a key: %v", err)
	}
	// Its old key tells it so.
	_, err = g.s.VerifyKey(ctx, token)
	var ve *ops.VerifyError
	if !errors.As(err, &ve) || ve.Code != ops.CodeTokenRevoked || !strings.Contains(ve.Detail, "stopped by a human: ask your owner") {
		t.Errorf("the stopped agent's key says: %v", err)
	}
	// Another owner's agent of the same name is not affected.
	if _, err := g.s.Issue(ctx, g.grant(func(g *Grant) { g.Owner = "second" })); err != nil {
		t.Errorf("another owner's agent: %v", err)
	}
	// Nothing in the database can quietly un-stop it: the revoke is written once.
	if _, err := g.db.SQL().Exec(`UPDATE keys SET human_stopped = 0, revoked_at = NULL WHERE id = ?`, info.ID); err == nil {
		t.Error("the database let a revoke be undone")
	}
}

func TestANewGrantReplacesTheAgentsLiveKey(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	token, first := g.issueAndClaim(nil)
	_, second := g.issueAndClaim(func(g *Grant) { g.Ops = []string{"pr.view"} })
	got, _ := g.s.Get(ctx, first.ID)
	if got.State != "revoked" || !strings.Contains(got.RevokeReason, "replaced by "+second.ID) {
		t.Errorf("the old key: %+v", got)
	}
	if _, err := g.s.VerifyKey(ctx, token); err == nil {
		t.Error("the replaced key still verifies")
	}
	if stopped, _ := g.s.AgentStopped(ctx, "main", "scout"); stopped {
		t.Error("replacing a key stopped the agent")
	}
	// A person's keys are not replaced: only an agent has one live key.
	_, a := g.issueAndClaim(func(g *Grant) { g.HolderKind, g.Holder = HolderPerson, "gilliano" })
	_, b := g.issueAndClaim(func(g *Grant) { g.HolderKind, g.Holder = HolderPerson, "gilliano" })
	if x, _ := g.s.Get(ctx, a.ID); x.State != "live" {
		t.Errorf("a person's first key: %s", x.State)
	}
	_ = b
}

func TestImmutabilityTriggersRefuseWhatTheyShould(t *testing.T) {
	g := newRig(t)
	_, info := g.issueAndClaim(nil)
	for _, q := range []string{
		`UPDATE keys SET expires_at = expires_at - 3600 WHERE id = '` + info.ID + `'`, // an expiry only moves later (an extension)
		`UPDATE keys SET issued_at = issued_at + 86400 WHERE id = '` + info.ID + `'`,
		`UPDATE keys SET project = 'other' WHERE id = '` + info.ID + `'`,
		`UPDATE keys SET owner_id = 'other' WHERE id = '` + info.ID + `'`,
		`UPDATE keys SET rate_per_hour = 100 WHERE id = '` + info.ID + `'`,
		`UPDATE keys SET token_sha256 = '` + strings.Repeat("0", 64) + `' WHERE id = '` + info.ID + `'`,
		`DELETE FROM keys WHERE id = '` + info.ID + `'`,
	} {
		if _, err := g.db.SQL().Exec(q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
}

// Ten callers race to claim one key: exactly one gets a token, and the row holds that one's hash.
func TestTenConcurrentClaimsGiveExactlyOneToken(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	k, err := g.s.Issue(ctx, g.grant(nil))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tokens []string
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, _, err := g.s.Claim(ctx, k.ID, "orchestrator:main"); err == nil {
				mu.Lock()
				tokens = append(tokens, tok)
				mu.Unlock()
			} else if !errors.Is(err, ErrAlreadyClaimed) {
				t.Errorf("claim: %v", err)
			}
		}()
	}
	wg.Wait()
	if len(tokens) != 1 {
		t.Fatalf("%d claims succeeded", len(tokens))
	}
	if _, err := g.s.VerifyKey(ctx, tokens[0]); err != nil {
		t.Errorf("the one token does not verify: %v", err)
	}
}

func (g *rig) signer() string {
	if g.who == "" {
		return "approver.operator"
	}
	return g.who
}
