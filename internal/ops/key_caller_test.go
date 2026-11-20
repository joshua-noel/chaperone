package ops

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// ---- the caller kinds are exhaustive switches --------------------------

func callerOfKind(kind string) *Caller {
	switch kind {
	case KindRun:
		return &Caller{Kind: KindRun, RunID: "r-7f3a", JTI: "jti-aaaaaaaaaaaaaaaa", Profile: "code", Project: "acme-shop", Repo: "acme/shop", Base: "main", Branch: "agent/r-7f3a", TokenOps: []string{"health"}}
	case KindOrchestrator:
		return &Caller{Kind: KindOrchestrator, OrchID: "main", Projects: []string{"acme-shop"}, ScopeOps: []string{"health"}}
	case KindKey:
		return &Caller{Kind: KindKey, KeyID: "k-0123456789abcdef", KeyOwner: "main", KeyHolder: "scout", Project: "acme-shop", KeyOps: []string{"health"}, KeyUnits: []string{"acme/shop"}}
	}
	return nil
}

// Adding a kind to CallerKinds without teaching every per-kind method about it fails here, not in
// production as "an orchestrator": every method answers something real for every listed kind.
func TestEveryCallerKindIsHandledByEveryPerKindMethod(t *testing.T) {
	g := newRig(t, rigOpts{})
	entry, _ := g.svc.policy.Catalog().Lookup("health")
	eff := g.svc.policy.For("acme-shop")
	for _, kind := range CallerKinds() {
		c := callerOfKind(kind)
		if c == nil {
			t.Fatalf("callerOfKind has no caller for %q: add it, and handle %q in every switch on Caller.Kind", kind, kind)
		}
		if c.Key() == unknownKey || !strings.HasPrefix(c.Key(), kind+":") {
			t.Errorf("%s: Key() = %q", kind, c.Key())
		}
		if len(c.opPatterns()) == 0 {
			t.Errorf("%s: opPatterns() is empty", kind)
		}
		sr := c.specRequester()
		if sr.Kind != KindRun && sr.Kind != KindOrchestrator {
			t.Errorf("%s: specRequester().Kind = %q, want a kind the spec knows", kind, sr.Kind)
		}
		if c.requesterView().Kind != kind {
			t.Errorf("%s: requesterView().Kind = %q", kind, c.requesterView().Kind)
		}
		if c.kindNoun() == "caller" {
			t.Errorf("%s: kindNoun() is the fallback", kind)
		}
		if (kind == KindRun || kind == KindKey) && scopeJSON(c) == "" {
			t.Errorf("%s: scopeJSON() is empty", kind)
		}
		if (&Server{}).projectOf(c) == "unknown" {
			t.Errorf("%s: projectOf() is the fallback", kind)
		}
		// The identity survives the trip through an op row.
		rec := g.svc.newRecord(c, &Submission{Op: "health", OpHash: "sha256:" + strings.Repeat("a", 64), ParamsJSON: "{}"}, "acme-shop", entry, eff)
		if back := rec.caller(); back.Key() != c.Key() || back.Kind != kind {
			t.Errorf("%s: record.caller().Key() = %q, want %q", kind, back.Key(), c.Key())
		}
		// The same requester the live caller projects, from the stored row.
		if got, want := rec.specRequest().Requester, c.specRequester(); got != want {
			t.Errorf("%s: record requester %v, caller requester %v", kind, got, want)
		}
	}
	// A kind nobody handles is nothing: it holds no op, owns nothing and is not an orchestrator.
	var ghost Caller
	ghost.Kind = "ghost"
	if ghost.Key() != unknownKey || ghost.opPatterns() != nil || ghost.specRequester() != (spec.Requester{}) ||
		ghost.requesterView().Kind != "" || scopeJSON(&ghost) != "" {
		t.Errorf("an unhandled kind is not refused: %q %v %v", ghost.Key(), ghost.opPatterns(), ghost.specRequester())
	}
}

// A key is projected onto the spec as the orchestrator key.<id>, in one place.
func TestKeyProjectsOntoTheSpecAsAnOrchestrator(t *testing.T) {
	c := callerOfKind(KindKey)
	sr := c.specRequester()
	if sr.Kind != KindOrchestrator || sr.ID != "key.k-0123456789abcdef" {
		t.Fatalf("projection = %+v", sr)
	}
	if id, ok := spec.KeyIDOf(sr); !ok || id != c.KeyID {
		t.Errorf("KeyIDOf = %q %v", id, ok)
	}
	if _, ok := spec.KeyIDOf(spec.Requester{Kind: KindOrchestrator, ID: "main"}); ok {
		t.Error("a plain orchestrator is read as a key")
	}
	if _, ok := spec.KeyIDOf(spec.Requester{Kind: KindRun, ID: "key.k-1"}); ok {
		t.Error("a run is read as a key")
	}
}

// No `if` that names a caller kind has an `else`: the other kind is never assumed to be an orchestrator.
func TestNoElseBranchAssumesTheOtherCallerKind(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		tree, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(tree, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || ifs.Else == nil {
				return true
			}
			mentions := false
			ast.Inspect(ifs.Cond, func(c ast.Node) bool {
				switch x := c.(type) {
				case *ast.Ident:
					mentions = mentions || x.Name == "KindRun" || x.Name == "KindOrchestrator" || x.Name == "KindKey"
				case *ast.SelectorExpr:
					mentions = mentions || (x.Sel.Name == "RequesterKind" || (x.Sel.Name == "Kind" && isCallerish(x.X)))
				}
				return true
			})
			if mentions {
				t.Errorf("%s: an if on the caller kind has an else; use a switch with a default that refuses", fset.Position(ifs.Pos()))
			}
			return true
		})
	}
}

func isCallerish(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "c" || x.Name == "caller"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Caller"
	}
	return false
}

// ---- keys as callers through the whole service ---------------------------------

const keyTok = KeyPrefix + "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK"

func keyCaller(ops []string, units ...string) *Caller {
	return &Caller{Kind: KindKey, KeyID: "k-0123456789abcdef", KeyOwner: "main", KeyHolder: "scout", Fingerprint: "ab12cd34",
		Project: "storefront", KeyOps: ops, KeyUnits: units}
}

func TestKeyReadsItsRepositoryAndOnlyIt(t *testing.T) {
	g := newReadRig(t)
	g.ver.keys[keyTok] = keyCaller(PRReadOps, readRepo)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	for _, op := range PRReadOps {
		if st, body, _ := g.ask(keyTok, op, n, map[string]any{}); st != http.StatusOK || str(body, "outcome") != "succeeded" {
			t.Errorf("%s under a key: %d %v", op, st, body)
		}
	}
	// The op row and its ledger events name the key, as the projected orchestrator, and nobody else.
	var kind, key, keyID, owner string
	err := g.db.SQL().QueryRow(`SELECT requester_kind, requester_key, key_id, owner_id FROM ops WHERE op = 'pr.view'`).Scan(&kind, &key, &keyID, &owner)
	if err != nil || kind != KindKey || key != "key:k-0123456789abcdef" || keyID != "k-0123456789abcdef" || owner != "main" {
		t.Errorf("op row: %v %q %q %q %q", err, kind, key, keyID, owner)
	}
	seen := false
	for _, ev := range g.led.rows(t, g.db, "op.request") {
		attrs, _ := ev["attrs"].(map[string]any)
		if attrs["factory.op"] != "pr.view" {
			continue
		}
		seen = true
		body, _ := ev["body"].(string)
		if attrs["factory.requester.kind"] != KindOrchestrator || attrs["factory.orchestrator.id"] != "key.k-0123456789abcdef" ||
			!strings.Contains(body, "key k-0123456789abcdef") || !strings.Contains(body, "owner main") || !strings.Contains(body, "holder scout") {
			t.Errorf("op.request of a key call: %v %q", attrs, body)
		}
	}
	if !seen {
		t.Error("no op.request event for the key's call")
	}

	// Another repository of the same installation is refused before any request to GitHub.
	before := len(g.s.Requests())
	st, body, _ := g.call("POST", "/v0/ops", keyTok, map[string]any{
		"op": "pr.view", "project": "storefront", "target": map[string]any{"adapter": "github", "ref": "example-org/other#1"}, "params": map[string]any{},
	})
	if st != http.StatusForbidden {
		t.Fatalf("other repository: %d %v", st, body)
	}
	mustDenial(t, body, "SCOPE_PATH")
	if after := len(g.s.Requests()); after != before {
		t.Errorf("a refused repository reached GitHub: %d new requests", after-before)
	}
	// A renamed spelling is the same repository; the name is compared the way chapd normalises it.
	if st, body, _ := g.call("POST", "/v0/ops", keyTok, map[string]any{
		"op": "pr.view", "project": "storefront", "target": map[string]any{"adapter": "github", "ref": strings.ToUpper(readRepo) + "#" + strconv.Itoa(n)}, "params": map[string]any{},
	}); st != http.StatusOK {
		t.Errorf("case-different spelling of the same repository: %d %v", st, body)
	}
}

func TestKeyCannotAskForAnOpOutsideItsList(t *testing.T) {
	g := newReadRig(t)
	g.ver.keys[keyTok] = keyCaller([]string{"pr.view"}, readRepo)
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	st, body, _ := g.ask(keyTok, "pr.diff", n, map[string]any{})
	if st != http.StatusForbidden {
		t.Fatalf("%d %v", st, body)
	}
	mustDenial(t, body, "OP_NOT_IN_TOKEN")
	// A project it is not bound to is refused as well, and the body cannot name another.
	st, body, _ = g.call("POST", "/v0/ops", keyTok, map[string]any{
		"op": "pr.view", "project": "acme-shop", "target": map[string]any{"adapter": "github", "ref": readRepo + "#1"}, "params": map[string]any{},
	})
	if st != http.StatusBadRequest && st != http.StatusForbidden {
		t.Errorf("another project: %d %v", st, body)
	}
}

// A critical op, an op on the never list and an op the key ceiling lacks are refused for a key even when a
// hand-edited row lists them (defence in depth).
func TestCriticalAndNeverOpsAreRefusedEvenInAHandEditedKey(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"repo.settings", "secrets.write", "keys.issue", "pr.open", "approvers.enroll"}, approvals: ap})
	hand := keyCaller([]string{"repo.settings", "secrets.write", "keys.issue", "pr.open", "approvers.enroll", "ci.report"}, "acme/shop")
	hand.Project = "acme-shop"
	g.ver.keys[keyTok] = hand
	for _, op := range []string{"repo.settings", "secrets.write", "keys.issue", "pr.open", "approvers.enroll"} {
		st, body, _ := g.call("POST", "/v0/ops", keyTok, map[string]any{
			"op": op, "target": map[string]any{"adapter": "github", "ref": "acme/shop"}, "params": map[string]any{},
		})
		if st != http.StatusForbidden {
			t.Errorf("%s: %d %v", op, st, body)
			continue
		}
		mustDenial(t, body, "OP_NOT_IN_TOKEN")
		if ap.n != 0 {
			t.Errorf("%s made a card", op)
		}
	}
	if n := opCount(t, g.db, "requester_kind = 'key' AND state NOT IN ('denied')"); n != 0 {
		t.Errorf("%d refused ops left live", n)
	}
}

// A high op under a key raises a card each time and is never allowed by the key; nothing runs before a decision.
func TestHighOpUnderAKeyRaisesACardEveryTime(t *testing.T) {
	ap := &fakeApprovals{}
	g := newRig(t, rigOpts{enable: []string{"deploy"}, approvals: ap})
	k := keyCaller([]string{"deploy", "health"})
	k.Project = "acme-shop"
	g.ver.keys[keyTok] = k
	for i, sha := range []string{sha1, sha2} {
		st, body, _ := g.call("POST", "/v0/ops", keyTok, opReq("deploy", sha))
		if st != http.StatusForbidden {
			t.Fatalf("call %d: %d %v", i, st, body)
		}
		mustDenial(t, body, "OP_APPROVAL_REQUIRED")
		st, op, _ := g.call("POST", "/v0/approvals", keyTok, approvalReq("deploy", sha))
		if st != http.StatusAccepted || op["state"] != "pending_approval" {
			t.Fatalf("card %d: %d %v", i, st, op)
		}
	}
	if ap.n != 2 {
		t.Errorf("cards = %d, want one per request", ap.n)
	}
	if len(g.ad.executions()) != 0 {
		t.Error("a key's high op ran before any decision")
	}
	// The card belongs to the key: another caller cannot read it.
	if st, _, _ := g.call("GET", "/v0/approvals/a-000001", orchTok, nil); st != http.StatusNotFound {
		t.Errorf("the orchestrator read a key's card: %d", st)
	}
	if st, _, _ := g.call("GET", "/v0/approvals/a-000001", keyTok, nil); st != http.StatusOK {
		t.Errorf("the key cannot read its own card: %d", st)
	}
}

func TestKeyRateIsPerKeyAcrossOps(t *testing.T) {
	g := newReadRig(t)
	k := keyCaller(PRReadOps, readRepo)
	k.KeyRate = 3
	g.ver.keys[keyTok] = k
	n, _ := g.openPR("agent/a", ghtest.PROptions{})
	for i, op := range []string{"pr.view", "pr.diff", "pr.checks"} {
		if st, body, _ := g.ask(keyTok, op, n, map[string]any{}); st != http.StatusOK {
			t.Fatalf("call %d: %d %v", i, st, body)
		}
	}
	st, body, hdr := g.ask(keyTok, "pr.files", n, map[string]any{})
	if st != http.StatusTooManyRequests {
		t.Fatalf("fourth call: %d %v", st, body)
	}
	mustDenial(t, body, "OP_POLICY_REFUSED")
	if !strings.Contains(str(body, "why"), "this key allows 3 calls per hour") || hdr.Get("Retry-After") == "" {
		t.Errorf("why = %q, Retry-After = %q", body["why"], hdr.Get("Retry-After"))
	}
	// Another key has its own count.
	other := keyCaller(PRReadOps, readRepo)
	other.KeyID = "k-fedcba9876543210"
	g.ver.keys[KeyPrefix+strings.Repeat("L", 43)] = other
	if st, _, _ := g.ask(KeyPrefix+strings.Repeat("L", 43), "pr.view", n, map[string]any{}); st != http.StatusOK {
		t.Errorf("a second key shares the first one's rate: %d", st)
	}
}

// A key is never accepted on the git proxy, and a run token, an orchestrator and a key are never mixed.
func TestKeyIsRefusedOnTheGitProxyAndNeverMixed(t *testing.T) {
	g := newRig(t, rigOpts{})
	g.ver.keys[keyTok] = keyCaller([]string{"health"})
	req, _ := http.NewRequest("GET", "http://"+strings.TrimPrefix(g.http.URL, "http://")+"/git/acme/shop.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer "+keyTok)
	if c, err := g.srv.cfg.Auth.Authenticate(req); err == nil || c != nil || !strings.Contains(err.Error(), "not accepted on the git proxy") {
		t.Errorf("git with a key: %v %v", c, err)
	}
	var resp *http.Response
	var err error
	// Two credentials in one request are refused as before.
	req, _ = http.NewRequest("GET", g.http.URL+"/v0/status", nil)
	req.Header.Add("Authorization", "Bearer "+keyTok)
	req.Header.Add("Authorization", "Bearer "+orchTok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("two credentials: %d", resp.StatusCode)
	}
	// A key in the query string is refused.
	st, _, _ := g.call("GET", "/v0/status?access_token="+keyTok, "", nil)
	if st != http.StatusUnauthorized {
		t.Errorf("a key in the query string: %d", st)
	}
}

// A key cannot read the ledger, list runs, or do any orchestrator-only route; it can read the catalog narrowed
// to what it may hold.
func TestKeyRoutesAreNarrow(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"deploy", "health", "repo.settings"}})
	k := keyCaller([]string{"health", "deploy", "repo.settings", "secrets.write"})
	k.Project = "acme-shop"
	g.ver.keys[keyTok] = k
	st, body, _ := g.call("GET", "/v0/status", keyTok, nil)
	if st != http.StatusOK {
		t.Fatalf("status: %d %v", st, body)
	}
	if req, _ := body["requester"].(map[string]any); req["kind"] != KindKey || req["key_id"] != "k-0123456789abcdef" || req["owner"] != "main" || req["holder"] != "scout" {
		t.Errorf("status requester: %v", body["requester"])
	}
	st, body, _ = g.call("GET", "/v0/catalog", keyTok, nil)
	if st != http.StatusOK {
		t.Fatalf("catalog: %d %v", st, body)
	}
	if got := strings.Join(opNames(body), ","); got != "deploy,health" {
		t.Errorf("a key's catalog = %s, want only what a key may hold and the policy turns on", got)
	}
	if st, _, _ := g.call("GET", "/v0/catalog?all=true", keyTok, nil); st != http.StatusForbidden {
		t.Errorf("a key listed every op: %d", st)
	}
}
