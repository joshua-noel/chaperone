package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// ADR-002 amendment 10 through the real registry: ci.report reads a run from chapd's own record, with the outcome
// the runner named when it ended the run.
func TestCIRunLookupReadsTheRegistry(t *testing.T) {
	r := newStatusRig(t)
	ctx := context.Background()
	lookup := ciRunLookup(func() *runtoken.Runs { return r.e.app.Runs })

	r.register("r-ci1a", "k2Gf3kQ2xV7bTz1LwA9cYd")
	r.register("r-ci1b", "k3Hq7mR1yW8cUa2MxB0dZe")

	run, err := lookup(ctx, "r-ci1a")
	if err != nil {
		t.Fatal(err)
	}
	if run.Ended || run.Outcome != "" || run.Project != "acme-shop" || run.Profile != "code" || run.Repo != "acme/shop" || run.Head != "main" {
		t.Fatalf("an active run: %+v", run)
	}

	st, body := r.e.call("POST", "/v0/runs/r-ci1a/end", "", map[string]any{"control": r.far.control(t, "run.end", "r-ci1a"), "outcome": "failed"})
	if st != 200 {
		t.Fatalf("end: %d %v", st, body)
	}
	if run, err = lookup(ctx, "r-ci1a"); err != nil || !run.Ended || run.Outcome != "failed" {
		t.Fatalf("a failed run: %+v %v", run, err)
	}

	// An operator revoke is killed.
	if st, body := r.e.call("POST", "/v0/runs/r-ci1b/revoke", r.orchTok, nil); st != 200 {
		t.Fatalf("revoke: %d %v", st, body)
	}
	if run, err = lookup(ctx, "r-ci1b"); err != nil || !run.Ended || run.Outcome != "killed" {
		t.Fatalf("a revoked run: %+v %v", run, err)
	}

	if _, err := lookup(ctx, "r-nope1"); !errors.Is(err, ops.ErrCIRunUnknown) {
		t.Fatalf("an unknown run: %v", err)
	}
	if _, err := ciRunLookup(func() *runtoken.Runs { return nil })(ctx, "r-ci1a"); err == nil || errors.Is(err, ops.ErrCIRunUnknown) {
		t.Fatalf("no registry must be an error, not 'unknown run': %v", err)
	}
}

// The shipped baseline has ci.report on, but a project with no `pr.local_ci` block is refused before anything reaches
// GitHub (OP_POLICY_REFUSED), with the GitHub App configured and the adapter installed.
func TestCIReportRefusesAProjectWithoutLocalCIInTheShippedBaseline(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keys := writeKeys(t, dir)
	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "storefront", "-ops", "ci.report", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))

	s := ghtest.New(t)
	s.AddInstallation(7, "example-org", map[string]string{"checks": "write", "metadata": "read"}).AddRepo("storefront", "main")
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", github: c})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	e := &e2e{t: t, app: app, srv: srv, db: db, token: token}

	before := len(s.Requests())
	st, body := e.call("POST", "/v0/ops", token, map[string]any{
		"op": "ci.report", "project": "storefront", "reason": "x",
		"target": map[string]any{"adapter": "runner", "ref": "r-ci1a"},
		"params": map[string]any{"run_id": "r-ci1a"},
	})
	if st != 403 {
		t.Fatalf("status %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if len(s.Requests()) != before {
		t.Errorf("a refused op made %d GitHub request(s)", len(s.Requests())-before)
	}
}
