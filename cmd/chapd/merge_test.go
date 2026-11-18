package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// TestE2EMergeOnRed is the demo as a test: the real chapd (real policy pack and
// the repository's policy/ folder, real pipeline) over a fake GitHub. A red PR is
// refused before anything is written to GitHub, a project with no `pr:` block is
// refused, a green low-tier PR merges.
func TestE2EMergeOnRed(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keys := writeKeys(t, dir)

	s := ghtest.New(t)
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	const base = "feat/d1-private-pilot" // the base of policy/storefront.yaml
	repo := in.AddRepo("storefront", base)
	verify := func(conclusion string) ghtest.Check {
		return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: conclusion}
	}
	open := func(branch, conclusion string) (int, string) {
		repo.Branch(branch, base)
		head := repo.Commit(branch)
		n := repo.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: branch, Base: base})
		repo.SetFiles(n, ghtest.File{Filename: "docs/notes.md"})
		repo.SetCheck(head, verify(conclusion))
		// policy/storefront.yaml has pr.local_ci mode `also`: the App's own local-ci check is needed besides verify.
		repo.SetCheck(head, ghtest.Check{Name: "local-ci", AppID: ghtest.OwnAppID, Status: "completed", Conclusion: "success"})
		return n, head
	}
	redN, redHead := open("agent/red", "failure")
	greenN, greenHead := open("agent/green", "success")

	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}

	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "storefront,acme-shop", "-ops", "pr.merge", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))

	policyDir, err := filepath.Abs(filepath.Join("..", "..", "policy"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", PolicyDir: policyDir, github: c})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	e := &e2e{t: t, app: app, srv: srv, db: db, token: token}

	merge := func(project, ref string, head string) (int, map[string]any) {
		return e.call("POST", "/v0/ops", token, map[string]any{
			"op": "pr.merge", "project": project, "reason": "demo",
			"target": map[string]any{"adapter": "github", "ref": ref},
			"params": map[string]any{"base": base, "head_sha": head, "method": "squash"},
		})
	}
	merges := func() int { return s.Count("PUT", "/merge") }

	// 1. Red CI: refused with the stop code, nothing written.
	st, body := merge("storefront", "example-org/storefront#"+strconv.Itoa(redN), redHead)
	if st != 403 {
		t.Fatalf("red PR: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED") // the cause code; the stop code leads the text
	if why, _ := body["why"].(string); !strings.HasPrefix(why, "CI_RED:") {
		t.Errorf("why does not lead with CI_RED: %q", why)
	}
	if merged, _ := repo.Merged(redN); merged || merges() != 0 {
		t.Fatalf("the red PR was merged or a merge call reached GitHub (%d)", merges())
	}

	// 2. A project with no `pr:` block: OP_POLICY_REFUSED, GitHub never asked.
	before := len(s.Requests())
	st, body = merge("acme-shop", "example-org/acme-shop#1", greenHead)
	if st != 403 {
		t.Fatalf("no pr: block: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_POLICY_REFUSED")
	if len(s.Requests()) != before {
		t.Errorf("a refused project still made %d GitHub requests", len(s.Requests())-before)
	}

	// 3. Green CI, low tier: merged.
	st, body = merge("storefront", "example-org/storefront#"+strconv.Itoa(greenN), greenHead)
	if st != 200 || body["state"] != "succeeded" {
		t.Fatalf("green PR: %d %v", st, body)
	}
	if merged, _ := repo.Merged(greenN); !merged || merges() != 1 {
		t.Errorf("green PR merged=%v, merge calls %d", merged, merges())
	}
	if merged, _ := repo.Merged(redN); merged {
		t.Error("the red PR merged")
	}
	if s.LiveTokens() != 0 {
		t.Errorf("%d installation tokens left live", s.LiveTokens())
	}
}
