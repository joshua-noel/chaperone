package gh_test

import (
	"context"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

const base = "feat/d1-private-pilot" // a base branch with a slash, as in ADR-002

type fixture struct {
	s     *ghtest.Server
	c     *gh.Client
	in    *ghtest.Installation
	r     *ghtest.Repo // example-org/storefront
	other *ghtest.Repo // example-org/other: same installation, not in narrowed tokens
	repo  gh.Repo
	orepo gh.Repo
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "example-org", map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	f := &fixture{s: s, c: c, in: in}
	f.r = in.AddRepo("storefront", base)
	f.other = in.AddRepo("other", "main")
	f.repo = gh.Repo{Owner: "example-org", Name: "storefront"}
	f.orepo = gh.Repo{Owner: "example-org", Name: "other"}
	return f
}

func (f *fixture) mint(t *testing.T, perms map[string]string, repos ...string) *gh.Token {
	t.Helper()
	if len(repos) == 0 {
		repos = []string{"storefront"}
	}
	tok, err := f.c.MintToken(context.Background(), 7, gh.TokenRequest{Repositories: repos, Permissions: perms})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Cleanup(tok.Wipe)
	return tok
}

// all is a token that can do everything the fake's installation allows, on storefront.
func (f *fixture) all(t *testing.T) *gh.Token {
	return f.mint(t, map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
}

// pr opens a PR from a new branch with one commit and returns its number and head.
func (f *fixture) pr(t *testing.T, branch string) (int, string) {
	t.Helper()
	f.r.Branch(branch, base)
	head := f.r.Commit(branch)
	return f.r.OpenPR(ghtest.PROptions{Title: "feat: " + branch, Head: branch, Base: base}), head
}

func verify(status, conclusion string) ghtest.Check {
	return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: status, Conclusion: conclusion}
}
