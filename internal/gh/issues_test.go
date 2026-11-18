package gh_test

import (
	"context"
	"errors"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

func issueFixture(t *testing.T, granted map[string]string) (*gh.Client, *ghtest.Server, *ghtest.Repo, gh.Repo) {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(9, "example-org", granted)
	r := in.AddRepo("storefront", "main")
	return c, s, r, gh.Repo{Owner: "example-org", Name: "storefront"}
}

func TestIssueRoundTrip(t *testing.T) {
	ctx := context.Background()
	c, _, r, repo := issueFixture(t, map[string]string{"issues": "write", "metadata": "read"})
	tok, err := c.MintToken(ctx, 9, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsIssueWrite()})
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Wipe()

	is, err := c.CreateIssue(ctx, tok, repo, gh.NewIssue{Title: "boom", Body: "stack", Labels: []string{"source:error-watcher", "bug"}})
	if err != nil || is.Number == 0 || is.HTMLURL == "" || !is.HasLabel("source:error-watcher") || is.HasLabel("other") {
		t.Fatalf("create: %+v %v", is, err)
	}
	cm, err := c.CreateIssueComment(ctx, tok, repo, is.Number, "again")
	if err != nil || cm.ID == 0 || cm.HTMLURL == "" {
		t.Fatalf("comment: %+v %v", cm, err)
	}
	r.CloseIssue(is.Number)
	got, err := c.GetIssue(ctx, tok, repo, is.Number)
	if err != nil || got.State != "closed" || got.PullRequest != nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	re, err := c.ReopenIssue(ctx, tok, repo, is.Number)
	if err != nil || re.State != "open" {
		t.Fatalf("reopen: %+v %v", re, err)
	}
	v, _ := r.Issue(is.Number)
	if v.State != "open" || v.Reason != "reopened" || len(v.Comments) != 1 || v.Comments[0].Body != "again" || v.Body != "stack" {
		t.Errorf("fake state: %+v", v)
	}
}

func TestIssueErrors(t *testing.T) {
	ctx := context.Background()
	c, _, r, repo := issueFixture(t, map[string]string{"issues": "write", "metadata": "read"})
	rd, err := c.MintToken(ctx, 9, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsIssueRead()})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Wipe()
	n := r.AddIssue(ghtest.IssueOptions{Title: "x", Labels: []string{"source:error-watcher"}})
	if _, err := c.GetIssue(ctx, rd, repo, n); err != nil {
		t.Errorf("read with the read token: %v", err)
	}
	var api *gh.APIError
	if _, err := c.CreateIssue(ctx, rd, repo, gh.NewIssue{Title: "t"}); !errors.As(err, &api) || api.Status != 403 {
		t.Errorf("write with a read token: %v, want 403", err)
	}
	if _, err := c.GetIssue(ctx, rd, repo, 99); !errors.Is(err, gh.ErrNotFound) {
		t.Errorf("missing issue: %v", err)
	}
	if _, err := c.GetIssue(ctx, rd, repo, 0); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("issue 0: %v", err)
	}
	if _, err := c.CreateIssue(ctx, rd, repo, gh.NewIssue{Title: "  "}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("blank title: %v", err)
	}
	p := r.AddIssue(ghtest.IssueOptions{Title: "pr", IsPull: true})
	if is, err := c.GetIssue(ctx, rd, repo, p); err != nil || is.PullRequest == nil {
		t.Errorf("a pull request through the issues API: %+v %v", is, err)
	}
}

func TestIssuePermissionNotGranted(t *testing.T) {
	ctx := context.Background()
	c, _, _, _ := issueFixture(t, map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
	_, err := c.MintToken(ctx, 9, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsIssueWrite()})
	var api *gh.APIError
	if !errors.As(err, &api) || api.Status != 422 {
		t.Fatalf("mint without issues permission: %v, want 422", err)
	}
}
