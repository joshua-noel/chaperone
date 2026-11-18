package gh_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

func TestGetPullReadsWhatPrViewShows(t *testing.T) {
	f := newFixture(t)
	f.r.Branch("agent/v", base)
	f.r.Commit("agent/v")
	n := f.r.OpenPR(ghtest.PROptions{Title: "feat: v", Head: "agent/v", Base: base, Body: "Body text.", Author: "octo", Labels: []string{"bug", "ci"}})
	f.r.SetFiles(n, ghtest.File{Filename: "a.go", Additions: 3, Deletions: 1}, ghtest.File{Filename: "b.go", Additions: 2})
	p, err := f.c.GetPull(ctx, f.all(t), f.repo, n)
	if err != nil {
		t.Fatal(err)
	}
	if p.Body != "Body text." || p.User == nil || p.User.Login != "octo" || len(p.Labels) != 2 || p.Labels[1].Name != "ci" ||
		p.Additions != 5 || p.Deletions != 1 || p.ChangedFiles != 2 || p.Commits != 1 || p.CreatedAt == "" || p.UpdatedAt == "" {
		t.Fatalf("%+v", p)
	}
	f.r.SetMergeableUnknown(n, true)
	if p, _ = f.c.GetPull(ctx, f.all(t), f.repo, n); p.Mergeable != nil || p.MergeableState != "unknown" {
		t.Errorf("mergeable not computed yet: %+v", p)
	}
	// a PR with no author (a deleted account) decodes too
	n2, _ := f.pr(t, "agent/anon")
	if p, err = f.c.GetPull(ctx, f.all(t), f.repo, n2); err != nil || p.User != nil {
		t.Errorf("no author: %+v %v", p, err)
	}
}

func TestGetPullDiff(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/d")
	f.r.SetFiles(n,
		ghtest.File{Filename: "a.go", Patch: "@@ -1 +1 @@\n-old\n+new"},
		ghtest.File{Filename: "img.png"},
		ghtest.File{Filename: "c.go", Status: "renamed", PreviousFilename: "b.go", Patch: "@@ -1 +1 @@\n-x\n+y\n"})
	got, err := f.c.GetPullDiff(ctx, f.all(t), f.repo, n)
	if err != nil {
		t.Fatal(err)
	}
	want := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-old\n+new\n" +
		"diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n" +
		"diff --git a/b.go b/c.go\n--- a/b.go\n+++ b/c.go\n@@ -1 +1 @@\n-x\n+y\n"
	if string(got) != want {
		t.Fatalf("diff:\n%s\nwant:\n%s", got, want)
	}
	if _, err := f.c.GetPullDiff(ctx, f.all(t), f.repo, 99); !errors.Is(err, gh.ErrNotFound) {
		t.Errorf("missing pull request: %v", err)
	}
	// GitHub's 406 for a diff it will not make is an APIError, not bytes
	f.s.Inject("GET", "/pulls/1", ghtest.Fault{Status: 406, Message: "Sorry, the diff exceeded the maximum number of lines (20000)"})
	var api *gh.APIError
	if _, err := f.c.GetPullDiff(ctx, f.all(t), f.repo, n); !errors.As(err, &api) || api.Status != 406 || !strings.Contains(api.Message, "20000") {
		t.Errorf("406: %v", err)
	}
}

func TestListPullFilesPage(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/p")
	var files []ghtest.File
	for i := range 45 {
		files = append(files, ghtest.File{Filename: fmt.Sprintf("f%02d.go", i), Additions: i})
	}
	f.r.SetFiles(n, files...)
	tok := f.all(t)
	got, err := f.c.ListPullFilesPage(ctx, tok, f.repo, n, 2, 20)
	if err != nil || len(got) != 20 || got[0].Filename != "f20.go" || got[19].Filename != "f39.go" {
		t.Fatalf("page 2 of 20: %d %v %v", len(got), err, got)
	}
	if got, err = f.c.ListPullFilesPage(ctx, tok, f.repo, n, 3, 20); err != nil || len(got) != 5 {
		t.Fatalf("page 3 of 20: %d %v", len(got), err)
	}
	if got, err = f.c.ListPullFilesPage(ctx, tok, f.repo, n, 4, 20); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("a page past the end is an empty list: %v %v", got, err)
	}
	for _, bad := range [][2]int{{0, 10}, {1, 0}, {1, 101}, {-1, 10}} {
		if _, err := f.c.ListPullFilesPage(ctx, tok, f.repo, n, bad[0], bad[1]); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("page %d of %d: %v", bad[0], bad[1], err)
		}
	}
	if c := f.s.Count("GET", "/files"); c != 3 {
		t.Errorf("%d file requests, want one per call that was valid (3)", c)
	}
}

func TestReadPermissionsAreEnough(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/perm")
	f.r.SetFiles(n, ghtest.File{Filename: "a.go", Patch: "@@ -1 +1 @@\n-a\n+b"})
	f.r.SetCheck(head, verify("completed", "success"))

	read := f.mint(t, gh.PermsReadPull())
	if _, err := f.c.GetPull(ctx, read, f.repo, n); err != nil {
		t.Errorf("get pull with pull_requests:read: %v", err)
	}
	if _, err := f.c.GetPullDiff(ctx, read, f.repo, n); err != nil {
		t.Errorf("diff with pull_requests:read: %v", err)
	}
	if _, err := f.c.ListPullFilesPage(ctx, read, f.repo, n, 1, 10); err != nil {
		t.Errorf("files with pull_requests:read: %v", err)
	}
	if _, err := f.c.ListCheckRuns(ctx, read, f.repo, head, gh.CheckRunQuery{}); !errors.Is(err, gh.ErrForbidden) {
		t.Errorf("a token without checks:read reads check runs: %v", err)
	}
	checks := f.mint(t, gh.PermsReadPullChecks())
	if runs, err := f.c.ListCheckRuns(ctx, checks, f.repo, head, gh.CheckRunQuery{}); err != nil || len(runs) != 1 {
		t.Errorf("check runs with checks:read: %v %v", runs, err)
	}
	for name, perms := range map[string]map[string]string{"PermsReadPull": gh.PermsReadPull(), "PermsReadPullChecks": gh.PermsReadPullChecks()} {
		for k, v := range perms {
			if v != gh.Read {
				t.Errorf("%s asks for %s:%s: a read op must ask for read only", name, k, v)
			}
			if k == "contents" {
				t.Errorf("%s asks for contents", name)
			}
		}
	}
}
