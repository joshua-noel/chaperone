package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// The fake GitHub (internal/gh/ghtest) is a test double: it holds a repository
// and pull requests in memory and accepts only its own throwaway key. It is
// compiled into every chapd, but it is switched on in exactly two places:
//
//   - `chapd quickstart --playground` (quickstart.go), and
//   - the `-tags demo` build's -dev-fake-github flag (demo.go).
//
// `chapd run` and `chapd svc` have no flag that reaches it, and no other code
// sets Config.github (TestFakeGitHubIsOnlyWiredByQuickstartAndDemo reads the
// sources to keep it so).

// fakeTB lets ghtest run outside a test. Only what ghtest calls is implemented;
// a failure of the fake's own set-up is a bug in this program, so it panics.
type fakeTB struct {
	testing.TB
	mu       sync.Mutex
	cleanups []func()
}

func (d *fakeTB) Helper() {}
func (d *fakeTB) Cleanup(f func()) {
	d.mu.Lock()
	d.cleanups = append(d.cleanups, f)
	d.mu.Unlock()
}
func (d *fakeTB) Errorf(format string, a ...any) { panic(fmt.Sprintf("fake GitHub: "+format, a...)) }
func (d *fakeTB) Fatalf(format string, a ...any) { panic(fmt.Sprintf("fake GitHub: "+format, a...)) }
func (d *fakeTB) Logf(string, ...any)            {}

// fakePRSpec is one pull request the fake opens: a branch off the base that
// changes File, and a `verify` check with Conclusion on its head.
type fakePRSpec struct {
	Kind, Branch, Title, Conclusion, File string
}

// fakePR is a pull request the fake opened.
type fakePR struct {
	Number int    `json:"number"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Head   string `json:"head_sha"`
	Merged bool   `json:"merged"`
}

type fakeGitHubOptions struct {
	Owner, Repo, Base string
	PRs               []fakePRSpec
	// LocalCI also plants the App's own `local-ci` check on every head, for a
	// project policy whose pr.local_ci mode is `also`.
	LocalCI bool
	// SkipIDs makes commit SHAs differ from run to run (ghtest.Server.SkipIDs).
	SkipIDs int64
	// BoundLog keeps only the last 500 requests, 4 KiB of each, for a fake that runs for a long time
	// on a port any local process can call (ghtest.Server.CapLog).
	BoundLog bool
}

// fakeGitHub is a running fake: a loopback server, a repository with pull
// requests, and a gh.Client that talks to it with the fake's own key.
type fakeGitHub struct {
	Client *gh.Client
	Repo   string // owner/name
	Base   string
	PRs    []fakePR

	srv  *ghtest.Server
	repo *ghtest.Repo
}

func newFakeGitHub(o fakeGitHubOptions) (*fakeGitHub, error) {
	s := ghtest.New(&fakeTB{})
	s.SkipIDs(o.SkipIDs)
	if o.BoundLog {
		s.CapLog(500, 4<<10)
	}
	in := s.AddInstallation(7, o.Owner, map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	repo := in.AddRepo(o.Repo, o.Base)
	f := &fakeGitHub{Repo: o.Owner + "/" + o.Repo, Base: o.Base, srv: s, repo: repo}
	for _, p := range o.PRs {
		repo.Branch(p.Branch, o.Base)
		head := repo.Commit(p.Branch)
		n := repo.OpenPR(ghtest.PROptions{Title: p.Title, Head: p.Branch, Base: o.Base})
		repo.SetFiles(n, ghtest.File{Filename: p.File})
		repo.SetCheck(head, ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: p.Conclusion})
		if o.LocalCI {
			repo.SetCheck(head, ghtest.Check{Name: "local-ci", AppID: ghtest.OwnAppID, Status: "completed", Conclusion: p.Conclusion})
		}
		f.PRs = append(f.PRs, fakePR{Number: n, Kind: p.Kind, Title: p.Title, Head: head})
	}
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		s.Close()
		return nil, err
	}
	f.Client = c
	return f, nil
}

// Merged reports whether the fake has merged pull request n.
func (f *fakeGitHub) Merged(n int) bool {
	m, _ := f.repo.Merged(n)
	return m
}

// MergeCalls is how many merge requests have reached the fake.
func (f *fakeGitHub) MergeCalls() int { return f.srv.Count("PUT", "/merge") }

// Close stops the fake's server.
func (f *fakeGitHub) Close() { f.srv.Close() }
