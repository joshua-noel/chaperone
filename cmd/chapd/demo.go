//go:build demo

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// This file exists only in a `go build -tags demo` binary, and only `chapd run`
// reads its flag (never `chapd svc`). It points chapd's GitHub client at an
// in-process fake GitHub (internal/gh/ghtest) holding a Storefront repository
// with two pull requests, so scripts/demo/merge-on-red.ps1 can show Chaperone
// refusing to merge a PR whose CI is red, with no GitHub App, no key and no
// network. The shipped chapd cannot do this.

const (
	demoOwner = "example-org"
	demoRepo  = "storefront"
	demoBase  = "feat/d1-private-pilot" // the `base` of policy/storefront.yaml
	// demoStateAddr serves what the fake holds, so the demo can show that the red
	// PR is still open after the refusal and the green one merged. The port is
	// free-chosen (another demo may be running); the seed file names the URL.
	demoStateAddr = "127.0.0.1:0"
)

// demoTB lets ghtest run outside a test. Only what ghtest calls is implemented.
type demoTB struct {
	testing.TB
	mu       sync.Mutex
	cleanups []func()
}

func (d *demoTB) Helper()                        {}
func (d *demoTB) Cleanup(f func())               { d.mu.Lock(); d.cleanups = append(d.cleanups, f); d.mu.Unlock() }
func (d *demoTB) Errorf(format string, a ...any) { panic(fmt.Sprintf("fake GitHub: "+format, a...)) }
func (d *demoTB) Fatalf(format string, a ...any) { panic(fmt.Sprintf("fake GitHub: "+format, a...)) }
func (d *demoTB) Logf(format string, a ...any)   {}

type demoPR struct {
	Number int    `json:"number"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Head   string `json:"head_sha"`
	Merged bool   `json:"merged"`
}

type demoSeed struct {
	Repo     string   `json:"repo"`
	Base     string   `json:"base"`
	StateURL string   `json:"state_url"`
	PRs      []demoPR `json:"prs"`
}

func demoFlags(fs *flag.FlagSet, cfg *Config) {
	fs.Func("dev-fake-github", "DEMO BUILD ONLY: serve a fake GitHub with a Storefront repo and PRs (green, red, two that need an approval), use it for pr.merge, and write the seeded PRs to this JSON file", func(path string) error {
		if path == "" {
			return errors.New("needs a file path")
		}
		return startDemoGitHub(cfg, path)
	})
	fs.BoolFunc("dev-enroll", "DEMO BUILD ONLY: when no approver exists, print a one-time address to enrol a passkey (Windows Hello) on this scratch database", func(string) error {
		cfg.afterBuild = printEnrollAddress
		return nil
	})
}

// printEnrollAddress is what `chapd enroll` does, for a chapd that is already
// running on a scratch database: one address, good once.
func printEnrollAddress(ctx context.Context, a *App) error {
	origin, _ := localEndpoints(a.cfg.Addr, a.cfg.Hosts)
	token, err := console.IssueEnrollment(ctx, a.DB, nil, 30*time.Minute, time.Now())
	if err != nil { // an approver exists already: sign in instead
		fmt.Printf("Console: %s/login\n", origin.URL)
		return nil
	}
	fmt.Printf("Enrol a passkey: %s/enroll#%s\n", origin.URL, token)
	return nil
}

func startDemoGitHub(cfg *Config, seedPath string) error {
	s := ghtest.New(&demoTB{})
	in := s.AddInstallation(7, demoOwner, map[string]string{
		"contents": "write", "pull_requests": "write", "checks": "read", "deployments": "write", "metadata": "read",
	})
	repo := in.AddRepo(demoRepo, demoBase)

	verify := func(conclusion string) ghtest.Check {
		return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: conclusion}
	}
	ln, err := net.Listen("tcp", demoStateAddr)
	if err != nil {
		return fmt.Errorf("demo state endpoint: %w", err)
	}
	seed := demoSeed{Repo: demoOwner + "/" + demoRepo, Base: demoBase, StateURL: "http://" + ln.Addr().String() + "/state"}
	// The two "medium" PRs touch a code path, so merging them needs an approval
	// card (scripts/demo/approve-a-merge.ps1); the others never need one.
	for _, p := range []struct{ kind, branch, title, conclusion, file string }{
		{"green", "agent/fix-typo", "docs: fix a typo in the notes", "success", "docs/notes.md"},
		{"red", "agent/break-checkout", "fix: speed up checkout", "failure", "docs/notes.md"},
		{"medium", "agent/checkout-copy", "feat: reword the checkout button", "success", "src/checkout.py"},
		{"medium-deny", "agent/checkout-fees", "feat: add a service fee at checkout", "success", "src/fees.py"},
	} {
		repo.Branch(p.branch, demoBase)
		head := repo.Commit(p.branch)
		n := repo.OpenPR(ghtest.PROptions{Title: p.title, Head: p.branch, Base: demoBase})
		repo.SetFiles(n, ghtest.File{Filename: p.file})
		repo.SetCheck(head, verify(p.conclusion))
		// policy/storefront.yaml has pr.local_ci mode `also`: the App's own local-ci check is needed besides verify.
		repo.SetCheck(head, ghtest.Check{Name: "local-ci", AppID: ghtest.OwnAppID, Status: "completed", Conclusion: p.conclusion})
		seed.PRs = append(seed.PRs, demoPR{Number: n, Kind: p.kind, Title: p.title, Head: head})
	}

	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		return err
	}
	cfg.github = c

	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		out := seed
		out.PRs = append([]demoPR(nil), seed.PRs...)
		for i := range out.PRs {
			out.PRs[i].Merged, _ = repo.Merged(out.PRs[i].Number)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"seed": out, "merge_calls_to_github": s.Count("PUT", "/merge")})
	})
	go func() { _ = http.Serve(ln, mux) }()

	b, _ := json.MarshalIndent(seed, "", "  ")
	return os.WriteFile(seedPath, b, 0o600)
}
