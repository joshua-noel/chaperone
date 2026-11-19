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
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
)

// This file exists only in a `go build -tags demo` binary, and only `chapd run`
// reads its flag (never `chapd svc`). It points chapd's GitHub client at an
// in-process fake GitHub (internal/gh/ghtest) holding a Storefront repository
// with four pull requests, so scripts/demo/merge-on-red.ps1 can show Chaperone
// refusing to merge a PR whose CI is red, with no GitHub App, no key and no
// network. The shipped chapd cannot do this with `chapd run`; its own copy of
// the fake is `chapd quickstart --playground` (quickstart.go).

const (
	demoOwner = "example-org"
	demoRepo  = "storefront"
	demoBase  = "feat/d1-private-pilot" // the `base` of policy/storefront.yaml
	// demoStateAddr serves what the fake holds, so the demo can show that the red
	// PR is still open after the refusal and the green one merged. The port is
	// free-chosen (another demo may be running); the seed file names the URL.
	demoStateAddr = "127.0.0.1:0"
)

type demoSeed struct {
	Repo     string   `json:"repo"`
	Base     string   `json:"base"`
	StateURL string   `json:"state_url"`
	PRs      []fakePR `json:"prs"`
}

func demoFlags(fs *flag.FlagSet, cfg *Config) {
	fs.Func("dev-fake-github", "DEMO BUILD ONLY: serve a fake GitHub with a Storefront repo and PRs (green, red, two that need an approval), use it for pr.merge, and write the seeded PRs to this JSON file", func(path string) error {
		if path == "" {
			return errors.New("needs a file path")
		}
		return startDemoGitHub(cfg, path)
	})
	fs.BoolFunc("dev-enroll", "DEMO BUILD ONLY: when no approver exists, print a one-time address to enrol a passkey on this scratch database", func(string) error {
		cfg.afterBuild = printEnrollAddress
		return nil
	})
}

// printEnrollAddress is what `chapd enroll` does, for a chapd that is already
// running on a scratch database: one address, good once.
func printEnrollAddress(ctx context.Context, a *App) error {
	origin, _ := localEndpoints(a.cfg.Addr, a.cfg.Hosts)
	token, err := console.IssueFirstEnrollment(ctx, a.DB, 30*time.Minute, time.Now())
	if err != nil {
		return err
	}
	if token == "" { // an approver exists already: sign in instead
		fmt.Printf("Console: %s/login\n", origin.URL)
		return nil
	}
	fmt.Printf("Enrol a passkey: %s/enroll#%s\n", origin.URL, token)
	return nil
}

func startDemoGitHub(cfg *Config, seedPath string) error {
	f, err := newFakeGitHub(fakeGitHubOptions{
		Owner: demoOwner, Repo: demoRepo, Base: demoBase,
		// The two "medium" PRs touch a code path, so merging them needs an approval
		// card (scripts/demo/approve-a-merge.ps1); the others never need one.
		PRs: []fakePRSpec{
			{Kind: "green", Branch: "agent/fix-typo", Title: "docs: fix a typo in the notes", Conclusion: "success", File: "docs/notes.md"},
			{Kind: "red", Branch: "agent/break-checkout", Title: "fix: speed up checkout", Conclusion: "failure", File: "docs/notes.md"},
			{Kind: "medium", Branch: "agent/checkout-copy", Title: "feat: reword the checkout button", Conclusion: "success", File: "src/checkout.py"},
			{Kind: "medium-deny", Branch: "agent/checkout-fees", Title: "feat: add a service fee at checkout", Conclusion: "success", File: "src/fees.py"},
		},
		// policy/storefront.yaml has pr.local_ci mode `also`: the App's own local-ci check is needed besides verify.
		LocalCI: true,
	})
	if err != nil {
		return err
	}
	cfg.github = f.Client

	ln, err := net.Listen("tcp", demoStateAddr)
	if err != nil {
		return fmt.Errorf("demo state endpoint: %w", err)
	}
	seed := demoSeed{Repo: f.Repo, Base: f.Base, StateURL: "http://" + ln.Addr().String() + "/state", PRs: f.PRs}

	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		out := seed
		out.PRs = append([]fakePR(nil), seed.PRs...)
		for i := range out.PRs {
			out.PRs[i].Merged = f.Merged(out.PRs[i].Number)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"seed": out, "merge_calls_to_github": f.MergeCalls()})
	})
	go func() { _ = http.Serve(ln, mux) }()

	b, _ := json.MarshalIndent(seed, "", "  ")
	return os.WriteFile(seedPath, b, 0o600)
}
