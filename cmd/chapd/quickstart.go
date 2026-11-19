package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
	"github.com/joshua-noel/chaperone/internal/loopback"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// `chapd quickstart` is a first run on any system, with no administrator rights
// and no account: it makes a scratch folder in the user's own profile, starts
// chapd in the foreground on a port that is not the real service's, and prints
// how to make the first passkey, how to connect Claude Code and three commands
// to try. The GitHub it uses is the PLAYGROUND, a fake inside this process.
//
// It is built so that it cannot touch a real install: it refuses the real
// service port, keeps its folder inside the user's home folder, makes that folder
// itself (private from the instant it exists) and refuses one that exists, and
// refuses the real install's database folder. See quickstart_dir.go. It has no vault and keeps no
// secret in a plain file except the orchestrator token, which every chap client
// needs and which only the invoking user can read.

const (
	quickstartHost      = "127.0.0.1"
	quickstartPort      = 55421 // not 55398 (the real service), 55415 (the demo script), 55440 (the dashboard frame example)
	quickstartProject   = "playground"
	quickstartInstance  = "quickstart"
	quickstartOrchID    = "main"
	quickstartKind      = "chaperone-quickstart"
	quickstartMarker    = "quickstart.json"
	quickstartTokenFile = "orchestrator.token"

	// quickstartEnrollTTL is how long the first-passkey address lives. A person
	// who has just seen the address needs time to open a browser and answer one
	// passkey prompt, and on a first run that may include setting up a screen
	// lock or finding a device; five minutes is too tight for that. The address
	// is shown only in this terminal, works from this computer only, works once,
	// and a restart spends it and prints a new one, so the cost of a longer life
	// is small and bounded. The ceremony itself still ends after 5 minutes.
	quickstartEnrollTTL = 15 * time.Minute

	// quickstartTokenDays is the life of the playground's orchestrator token. It
	// reaches only the fake GitHub, through pr.* ops of the playground project.
	quickstartTokenDays = 7
	// A token with less than this left is replaced at the next run.
	quickstartTokenMinLeft = 24 * time.Hour
)

// quickstartOps are the ops of the playground's orchestrator token: reads, and
// pr.merge, which always needs a passkey for a change to code.
var quickstartOps = []string{"pr.checks", "pr.diff", "pr.files", "pr.merge", "pr.view"}

// quickstartAfterCheck runs between the folder check and the folder preparation. Only tests set it: they
// plant a file there, the way another user could in that window.
var quickstartAfterCheck func()

// quickstartAfterBuild runs after chapd has opened its files and before the folder identity is checked. Only tests set it.
var quickstartAfterBuild func()

//go:embed quickstart_policy/playground.yaml
var quickstartPolicy []byte

// The pull requests of the playground. The first is a documentation fix (low
// tier: no approval), the second has red CI (refused), the third changes code
// (medium tier: needs the operator's passkey).
var playgroundPRs = []fakePRSpec{
	{Kind: "green", Branch: "agent/fix-typo", Title: "docs: fix a typo in the notes", Conclusion: "success", File: "docs/notes.md"},
	{Kind: "red", Branch: "agent/break-checkout", Title: "fix: speed up checkout", Conclusion: "failure", File: "docs/notes.md"},
	{Kind: "medium", Branch: "agent/checkout-copy", Title: "feat: reword the checkout button", Conclusion: "success", File: "src/checkout.py"},
}

const (
	playgroundOwner = "playground"
	playgroundRepo  = "storefront"
	playgroundBase  = "main"
)

const quickstartUsage = `usage: chapd quickstart [--playground] [--dir PATH] [--addr 127.0.0.1:PORT]

Starts a scratch chapd in this terminal, with its own folder, database and
passkey, for a first try. It uses a PLAYGROUND: a fake GitHub inside this
program, so nothing real is reached. It needs no administrator rights.

  --playground   use the fake GitHub (the default; the only choice in this version)
  --dir PATH     the scratch folder (default: a "chaperone-quickstart" folder in your user profile)
  --addr ADDR    listen address, 127.0.0.1 only (default 127.0.0.1:55421; never 55398, the real service's port)
`

type quickstartOptions struct {
	Dir         string
	Addr        string // empty: the folder's own address, or the default for a new folder
	Playground  bool
	GitHubAppID string
}

// quickstartState is the marker file of a quickstart folder. A folder without
// it, and not empty, is not ours and is never used.
type quickstartState struct {
	Kind       string `json:"kind"`
	Version    int    `json:"version"`
	Addr       string `json:"addr"` // passkeys are bound to this address, so it must not change
	Playground bool   `json:"playground"`
	Created    string `json:"created"`
}

func quickstartCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("chapd quickstart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o quickstartOptions
	fs.BoolVar(&o.Playground, "playground", true, "use the fake GitHub (the default and the only choice in this version)")
	fs.StringVar(&o.Dir, "dir", "", "the scratch folder")
	fs.StringVar(&o.Addr, "addr", "", "listen address, 127.0.0.1 only")
	fs.StringVar(&o.GitHubAppID, "github-app-id", "", "a real GitHub App: not in this version")
	fs.Usage = func() { fmt.Fprint(stderr, quickstartUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if err := o.check(); err != nil {
		fmt.Fprintf(stderr, "chapd quickstart: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runQuickstart(ctx, o, stdout); err != nil {
		fmt.Fprintf(stderr, "chapd quickstart: %v\n", err)
		return 1
	}
	return 0
}

// check refuses what this version cannot or must not do, before anything is touched.
func (o quickstartOptions) check() error {
	if !o.Playground || o.GitHubAppID != "" {
		return errors.New("a real GitHub App is not in this version of the quickstart. " +
			"Use the playground (the default), or set the App up by hand: docs/runbooks/github-app-key.md")
	}
	if o.Addr != "" {
		return checkQuickstartAddr(o.Addr)
	}
	return nil
}

// checkQuickstartAddr accepts 127.0.0.1:PORT and nothing else, and never the
// real service's port.
func checkQuickstartAddr(addr string) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(addr)
	if host != quickstartHost {
		return fmt.Errorf("listen address %q: the quickstart listens on %s only", addr, quickstartHost)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1024 || n > 65535 {
		return fmt.Errorf("listen address %q: the port must be a number from 1024 to 65535", addr)
	}
	if port == "55398" || n == 55398 {
		return fmt.Errorf("listen address %q: port 55398 is the real Chaperone service's. Use another port", addr)
	}
	return nil
}

// newQuickstartKeySet is a pinned run-token key set with one runner key whose
// private half is thrown away at once: nobody can mint a run token for this
// chapd, so the orchestrator token is the only credential.
func newQuickstartKeySet() ([]byte, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{"version": 1, "allow_interim": false, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.quickstart", "public_key": base64.RawURLEncoding.EncodeToString(pub)},
	}}
	b, err := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n'), err
}

// ensureQuickstartToken makes sure the token file holds a live orchestrator
// token for the playground: it keeps the one there if chapd still accepts it
// with the right scope and at least a day left; otherwise it issues a new one,
// which revokes the old. The file is written by writePrivate: a new file only
// this user can read (mode 0600, or one ACE for this user on Windows).
func ensureQuickstartToken(ctx context.Context, a *App, path string, now time.Time) error {
	if raw, err := os.ReadFile(path); err == nil {
		if p, err := a.Orch.Verify(ctx, strings.TrimSpace(string(raw))); err == nil &&
			p.ID == quickstartOrchID && p.ExpiresAt.Sub(now) >= quickstartTokenMinLeft &&
			slices.Equal(p.Scope.Projects, []string{quickstartProject}) && slices.Equal(sortedCopy(p.Scope.Ops), quickstartOps) && !p.Scope.MintInterim {
			return nil
		}
	}
	res, err := a.Orch.Issue(ctx, runtoken.IssueParams{
		ID:    quickstartOrchID,
		Scope: runtoken.OrchScope{Projects: []string{quickstartProject}, Ops: quickstartOps},
		Days:  quickstartTokenDays,
	})
	if err != nil {
		return err
	}
	if err := writePrivate(path, []byte(res.Token+"\n")); err != nil {
		// A token nobody holds must not stay live.
		rerr := a.Orch.Revoke(ctx, quickstartOrchID, "chapd quickstart: could not write the token file")
		return fmt.Errorf("could not write %s: %w", path, errors.Join(err, rerr))
	}
	return nil
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// runQuickstart does everything and serves until ctx ends. It writes the three
// things to stdout once chapd is listening.
func runQuickstart(ctx context.Context, o quickstartOptions, stdout io.Writer) error {
	if err := o.check(); err != nil {
		return err
	}
	dir := o.Dir
	if dir == "" {
		var err error
		if dir, err = defaultQuickstartDir(runtime.GOOS, os.UserCacheDir, os.UserConfigDir, os.UserHomeDir); err != nil {
			return err
		}
	}
	dir, state, err := checkQuickstartDir(dir)
	if err != nil {
		return err
	}
	addr := o.Addr
	if addr == "" && state != nil {
		addr = state.Addr
	}
	if addr == "" {
		addr = net.JoinHostPort(quickstartHost, strconv.Itoa(quickstartPort))
	}
	// Listen first: a second quickstart on the same folder stops here, before it touches the database.
	// Both loopback addresses, because the browser is sent to "localhost" (see quickstart_listen.go).
	lns, err := bindQuickstart(addr, loopback.Listen)
	if err != nil {
		return err
	}
	defer loopback.CloseAll(lns)
	if quickstartAfterCheck != nil {
		quickstartAfterCheck()
	}

	f, err := prepareQuickstartFolder(dir, state, o.Addr, time.Now())
	if err != nil {
		return err
	}
	logger, closeLog, err := newLogger(f.LogDir, io.Discard)
	if err != nil {
		return err
	}
	defer closeLog()

	fake, err := newPlaygroundFake()
	if err != nil {
		return err
	}
	defer fake.Close()

	app, err := Build(ctx, Config{
		DBPath: f.DB, KeysPath: f.Keys, PolicyDir: f.PolicyDir, Instance: quickstartInstance,
		Addr: f.Addr, Log: logger, github: fake.Client,
		// A throwaway playground over a fake GitHub, on any system, is for trying the flow: a Linux desktop usually has no built-in
		// authenticator, so the playground also takes a security key or a phone. `chapd run` stays strict until its operator opts in.
		Authenticators: console.AuthenticatorsAny,
	})
	if err != nil {
		return err
	}
	defer app.Close()
	if err := app.Start(ctx); err != nil {
		return err
	}
	if err := ensureQuickstartToken(ctx, app, f.TokenFile, time.Now()); err != nil {
		return err
	}
	enrol, err := console.IssueFirstEnrollment(ctx, app.DB, quickstartEnrollTTL, time.Now())
	if err != nil {
		return err
	}
	// chapd has opened its files by path. Before anything is shown or served, the path must still lead to the folder
	// that was prepared (a folder renamed away and replaced in between would hold the attacker's files).
	if quickstartAfterBuild != nil {
		quickstartAfterBuild()
	}
	if err := f.stillTheSameFolder(); err != nil {
		return err
	}
	origin, _ := localEndpoints(f.Addr, nil)
	info := quickstartInfo{
		GOOS: runtime.GOOS, Dir: f.Dir, LogDir: f.LogDir, Addr: f.Addr, Origin: origin.URL, EnrollToken: enrol, Fresh: f.Fresh,
		TokenFile: f.TokenFile, Project: quickstartProject, Repo: fake.Repo, Base: fake.Base, PRs: fake.PRs, TTL: quickstartEnrollTTL,
	}
	info.Chap, info.ChapOnPath = findChap(runtime.GOOS)
	fmt.Fprint(stdout, renderQuickstart(info))
	return serveListeners(ctx, app, lns)
}
