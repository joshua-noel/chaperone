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
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// `chapd quickstart` is a first run on any system, with no administrator rights
// and no account: it makes a scratch folder in the user's own profile, starts
// chapd in the foreground on a port that is not the real service's, and prints
// how to make the first passkey, how to connect Claude Code and three commands
// to try. The GitHub it uses is the PLAYGROUND, a fake inside this process.
//
// It is built so that it cannot touch a real install: it refuses the real
// service port, refuses a folder that is not empty and was not made by itself,
// and refuses the real install's database folder. It has no vault and keeps no
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

// defaultQuickstartDir is the folder under the user's own profile. On Windows
// it is under %LOCALAPPDATA% (not the roaming %APPDATA%: a database must not
// follow a profile around); elsewhere it is under the user's config folder.
// Never the real install's folders.
func defaultQuickstartDir(goos string, cacheDir, configDir, homeDir func() (string, error)) (string, error) {
	var base string
	var err error
	if goos == "windows" {
		base, err = cacheDir()
	} else {
		base, err = configDir()
	}
	if err != nil {
		h, herr := homeDir()
		if herr != nil {
			return "", fmt.Errorf("cannot find your user folder (pass --dir): %w", errors.Join(err, herr))
		}
		return filepath.Join(h, ".chaperone-quickstart"), nil
	}
	return filepath.Join(base, "chaperone-quickstart"), nil
}

// resolveExisting makes p absolute and resolves links in the part that exists,
// so a link or junction into a real install is seen for what it is.
func resolveExisting(p string) (string, error) {
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		rel = strings.ToLower(rel)
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// realInstallDir is the real install's database folder where this system has a
// known one (the Windows default of ADR-006), else "". A variable so tests can
// point it at a scratch folder.
var realInstallDir = func() string {
	if filepath.IsAbs(defaultDB) {
		return filepath.Dir(defaultDB)
	}
	return ""
}

// hasAncestorSameFile reports whether p, or a folder above it, is the very same
// folder as target. It compares file identity (os.SameFile), not path text, so a
// junction or link that leads into target is found: Go's EvalSymlinks does not
// follow Windows junctions.
func hasAncestorSameFile(p string, target os.FileInfo) bool {
	for cur := p; ; {
		if st, err := os.Stat(cur); err == nil && os.SameFile(st, target) {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

// overlapsRealInstall reports whether any of the paths is, holds or lies inside the
// known real install folder, by path text after resolving links and by file identity.
// It is a second line of defence: for every other place a real install may live the
// rule that protects it is the marker rule of checkQuickstartDir.
func overlapsRealInstall(paths ...string) bool {
	real := realInstallDir()
	if real == "" {
		return false
	}
	realAbs, err := filepath.Abs(real)
	if err != nil {
		return false
	}
	realRes, _ := resolveExisting(realAbs)
	realSt, realErr := os.Stat(realAbs)
	for _, p := range paths {
		for _, r := range []string{realAbs, realRes} {
			if r != "" && (within(p, r) || within(r, p)) {
				return true
			}
		}
		if realErr == nil && hasAncestorSameFile(p, realSt) {
			return true
		}
		if st, err := os.Stat(p); err == nil && hasAncestorSameFile(realAbs, st) {
			return true
		}
	}
	return false
}

// checkQuickstartDir decides whether dir may be used. It returns the folder's
// marker when it is a quickstart folder, nil when it is new or empty. It
// refuses a file, any folder that holds something but was not made by
// `chapd quickstart` (the marker rule: a real install has a state.db and no
// marker, wherever it is, on any system), and, as a second check, the known real
// install folder and anything above, below or linked into it.
func checkQuickstartDir(dir string) (string, *quickstartState, error) {
	given, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, err
	}
	dir, err = resolveExisting(given)
	if err != nil {
		return "", nil, err
	}
	if overlapsRealInstall(given, dir) {
		return "", nil, fmt.Errorf("%s is, or holds, the real Chaperone install's folder. The quickstart never touches it", dir)
	}
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return dir, nil, nil
	case err != nil:
		return "", nil, err
	case !st.IsDir():
		return "", nil, fmt.Errorf("%s is a file, not a folder", dir)
	}
	state, err := readQuickstartState(dir)
	if err == nil {
		return dir, state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", nil, fmt.Errorf("%s: %w", dir, err)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return "", nil, rerr
	}
	if len(entries) != 0 {
		return "", nil, fmt.Errorf("%s is not empty and was not made by chapd quickstart (it has no %s). "+
			"It could be a real install, so it is left alone. Use an empty folder, or leave out --dir", dir, quickstartMarker)
	}
	return dir, nil, nil
}

func readQuickstartState(dir string) (*quickstartState, error) {
	b, err := os.ReadFile(filepath.Join(dir, quickstartMarker))
	if err != nil {
		return nil, err
	}
	var s quickstartState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", quickstartMarker, err)
	}
	if s.Kind != quickstartKind || s.Version != 1 {
		return nil, fmt.Errorf("%s is not a quickstart marker this version understands", quickstartMarker)
	}
	if err := checkQuickstartAddr(s.Addr); err != nil {
		return nil, fmt.Errorf("%s names a bad address: %w", quickstartMarker, err)
	}
	return &s, nil
}

// quickstartFolder is a prepared folder.
type quickstartFolder struct {
	Dir, DB, Keys, PolicyDir, TokenFile, LogDir string
	Addr                                        string
	Fresh                                       bool
}

// prepareQuickstartFolder makes or re-opens the folder. The marker is written
// first, so an interrupted first run is a quickstart folder too. Existing files
// are kept: a second run reuses the database, the key set and the policy.
func prepareQuickstartFolder(dir string, state *quickstartState, wantAddr string, now time.Time) (*quickstartFolder, error) {
	f := &quickstartFolder{
		Dir: dir, DB: filepath.Join(dir, "state.db"), Keys: filepath.Join(dir, "run-keys.json"),
		PolicyDir: filepath.Join(dir, "policy"), TokenFile: filepath.Join(dir, quickstartTokenFile), LogDir: filepath.Join(dir, "logs"),
		Fresh: state == nil,
	}
	switch {
	case state == nil:
		f.Addr = wantAddr
		if f.Addr == "" {
			f.Addr = net.JoinHostPort(quickstartHost, strconv.Itoa(quickstartPort))
		}
	case wantAddr != "" && wantAddr != state.Addr:
		return nil, fmt.Errorf("this folder was set up for %s, and its passkey is bound to that address. "+
			"Use --addr %s, or a new --dir", state.Addr, state.Addr)
	default:
		f.Addr = state.Addr
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Private to this user whatever the parent allows: mode 0700, or on Windows a protected ACL with one inherited
	// entry for this user, read back. A folder that cannot be made private is refused.
	if err := restrictDirToCurrentUser(dir); err != nil {
		return nil, fmt.Errorf("cannot make %s private to this user: %w", dir, err)
	}
	if state == nil {
		b, _ := json.MarshalIndent(quickstartState{Kind: quickstartKind, Version: 1, Addr: f.Addr, Playground: true, Created: now.UTC().Format(time.RFC3339)}, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, quickstartMarker), append(b, '\n'), 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(f.PolicyDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.LogDir, 0o700); err != nil {
		return nil, err
	}
	if err := writeIfAbsent(filepath.Join(f.PolicyDir, quickstartProject+".yaml"), quickstartPolicy); err != nil {
		return nil, err
	}
	keys, err := newQuickstartKeySet()
	if err != nil {
		return nil, err
	}
	if err := writeIfAbsent(f.Keys, keys); err != nil {
		return nil, err
	}
	return f, nil
}

// writeIfAbsent writes data to a new file with mode 0600 and leaves an existing file alone.
func writeIfAbsent(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
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
	lns, err := bindQuickstart(addr, net.Listen)
	if err != nil {
		return err
	}
	defer closeAll(lns)

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
	origin, _ := localEndpoints(f.Addr, nil)
	info := quickstartInfo{
		GOOS: runtime.GOOS, Dir: f.Dir, LogDir: f.LogDir, Addr: f.Addr, Origin: origin.URL, EnrollToken: enrol, Fresh: f.Fresh,
		TokenFile: f.TokenFile, Project: quickstartProject, Repo: fake.Repo, Base: fake.Base, PRs: fake.PRs, TTL: quickstartEnrollTTL,
	}
	info.Chap, info.ChapOnPath = findChap(runtime.GOOS)
	fmt.Fprint(stdout, renderQuickstart(info))
	return serveQuickstart(ctx, app, lns)
}
