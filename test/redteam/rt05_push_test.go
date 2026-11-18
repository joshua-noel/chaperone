package redteam

// RT-05: a push the run must not make: to the base branch, to a tag, to another
// branch (its own or another run's), a deletion, several refs at once, a force
// push, another ref namespace, a push after the run ended, a push by a token
// that does not hold branch.push, and a commit that adds a workflow file.
// Threat model: TB3-E1, TB3-T2. Red-team list: docs/manual-crosswalk.md,
// RT-05 (and ADR-002 "Push path").
//
// Setup: a real `git` client talks to chapd's /git/ routes with an interim run
// token. chapd (the real op service, token verifiers and git proxy, in the
// red-team rig) talks to a fake GitHub: ghtest for the API (installation tokens
// are minted and revoked there) and `git http-backend` over a bare repository
// for the pack protocol, so a push that reaches GitHub really changes the
// repository and the test can read the refs back.
//
// Expected block: every refused push is refused by chapd before any
// git-receive-pack request reaches GitHub (the upstream request count does not
// move), the remote refs are exactly as before, no refusal text or ledger event
// holds an installation token, and no installation token is left live. The
// control: a fast-forward of the run's own task branch lands and is recorded.
//
// Workflow files: chapd reads only the command list of a push, never the pack,
// so it cannot see that a commit adds .github/workflows/x.yml. The control is
// the token: the installation token minted for a push carries exactly
// contents:write, pull_requests:write, metadata:read (less for a fetch), never `workflows`, and
// GitHub refuses a push that touches a workflow file without that permission.
// The test checks the permission set chapd asks for; that GitHub refuses is
// GitHub's, and is asserted by the live test in internal/gh (not run offline).
//
// To see this fail, drop the branch check in internal/ops/git_gate.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/gitproxy"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// ---- a fake GitHub git host ------------------------------------------------

type gitHost struct {
	mu      sync.Mutex
	srv     *httptest.Server
	root    string
	seen    []string // "METHOD path"
	pw      map[string]bool
	notLive int
	live    func(string) bool
}

func (u *gitHost) requests(sub string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, s := range u.seen {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func (u *gitHost) passwords() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []string
	for p := range u.pw {
		out = append(out, p)
	}
	return out
}

func (u *gitHost) bare() string { return filepath.Join(u.root, "acme", "shop.git") }

func gitBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("RT-05 needs git on PATH: %v", err)
	}
	return p
}

func gitEnvFor(home string) []string {
	cfg := filepath.Join(home, "gitconfig")
	if _, err := os.Stat(cfg); err != nil {
		_ = os.WriteFile(cfg, []byte("[user]\n\tname = Run\n\temail = run@example.invalid\n"), 0o644)
	}
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+cfg, "HOME="+home, "USERPROFILE="+home,
		"GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=Never", "GIT_ASKPASS=", "SSH_ASKPASS=",
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost", "HTTP_PROXY=", "http_proxy=",
	)
}

func gitTry(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(gitBin(t), args...)
	cmd.Dir = dir
	if env == nil {
		env = gitEnvFor(t.TempDir())
	}
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(3 * time.Minute):
		_ = cmd.Process.Kill()
		return buf.String(), fmt.Errorf("timed out")
	}
}

func gitMust(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	out, err := gitTry(t, dir, env, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func newGitHost(t *testing.T, live func(string) bool) *gitHost {
	t.Helper()
	git := gitBin(t)
	out, err := exec.Command(git, "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if runtime.GOOS == "windows" {
		backend += ".exe"
	}
	if _, err := os.Stat(backend); err != nil {
		t.Fatalf("RT-05 needs git http-backend: %v", err)
	}
	u := &gitHost{root: t.TempDir(), pw: map[string]bool{}, live: live}
	bare := u.bare()
	gitMust(t, "", nil, "init", "--bare", "-b", "main", bare)
	gitMust(t, bare, nil, "config", "http.receivepack", "true")
	seed := t.TempDir()
	gitMust(t, seed, nil, "init", "-b", "main", ".")
	if err := os.WriteFile(filepath.Join(seed, "README"), []byte("shop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitMust(t, seed, nil, "add", ".")
	gitMust(t, seed, nil, "commit", "-m", "seed")
	gitMust(t, seed, nil, "push", bare, "main")

	cgiH := &cgi.Handler{
		Path: backend,
		Env:  []string{"GIT_PROJECT_ROOT=" + u.root, "GIT_HTTP_EXPORT_ALL=1"},
		InheritEnv: []string{
			"PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE", "TMPDIR",
		},
	}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pw, ok := r.BasicAuth()
		u.mu.Lock()
		u.seen = append(u.seen, r.Method+" "+r.URL.Path)
		if ok && user == "x-access-token" {
			u.pw[pw] = true
			if u.live != nil && !u.live(pw) {
				u.notLive++
			}
		}
		u.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="github"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if r.ContentLength < 0 && r.Body != nil {
			// Go's CGI handler refuses chunked bodies; GitHub does not.
			f, err := os.CreateTemp(u.root, "body-*")
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			defer os.Remove(f.Name())
			defer f.Close()
			n, err := io.Copy(f, r.Body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_, _ = f.Seek(0, io.SeekStart)
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(f), n, nil
		}
		cgiH.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// ---- the rig with the git proxy mounted -----------------------------------

type pushRig struct {
	*rig
	gh    *ghtest.Server
	host  *gitHost
	home  string
	token string
	runID string
	url   string
}

func newPushRig(t *testing.T, o rigOpts, opsList ...string) *pushRig {
	t.Helper()
	gitBin(t)
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "acme", gh.PermsPush())
	in.AddRepo("shop", "main")
	in.AddRepo("other", "main")
	host := newGitHost(t, func(pw string) bool { return !s.TokenRevoked(pw) })

	g := newRig(t, o)
	git := &gitproxy.Handler{Gate: g.svc, Tokens: &ops.InstallationMinter{Client: c}, Revoker: c, Upstream: host.srv.URL, Now: s.Now}
	g.scfg.Git = git
	g.afterEnd = func(runID string) { // as chapd's AfterEnd hook does, then waits for the revokes it started
		git.EndRun(runID)
		git.WaitRevokes()
	}
	g.restart()
	if len(opsList) == 0 {
		opsList = []string{"branch.push", "pr.open"}
	}
	tok, runID := g.mint(opsList...)
	return &pushRig{rig: g, gh: s, host: host, home: t.TempDir(), token: tok, runID: runID,
		url: "http://x:" + tok + "@" + strings.TrimPrefix(g.srv.URL, "http://") + "/git/acme/shop.git"}
}

func (p *pushRig) git(dir string, args ...string) (string, error) {
	p.t.Helper()
	return gitTry(p.t, dir, gitEnvFor(p.home), args...)
}

func (p *pushRig) mustGit(dir string, args ...string) string {
	p.t.Helper()
	return gitMust(p.t, dir, gitEnvFor(p.home), args...)
}

func (p *pushRig) clone(url string) string {
	p.t.Helper()
	dir := filepath.Join(p.t.TempDir(), "work")
	p.mustGit("", "clone", "-q", url, dir)
	p.mustGit(dir, "checkout", "-q", "-b", rigBranch)
	return dir
}

func (p *pushRig) commit(dir, file, content string) {
	p.t.Helper()
	full := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		p.t.Fatal(err)
	}
	p.mustGit(dir, "add", file)
	p.mustGit(dir, "commit", "-q", "-m", "change "+file)
}

func (p *pushRig) refs() string {
	p.t.Helper()
	return gitMust(p.t, p.host.bare(), nil, "for-each-ref", "--format=%(refname) %(objectname)")
}

// leaks reports any installation token chapd used that shows up in text.
func (p *pushRig) noInstallationToken(text string) {
	p.t.Helper()
	for _, tok := range p.host.passwords() {
		if strings.Contains(text, tok) {
			p.t.Errorf("a GitHub installation token reached a place it must not:\n%s", text)
		}
	}
}

func mintReqBranch(branch string) runtoken.MintRequest {
	return runtoken.MintRequest{Project: rigProject, Profile: "host-interim", Repo: rigRepo, Base: "main", Branch: branch, Ops: []string{"branch.push"}, Minutes: 30}
}

func mintReqOps(opsList ...string) runtoken.MintRequest {
	r := mintReqBranch(rigBranch)
	r.Ops = opsList
	return r
}

func TestRT05PushToTheWrongRef(t *testing.T) {
	p := newPushRig(t, rigOpts{})
	dir := p.clone(p.url)
	p.commit(dir, "a.txt", "hello\n")
	p.mustGit(dir, "push", "origin", rigBranch) // control, and so there is a branch to delete

	refsBefore := p.refs()
	pushesBefore := p.host.requests("git-receive-pack")

	p.commit(dir, "evil.txt", "x\n")
	p.mustGit(dir, "tag", "v1")
	p.mustGit(dir, "tag", "-a", "-m", "release", "v2")
	p.mustGit(dir, "branch", "other")
	p.mustGit(dir, "branch", "agent/another-run")
	attacks := map[string][]string{
		"the base branch":                 {"push", "origin", rigBranch + ":main"},
		"the base branch, forced":         {"push", "--force", "origin", "HEAD:refs/heads/main"},
		"a tag":                           {"push", "origin", "v1"},
		"an annotated tag":                {"push", "origin", "v2"},
		"all tags":                        {"push", "origin", "--tags"},
		"a tag that replaces another":     {"push", "--force", "origin", "v1:refs/tags/v0"},
		"another branch":                  {"push", "origin", "other"},
		"another run's agent/ branch":     {"push", "origin", "agent/another-run"},
		"deleting the task branch":        {"push", "origin", ":" + rigBranch},
		"deleting the base branch":        {"push", "origin", ":main"},
		"two refs in one push":            {"push", "origin", rigBranch, "other"},
		"every branch":                    {"push", "origin", "--all"},
		"a mirror":                        {"push", "origin", "--mirror"},
		"another ref namespace":           {"push", "origin", "HEAD:refs/changes/1"},
		"refs/pull":                       {"push", "origin", "HEAD:refs/pull/1/head"},
		"the task branch under a new tag": {"push", "origin", "HEAD:refs/tags/" + rigBranch},
	}
	for name, args := range attacks {
		t.Run(name, func(t *testing.T) {
			out, err := p.git(dir, args...)
			if err == nil {
				t.Fatalf("the push was accepted:\n%s", out)
			}
			p.noInstallationToken(out)
		})
	}
	if n := p.host.requests("git-receive-pack") - pushesBefore; n != 0 {
		t.Errorf("%d refused push(es) reached GitHub", n)
	}
	if after := p.refs(); after != refsBefore {
		t.Errorf("the remote changed under refused pushes:\nbefore:\n%s\nafter:\n%s", refsBefore, after)
	}
	if p.host.notLive != 0 {
		t.Errorf("GitHub saw %d request(s) with a revoked installation token", p.host.notLive)
	}
	// The run is still active, so chapd still holds its tokens; the refused
	// pushes minted none of their own (one fetch token, one push token).
	if n := p.gh.LiveTokens(); n > 2 {
		t.Errorf("%d installation token(s) live for one run, want at most 2", n)
	}
	// Every refusal is a denial in the ledger, none holds a GitHub token.
	if n := p.count(`SELECT COUNT(*) FROM ledger_events WHERE event_name = 'denial' AND event LIKE '%SCOPE_BRANCH%'`); n < len(attacks) {
		t.Errorf("%d SCOPE_BRANCH denial events for %d refused pushes", n, len(attacks))
	}
	p.noInstallationToken(p.ledgerText())
	p.mustLedgerOK()

	// Control: a fast-forward of the task branch lands and is recorded.
	p.commit(dir, "b.txt", "more\n")
	if out, err := p.git(dir, "push", "origin", rigBranch); err != nil {
		t.Fatalf("control push: %v\n%s", err, out)
	}
	if !strings.Contains(p.refs(), "refs/heads/"+rigBranch) {
		t.Fatalf("the control push did not land: %s", p.refs())
	}
	if n := p.count(`SELECT COUNT(*) FROM ops WHERE op = 'branch.push' AND state = 'succeeded'`); n != 2 {
		t.Errorf("%d succeeded branch.push ops, want 2 (the two control pushes)", n)
	}
	// Ending the run revokes what chapd held for it.
	if err := p.runs.Revoke(context.Background(), p.runID, "OPERATOR_STOP_RUN"); err != nil {
		t.Fatal(err)
	}
	if n := p.gh.LiveTokens(); n != 0 {
		t.Errorf("%d installation token(s) left live after the run ended", n)
	}
	if p.host.notLive != 0 {
		t.Errorf("GitHub saw %d request(s) with a revoked installation token", p.host.notLive)
	}
}

func TestRT05PushByARunThatMayNot(t *testing.T) {
	// Another run's token: its task branch is another one.
	p := newPushRig(t, rigOpts{})
	dir := p.clone(p.url)
	p.commit(dir, "a.txt", "a\n")
	res, err := p.minter.Mint(context.Background(), p.OrchToken, mintReqBranch("agent/rt-2"))
	if err != nil {
		t.Fatal(err)
	}
	otherURL := "http://x:" + res.Token + "@" + strings.TrimPrefix(p.srv.URL, "http://") + "/git/acme/shop.git"
	before := p.host.requests("git-receive-pack")
	out, perr := p.git(dir, "push", otherURL, rigBranch)
	if perr == nil {
		t.Fatalf("a run pushed to another run's branch:\n%s", out)
	}
	if p.host.requests("git-receive-pack") != before {
		t.Error("the refused push reached GitHub")
	}

	// A token that does not hold branch.push.
	res, err = p.minter.Mint(context.Background(), p.OrchToken, mintReqOps("health"))
	if err != nil {
		t.Fatal(err)
	}
	noPush := "http://x:" + res.Token + "@" + strings.TrimPrefix(p.srv.URL, "http://") + "/git/acme/shop.git"
	if out, perr := p.git(dir, "push", noPush, rigBranch); perr == nil {
		t.Fatalf("a token without branch.push pushed:\n%s", out)
	}
	// The wrong repository.
	wrong := "http://x:" + p.token + "@" + strings.TrimPrefix(p.srv.URL, "http://") + "/git/acme/other.git"
	if out, perr := p.git(dir, "push", wrong, rigBranch); perr == nil {
		t.Fatalf("a run pushed to another repository:\n%s", out)
	}
	if out, perr := p.git("", "clone", "-q", wrong, filepath.Join(t.TempDir(), "x")); perr == nil {
		t.Fatalf("a run cloned another repository:\n%s", out)
	}
	if p.host.requests("git-receive-pack") != before {
		t.Error("a refused push reached GitHub")
	}

	// A forged, an altered and an absent credential.
	for name, tok := range map[string]string{"a made-up token": "nope", "the orchestrator token": p.OrchToken, "empty": ""} {
		u := "http://x:" + tok + "@" + strings.TrimPrefix(p.srv.URL, "http://") + "/git/acme/shop.git"
		if out, perr := p.git(dir, "push", u, rigBranch); perr == nil {
			t.Fatalf("%s pushed:\n%s", name, out)
		}
	}
	if p.host.requests("git-receive-pack") != before {
		t.Error("a refused push reached GitHub")
	}
}

func TestRT05PushAfterTheRunEnded(t *testing.T) {
	p := newPushRig(t, rigOpts{})
	dir := p.clone(p.url)
	p.commit(dir, "a.txt", "a\n")
	p.mustGit(dir, "push", "origin", rigBranch)
	if err := p.runs.Revoke(context.Background(), p.runID, "OPERATOR_STOP_RUN"); err != nil {
		t.Fatal(err)
	}
	if n := p.gh.LiveTokens(); n != 0 {
		t.Errorf("%d installation token(s) left live after the run was revoked", n)
	}
	before := p.host.requests("")
	p.commit(dir, "b.txt", "b\n")
	if out, err := p.git(dir, "push", "origin", rigBranch); err == nil {
		t.Fatalf("a revoked run pushed:\n%s", out)
	}
	if out, err := p.git("", "clone", "-q", p.url, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatalf("a revoked run cloned:\n%s", out)
	}
	if p.host.requests("") != before {
		t.Error("a revoked run's request reached GitHub")
	}
}

func TestRT05WorkflowFilesNeedAPermissionChapdNeverAsksFor(t *testing.T) {
	p := newPushRig(t, rigOpts{})
	dir := p.clone(p.url)
	p.commit(dir, ".github/workflows/evil.yml", "on: push\njobs: {}\n")
	// The fake GitHub cannot refuse a workflow file (it does not read packs),
	// and neither can chapd: the push of the task branch is allowed.
	if out, err := p.git(dir, "push", "origin", rigBranch); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// What protects the repository is the token. Look at every installation
	// token chapd minted on the way: its permissions.
	var mints int
	for _, r := range p.gh.Requests() {
		if r.Method != "POST" || !strings.Contains(r.Path, "/access_tokens") {
			continue
		}
		mints++
		var body struct {
			Permissions  map[string]string `json:"permissions"`
			Repositories []string          `json:"repositories"`
		}
		if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
			t.Fatalf("%v: %q", err, r.Body)
		}
		if _, ok := body.Permissions["workflows"]; ok {
			t.Errorf("chapd asked GitHub for the workflows permission: %v", body.Permissions)
		}
		for perm, level := range body.Permissions {
			// A fetch asks for less than a push (contents:read); never for more.
			if want, ok := gh.PermsPush()[perm]; !ok || (level != want && !(level == gh.Read && want == gh.Write)) {
				t.Errorf("permission %s:%s is not within the push set %v", perm, level, gh.PermsPush())
			}
		}
		if len(body.Repositories) != 1 || body.Repositories[0] != "shop" {
			t.Errorf("the token is not narrowed to the one repository: %v", body.Repositories)
		}
	}
	if mints == 0 {
		t.Fatal("no installation token was minted, so the permission check proved nothing")
	}
	if _, ok := gh.PermsPush()["workflows"]; ok {
		t.Fatal("PermsPush grants workflows")
	}
	// And the op that would allow it is off, and not in any interim ceiling an agent can mint.
	st, body := p.call("POST", "/v0/dev-tokens", p.OrchToken, devTokenReq("pr.push.workflow"))
	if st < 400 {
		t.Fatalf("a token that may push workflows was minted: %d %v", st, body)
	}
}
