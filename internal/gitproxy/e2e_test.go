package gitproxy_test

// End-to-end tests: a real `git` client talks to chapd's /git/ routes; chapd talks
// to a fake GitHub that serves a local bare repository through `git
// http-backend`. The op service, store and policy are the real ones.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/store"
)

const (
	runTok = "eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2ln"
	branch = "agent/r-7f3a"
)

// ---- ops plumbing ----------------------------------------------------------

type tableLedger struct{}

func (tableLedger) AppendTx(ctx context.Context, tx *store.Tx, e ops.Event) error {
	attrs, _ := json.Marshal(e.Attributes)
	_, err := tx.ExecContext(ctx, `INSERT INTO test_ledger (name, attrs) VALUES (?, ?)`, e.Name, string(attrs))
	return err
}

type verifier struct{}

func (verifier) VerifyRun(_ context.Context, b string) (*ops.Caller, error) {
	if b != runTok {
		return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "signature does not verify"}
	}
	return &ops.Caller{
		Kind: ops.KindRun, RunID: "r-7f3a", JTI: "jti-aaaaaaaaaaaaaaaa", Profile: "code", Project: "acme-shop",
		Repo: "acme/shop", Base: "main", Branch: branch, TokenOps: []string{"branch.push"},
	}, nil
}

func (verifier) VerifyOrch(context.Context, string) (*ops.Caller, error) {
	return nil, &ops.VerifyError{Code: ops.CodeTokenInvalid, Detail: "no orchestrators here"}
}

// ---- the fake GitHub git host ---------------------------------------------

// upstream serves /acme/shop.git through git http-backend and records what it saw.
type upstream struct {
	mu       sync.Mutex
	srv      *httptest.Server
	root     string
	seen     []string                // "METHOD path"
	pw       map[string]bool         // every Basic password it was given
	badUser  int                     // requests whose user was not x-access-token
	noAuth   int                     // requests without credentials
	fail     func(*http.Request) int // non-zero: answer with this status
	live     func(string) bool       // is this password a live installation token
	notLive  int
	answers  []string // "METHOD path -> status head-of-body"
	gzipSeen int
	chunked  int
}

func (u *upstream) requests(sub string) int {
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

func (u *upstream) tokens() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []string
	for p := range u.pw {
		out = append(out, p)
	}
	return out
}

func gitExe(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	return p
}

func newUpstream(t *testing.T, live func(string) bool) *upstream {
	t.Helper()
	git := gitExe(t)
	out, err := exec.Command(git, "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if runtime.GOOS == "windows" {
		backend += ".exe"
	}
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git http-backend is not available: %v", err)
	}
	u := &upstream{root: t.TempDir(), pw: map[string]bool{}, live: live}
	bare := filepath.Join(u.root, "acme", "shop.git")
	run(t, "", nil, "git", "init", "--bare", "-b", "main", bare)
	run(t, bare, nil, "git", "config", "http.receivepack", "true")
	// Seed main with one commit.
	seed := t.TempDir()
	run(t, seed, nil, "git", "init", "-b", "main", ".")
	write(t, filepath.Join(seed, "README"), "shop\n")
	run(t, seed, nil, "git", "add", ".")
	run(t, seed, nil, "git", "commit", "-m", "seed")
	run(t, seed, nil, "git", "push", bare, "main")

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
		switch {
		case !ok:
			u.noAuth++
		case user != "x-access-token":
			u.badUser++
		default:
			u.pw[pw] = true
			if u.live != nil && !u.live(pw) {
				u.notLive++
			}
		}
		if r.Header.Get("Content-Encoding") == "gzip" {
			u.gzipSeen++
		}
		if len(r.TransferEncoding) > 0 {
			u.chunked++
		}
		fail := u.fail
		u.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="github"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if fail != nil {
			if st := fail(r); st != 0 {
				http.Error(w, "injected", st)
				return
			}
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
		sw := &statusWriter{ResponseWriter: w, status: 200}
		cgiH.ServeHTTP(sw, r)
		u.mu.Lock()
		u.answers = append(u.answers, fmt.Sprintf("%s %s -> %d %s", r.Method, r.URL.Path, sw.status, sw.head))
		u.mu.Unlock()
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// statusWriter keeps the status and the first bytes of an answer for failure messages.
type statusWriter struct {
	http.ResponseWriter
	status int
	head   string
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status >= 400 && len(s.head) < 200 {
		s.head += string(b)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (u *upstream) bare() string { return filepath.Join(u.root, "acme", "shop.git") }

// ---- the rig ---------------------------------------------------------------

type rig struct {
	t     *testing.T
	gh    *ghtest.Server
	up    *upstream
	db    *store.DB
	chapd *httptest.Server
	url   string // the repo URL a run uses
	home  string
	rt    *recorder
	h     *gitproxy.Handler
}

// recorder wraps the proxy to count what reached it.
type recorder struct {
	ops.GitHandler
	mu sync.Mutex
	n  int
}

func (r *recorder) ServeGit(w http.ResponseWriter, req *http.Request, c *ops.Caller) error {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	return r.GitHandler.ServeGit(w, req, c)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	gitExe(t)
	ctx := context.Background()

	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "acme", map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"})
	in.AddRepo("shop", "main")
	in.AddRepo("other", "main")
	up := newUpstream(t, func(pw string) bool { return !s.TokenRevoked(pw) })

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`CREATE TABLE test_ledger (seq INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, attrs TEXT)`); err != nil {
		t.Fatal(err)
	}
	cat, pack, err := policy.Default() // the shipped baseline has branch.push on
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ops.NewService(ops.Config{DB: db, Ledger: tableLedger{}, Policy: policy.NewEngine(cat, pack, "")})
	if err != nil {
		t.Fatal(err)
	}

	h := &gitproxy.Handler{
		Gate: svc, Tokens: &ops.InstallationMinter{Client: c}, Revoker: c, Upstream: up.srv.URL, Now: s.Now,
	}
	rec := &recorder{GitHandler: h}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := ln.Addr().String()
	srv := ops.NewServer(ops.ServerConfig{
		Svc: svc, Auth: &ops.Auth{Run: verifier{}, Orch: verifier{}, Svc: svc}, Version: "test",
		Hosts: []string{host}, Git: rec,
	})
	ts := httptest.NewUnstartedServer(srv)
	ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)

	return &rig{
		t: t, gh: s, up: up, db: db, chapd: ts, home: t.TempDir(), rt: rec, h: h,
		url: "http://x:" + runTok + "@" + host + "/git/acme/shop.git",
	}
}

// ---- helpers ----------------------------------------------------------------

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitEnv(home string) []string {
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

// run executes a command and fails the test on error; with env nil it uses a clean git env.
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	out, err := tryRun(t, dir, env, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func tryRun(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env == nil {
		env = gitEnv(t.TempDir())
	}
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(5 * time.Minute):
		_ = cmd.Process.Kill()
		return buf.String(), fmt.Errorf("timed out")
	}
}

// git runs git in dir with the rig's client environment.
func (g *rig) git(dir string, args ...string) (string, error) {
	g.t.Helper()
	return tryRun(g.t, dir, gitEnv(g.home), "git", args...)
}

func (g *rig) mustGit(dir string, args ...string) string {
	g.t.Helper()
	out, err := g.git(dir, args...)
	if err != nil {
		g.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// clone makes a working copy of the shop repo on a task branch.
func (g *rig) clone() string {
	g.t.Helper()
	dir := filepath.Join(g.t.TempDir(), "work")
	g.mustGit("", "clone", "-q", g.url, dir)
	g.mustGit(dir, "checkout", "-q", "-b", branch)
	return dir
}

func (g *rig) commit(dir, file, content string) {
	g.t.Helper()
	write(g.t, filepath.Join(dir, file), content)
	g.mustGit(dir, "add", file)
	g.mustGit(dir, "commit", "-q", "-m", "change "+file)
}

func (g *rig) opStates() map[string]int {
	g.t.Helper()
	rs, err := g.db.SQL().Query(`SELECT state, COUNT(*) FROM ops WHERE op = 'branch.push' GROUP BY state`)
	if err != nil {
		g.t.Fatal(err)
	}
	defer rs.Close()
	out := map[string]int{}
	for rs.Next() {
		var s string
		var n int
		if err := rs.Scan(&s, &n); err != nil {
			g.t.Fatal(err)
		}
		out[s] = n
	}
	return out
}

func (g *rig) ledgerCount(name string) int {
	g.t.Helper()
	var n int
	if err := g.db.SQL().QueryRow(`SELECT COUNT(*) FROM test_ledger WHERE name = ?`, name).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

func (g *rig) denials(code string) int {
	g.t.Helper()
	var n int
	if err := g.db.SQL().QueryRow(`SELECT COUNT(*) FROM denials WHERE cause_code = ?`, code).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

// remoteRefs lists the refs of the bare repo behind the fake GitHub.
func (g *rig) remoteRefs() string {
	g.t.Helper()
	return run(g.t, g.up.bare(), nil, "git", "for-each-ref", "--format=%(refname)")
}

// noSecrets fails when text shows a GitHub token the proxy used.
func (g *rig) noSecrets(text string) {
	g.t.Helper()
	for _, tok := range g.up.tokens() {
		if strings.Contains(text, tok) {
			g.t.Errorf("a GitHub installation token reached the client:\n%s", text)
		}
	}
}

// ---- tests ------------------------------------------------------------------

func TestCloneAndFetchGoThroughTheProxy(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	if _, err := os.Stat(filepath.Join(dir, "README")); err != nil {
		t.Fatal(err)
	}
	out := g.mustGit(dir, "fetch", "origin")
	g.noSecrets(out)

	if g.up.requests("POST") == 0 {
		t.Error("the clone made no upload-pack call upstream")
	}
	toks := g.up.tokens()
	if len(toks) == 0 {
		t.Fatal("the proxy sent no credential upstream")
	}
	for _, tok := range toks {
		if tok == runTok {
			t.Error("the run token was forwarded to GitHub")
		}
	}
	g.up.mu.Lock()
	defer g.up.mu.Unlock()
	if g.up.noAuth != 0 || g.up.badUser != 0 || g.up.notLive != 0 {
		t.Errorf("upstream saw noAuth=%d badUser=%d notLive=%d, want 0", g.up.noAuth, g.up.badUser, g.up.notLive)
	}
	g.endRun()
	if n := g.gh.LiveTokens(); n != 0 {
		t.Errorf("%d installation tokens still live", n)
	}
}

func TestPushTaskBranchSucceedsAndIsRecorded(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	g.commit(dir, "a.txt", "hello\n")
	out, err := g.git(dir, "push", "origin", branch)
	if err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	g.noSecrets(out)
	if !strings.Contains(g.remoteRefs(), "refs/heads/"+branch) {
		t.Errorf("the branch did not land: %s", g.remoteRefs())
	}
	if st := g.opStates(); st["succeeded"] != 1 || len(st) != 1 {
		t.Errorf("op states %v, want one succeeded", st)
	}
	if g.ledgerCount("op.request") != 1 || g.ledgerCount("op.result") != 1 {
		t.Errorf("ledger: %d op.request, %d op.result, want 1 each", g.ledgerCount("op.request"), g.ledgerCount("op.result"))
	}
	if n := g.gh.LiveTokens(); n != 2 { // the run's fetch token and push token, kept for the run
		t.Errorf("%d installation tokens live while the run is active, want 2", n)
	}

	// A second push to the same branch (fast-forward) is a second op.
	g.commit(dir, "b.txt", "more\n")
	g.mustGit(dir, "push", "origin", branch)
	if st := g.opStates(); st["succeeded"] != 2 {
		t.Errorf("op states %v, want two succeeded", st)
	}
	if n := len(g.mintedSets()); n != 2 {
		t.Errorf("%d tokens minted for a clone and two pushes, want 2", n)
	}
	g.endRun()
	if n := g.gh.LiveTokens(); n != 0 {
		t.Errorf("%d installation tokens still live after the run ended", n)
	}
}

func TestPushRefusalsNeverReachGitHub(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	g.commit(dir, "a.txt", "hello\n")
	g.mustGit(dir, "push", "origin", branch) // so there is a branch to delete
	before := g.up.requests("git-receive-pack")

	g.commit(dir, "evil.txt", "x\n")
	g.mustGit(dir, "tag", "v1")
	g.mustGit(dir, "branch", "other")
	for name, args := range map[string][]string{
		"base branch":  {"push", "origin", branch + ":main"},
		"other branch": {"push", "origin", "other"},
		"tag":          {"push", "origin", "v1"},
		"delete":       {"push", "origin", ":" + branch},
		"two refs":     {"push", "origin", branch, "other"},
		"force base":   {"push", "--force", "origin", "HEAD:refs/heads/main"},
		"other ns":     {"push", "origin", "HEAD:refs/changes/1"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := g.git(dir, args...)
			if err == nil {
				t.Fatalf("push was accepted:\n%s", out)
			}
			if !strings.Contains(out, "SCOPE_BRANCH") && !strings.Contains(out, branch) {
				t.Logf("refusal text: %s", out)
			}
			g.noSecrets(out)
		})
	}
	if n := g.up.requests("git-receive-pack") - before; n != 0 {
		t.Errorf("a refused push reached GitHub (%d new receive-pack POSTs)", n)
	}
	refs := g.remoteRefs()
	if strings.Contains(refs, "refs/tags/v1") || strings.Contains(refs, "refs/heads/other") {
		t.Errorf("a refused ref landed: %s", refs)
	}
	if !strings.Contains(refs, "refs/heads/"+branch) || !strings.Contains(refs, "refs/heads/main") {
		t.Errorf("a refused push damaged the remote: %s", refs)
	}
	if g.denials("SCOPE_BRANCH") < 7 {
		t.Errorf("%d SCOPE_BRANCH denials, want one per refused push", g.denials("SCOPE_BRANCH"))
	}
	if st := g.opStates(); st["denied"] < 7 || st["succeeded"] != 1 {
		t.Errorf("op states %v", st)
	}
}

func TestFetchOfAnotherRepoIsRefused(t *testing.T) {
	g := newRig(t)
	url := strings.Replace(g.url, "shop.git", "other.git", 1)
	out, err := g.git("", "clone", "-q", url, filepath.Join(t.TempDir(), "x"))
	if err == nil {
		t.Fatal("clone of another repo succeeded")
	}
	g.noSecrets(out)
	if len(g.up.seen) != 0 {
		t.Errorf("the refused fetch reached GitHub: %v", g.up.seen)
	}
	if g.denials("SCOPE_PATH") == 0 {
		t.Error("no SCOPE_PATH denial recorded")
	}
}

func TestWrongRunTokenIsChallengedWithBasic(t *testing.T) {
	g := newRig(t)
	host := strings.TrimPrefix(g.chapd.URL, "http://")
	resp, err := http.Get("http://" + host + "/git/acme/shop.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("no credentials: %d %q, want 401 with a Basic challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	bad := strings.Replace(g.url, runTok, "nope", 1)
	out, err := g.git("", "clone", "-q", bad, filepath.Join(t.TempDir(), "x"))
	if err == nil {
		t.Fatalf("a wrong token cloned:\n%s", out)
	}
	if len(g.up.seen) != 0 {
		t.Errorf("an unauthenticated call reached GitHub: %v", g.up.seen)
	}
}

func TestPushUnconfirmedWhenGitHubFailsAfterSending(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	g.commit(dir, "a.txt", "hello\n")
	g.up.mu.Lock()
	g.up.fail = func(r *http.Request) int {
		if r.Method == http.MethodPost {
			return http.StatusBadGateway
		}
		return 0
	}
	g.up.mu.Unlock()
	if out, err := g.git(dir, "push", "origin", branch); err == nil {
		t.Fatalf("push succeeded against a failing GitHub:\n%s", out)
	}
	if st := g.opStates(); st["unconfirmed"] != 1 {
		t.Errorf("op states %v, want one unconfirmed", st)
	}
	// The retry is not held back behind the unconfirmed try.
	g.up.mu.Lock()
	g.up.fail = nil
	g.up.mu.Unlock()
	if out, err := g.git(dir, "push", "origin", branch); err != nil {
		t.Fatalf("retry: %v\n%s", err, out)
	}
	if st := g.opStates(); st["succeeded"] != 1 || st["unconfirmed"] != 1 {
		t.Errorf("op states %v, want one succeeded and one unconfirmed", st)
	}
	g.endRun()
	if n := g.gh.LiveTokens(); n != 0 {
		t.Errorf("%d installation tokens still live", n)
	}
}

func TestPushRejectedByGitHubIsFailed(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	g.commit(dir, "a.txt", "hello\n")
	g.mustGit(dir, "push", "origin", branch)
	// A non-fast-forward the client forces: GitHub (git) refuses it.
	run(t, g.up.bare(), nil, "git", "config", "receive.denyNonFastForwards", "true")
	g.mustGit(dir, "reset", "-q", "--hard", "HEAD~1")
	g.commit(dir, "c.txt", "diverged\n")
	out, err := g.git(dir, "push", "--force", "origin", branch)
	if err == nil {
		t.Fatalf("a forced non-fast-forward was accepted:\n%s", out)
	}
	st := g.opStates()
	if st["failed"] != 1 || st["succeeded"] != 1 {
		t.Errorf("op states %v, want one succeeded and one failed", st)
	}
}

func TestLargePushStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("50 MB push")
	}
	g := newRig(t)
	dir := g.clone()
	blob := make([]byte, 50<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	g.mustGit(dir, "add", "big.bin")
	g.mustGit(dir, "commit", "-q", "-m", "big")
	out, err := g.git(dir, "push", "origin", branch)
	if err != nil {
		t.Fatalf("push: %v\n%s\nupstream answered %v; ops %v", err, out, g.up.answers, g.opStates())
	}
	if !strings.Contains(g.remoteRefs(), "refs/heads/"+branch) {
		t.Errorf("the big push did not land")
	}
	if g.up.chunked == 0 {
		t.Log("[note] the 50 MB push was not sent chunked")
	}
	if st := g.opStates(); st["succeeded"] != 1 {
		t.Errorf("op states %v", st)
	}
	// And it can be fetched back through the proxy.
	back := filepath.Join(t.TempDir(), "back")
	g.mustGit("", "clone", "-q", "-b", branch, g.url, back)
	if fi, err := os.Stat(filepath.Join(back, "big.bin")); err != nil || fi.Size() != int64(len(blob)) {
		t.Errorf("cloned big file: %v %v", fi, err)
	}
}

// pkt makes one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func (g *rig) rawPush(body []byte, gz bool) (int, string) {
	g.t.Helper()
	host := strings.TrimPrefix(g.chapd.URL, "http://")
	req, err := http.NewRequest(http.MethodPost, "http://"+host+"/git/acme/shop.git/git-receive-pack", bytes.NewReader(body))
	if err != nil {
		g.t.Fatal(err)
	}
	req.SetBasicAuth("x", runTok)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestHandCraftedPushRequestsAreRefused(t *testing.T) {
	g := newRig(t)
	zero := strings.Repeat("0", 40)
	one := strings.Repeat("1", 40)
	cmd := func(ref string) string {
		return pkt(zero + " " + one + " " + ref + "\x00report-status side-band-64k\n")
	}

	for name, tc := range map[string]struct {
		body []byte
		gz   bool
		want string
	}{
		"plain, base":   {[]byte(cmd("refs/heads/main") + "0000"), false, "this run may push"},
		"gzip, base":    {gz([]byte(cmd("refs/heads/main") + "0000PACK")), true, "this run may push"},
		"gzip, tag":     {gz([]byte(cmd("refs/tags/v1") + "0000")), true, "this run may push"},
		"push-cert":     {[]byte(pkt("push-cert\x00report-status\n") + "0000"), false, "push-cert"},
		"two commands":  {[]byte(cmd("refs/heads/"+branch) + pkt(zero+" "+one+" refs/heads/x\n") + "0000"), false, "one push may update one ref"},
		"delete":        {[]byte(pkt(one+" "+zero+" refs/heads/"+branch+"\x00report-status\n") + "0000"), false, "is not allowed"},
		"garbage":       {[]byte("this is not git"), false, "could not be read"},
		"bad gzip":      {[]byte("not gzip at all"), true, "could not be read"},
		"no flush":      {[]byte(cmd("refs/heads/" + branch)), false, "could not be read"},
		"no commands":   {[]byte("0000x"), false, "no ref update"},
		"bad object id": {[]byte(pkt("xyz "+one+" refs/heads/"+branch+"\n") + "0000"), false, "could not be read"},
	} {
		t.Run(name, func(t *testing.T) {
			before := g.up.requests("POST")
			status, body := g.rawPush(tc.body, tc.gz)
			if status < 400 || !strings.Contains(body, tc.want) {
				t.Errorf("status %d body %q, want a refusal with %s", status, body, tc.want)
			}
			if n := g.up.requests("POST") - before; n != 0 {
				t.Errorf("a refused request reached GitHub")
			}
		})
	}
	if n := g.denials("SCOPE_BRANCH"); n != 6 {
		t.Errorf("%d SCOPE_BRANCH denials, want 6", n)
	}
	if n := g.denials("OP_PARAMS_INVALID"); n != 5 {
		t.Errorf("%d OP_PARAMS_INVALID denials, want 5", n)
	}
}

func TestOnlyGitRoutesAreServed(t *testing.T) {
	g := newRig(t)
	host := strings.TrimPrefix(g.chapd.URL, "http://")
	for _, p := range []string{
		"/git/acme/shop.git/HEAD",
		"/git/acme/shop.git/objects/info/packs",
		"/git/acme/shop.git/info/refs", // dumb protocol: no service
		"/git/acme/shop.git/info/refs?service=git-upload-archive",
		"/git/acme",
		"/git/acme/../other/info/refs?service=git-upload-pack",
	} {
		req, _ := http.NewRequest("GET", "http://"+host+p, nil)
		req.SetBasicAuth("x", runTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("GET %s: %d, want a refusal", p, resp.StatusCode)
		}
	}
	if len(g.up.seen) != 0 {
		t.Errorf("a non-git route reached GitHub: %v", g.up.seen)
	}
}

// git sends a bare flush-pkt before a large push, to test its credentials. It
// updates nothing, so it is not an op.
func TestPushProbeIsForwardedWithoutAnOp(t *testing.T) {
	g := newRig(t)
	status, body := g.rawPush([]byte("0000"), false)
	if status != 200 {
		t.Errorf("probe: %d %q, want 200", status, body)
	}
	if n := g.up.requests("POST /acme/shop.git/git-receive-pack"); n != 1 {
		t.Errorf("%d receive-pack POSTs upstream, want 1", n)
	}
	if st := g.opStates(); len(st) != 0 {
		t.Errorf("a probe made ops: %v", st)
	}
	g.endRun()
	if g.gh.LiveTokens() != 0 {
		t.Error("a token is still live")
	}
}

// GitHub may answer before it has read the pack. The proxy must stop reading
// the client's body cleanly (net/http panics otherwise) and record the push as
// unconfirmed, and the connection must serve the next request.
func TestEarlyUpstreamAnswerDuringALargeBody(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	blob := make([]byte, 8<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	g.mustGit(dir, "add", "big.bin")
	g.mustGit(dir, "commit", "-q", "-m", "big")
	g.up.mu.Lock()
	g.up.fail = func(r *http.Request) int {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-receive-pack") && r.ContentLength != 4 {
			return http.StatusServiceUnavailable
		}
		return 0
	}
	g.up.mu.Unlock()
	if out, err := g.git(dir, "push", "origin", branch); err == nil {
		t.Fatalf("push succeeded:\n%s", out)
	}
	if st := g.opStates(); st["unconfirmed"] != 1 {
		t.Errorf("op states %v, want one unconfirmed", st)
	}
	g.up.mu.Lock()
	g.up.fail = nil
	g.up.mu.Unlock()
	if out, err := g.git(dir, "push", "origin", branch); err != nil {
		t.Fatalf("retry: %v\n%s", err, out)
	}
}

// endRun ends the run the rig's verifier admits, as the run registry does when
// the run ends: the proxy then revokes the tokens it kept for the run.
func (g *rig) endRun() {
	g.t.Helper()
	g.h.EndRun("r-7f3a")
	g.h.WaitRevokes()
}

// mintedSets are the permission sets of every installation token the fake was
// asked for, in order.
func (g *rig) mintedSets() []string {
	var out []string
	for _, r := range g.gh.Requests() {
		if r.Method != "POST" || !strings.HasSuffix(r.Path, "/access_tokens") {
			continue
		}
		var b struct{ Permissions map[string]string }
		_ = json.Unmarshal([]byte(r.Body), &b)
		out = append(out, fmt.Sprint(b.Permissions))
	}
	return out
}

// Least privilege, pinned (ADR-002 item 1, amendment 9): a clone or fetch gets
// contents:read and nothing else; a push gets what receive-pack needs
// (contents:write, metadata:read) and the pull_requests:write it has always
// carried. Each permission set is its own token, minted once for the run: a
// clone, a fetch and a push are about ten HTTP requests, and two tokens serve
// them all.
func TestProxyTokenPermissionsPerGitCall(t *testing.T) {
	g := newRig(t)
	dir := g.clone()
	g.mustGit(dir, "fetch", "origin")
	fetch := fmt.Sprint(map[string]string{"contents": "read"})
	if sets := g.mintedSets(); len(sets) != 1 || sets[0] != fetch {
		t.Fatalf("a clone and a fetch minted %v, want one %s", sets, fetch)
	}

	g.commit(dir, "a.txt", "hello\n")
	g.mustGit(dir, "push", "origin", branch)
	push := fmt.Sprint(gh.PermsPush())
	if want := fmt.Sprint(map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}); push != want {
		t.Fatalf("PermsPush = %s, want %s", push, want)
	}
	if sets := g.mintedSets(); len(sets) != 2 || sets[0] != fetch || sets[1] != push {
		t.Fatalf("after a push the minted sets are %v, want [%s %s]", sets, fetch, push)
	}

	// More of the same reuses both tokens.
	g.mustGit(dir, "fetch", "origin")
	g.commit(dir, "b.txt", "more\n")
	g.mustGit(dir, "push", "origin", branch)
	if sets := g.mintedSets(); len(sets) != 2 {
		t.Errorf("a second fetch and push minted again: %v", sets)
	}
	if n := g.gh.LiveTokens(); n != 2 {
		t.Errorf("%d tokens live while the run is active, want 2", n)
	}
	g.endRun()
	if n := g.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live after the run ended, want 0", n)
	}
}
