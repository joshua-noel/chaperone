package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
)

func qsFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// qsRun is one `chapd quickstart` running in this process.
type qsRun struct {
	t      *testing.T
	out    *syncBuf
	done   chan error
	cancel context.CancelFunc
}

func startQuickstart(t *testing.T, o quickstartOptions) *qsRun {
	t.Helper()
	o.Playground = true
	ctx, cancel := context.WithCancel(context.Background())
	r := &qsRun{t: t, out: &syncBuf{}, done: make(chan error, 1), cancel: cancel}
	go func() { r.done <- runQuickstart(ctx, o, r.out) }()
	t.Cleanup(func() { r.stop() })
	return r
}

// ready waits for the printed text (its last line is the pull request 2 command).
func (r *qsRun) ready() string {
	r.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-r.done:
			r.t.Fatalf("quickstart ended early: %v\n%s", err, r.out.String())
		default:
		}
		if s := r.out.String(); strings.Contains(s, "Extra: pull request 2") && strings.Count(s, "\n") > 20 && strings.HasSuffix(s, "\n") {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("quickstart printed nothing useful:\n%s", r.out.String())
	return ""
}

func (r *qsRun) stop() error {
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(30 * time.Second):
		r.t.Error("quickstart did not stop")
		return errors.New("timeout")
	}
}

var (
	enrolRe = regexp.MustCompile(`http://localhost:(\d+)/enroll#(\S+)`)
	mergeRe = regexp.MustCompile(`chap pr merge 3 --head ([0-9a-f]{40}) `)
)

// ---- what it refuses ----

func TestQuickstartRefusesTheRealPort(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:55398", "127.0.0.1:055398"} {
		if err := checkQuickstartAddr(addr); err == nil || !strings.Contains(err.Error(), "55398") {
			t.Errorf("%s: %v", addr, err)
		}
	}
	dir := filepath.Join(t.TempDir(), "qs")
	var out, errb bytes.Buffer
	if code := quickstartCmd([]string{"--dir", dir, "--addr", "127.0.0.1:55398"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "55398") {
		t.Errorf("stderr: %s", errb.String())
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the folder was created before the address was refused")
	}
	// A marker that names the real port is refused too, so a folder cannot be edited into it.
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, quickstartMarker), []byte(`{"kind":"chaperone-quickstart","version":1,"addr":"127.0.0.1:55398"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkQuickstartDir(d); err == nil {
		t.Error("a folder whose marker names the real port was accepted")
	}
}

func TestQuickstartRefusesANonLoopbackAddress(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:55421", "[::]:55421", ":55421", "192.0.2.20:55421", "10.0.0.5:55421", "8.8.8.8:55421",
		"localhost:55421", "example.com:55421", // not an IP address
		"127.0.0.2:55421", "[::1]:55421", // loopback, but the console's Host allowlist is 127.0.0.1 and localhost
		"127.0.0.1", "127.0.0.1:0", "127.0.0.1:80", "127.0.0.1:99999",
	} {
		if err := checkQuickstartAddr(addr); err == nil {
			t.Errorf("%s was accepted", addr)
		}
		dir := filepath.Join(t.TempDir(), "qs")
		var out, errb bytes.Buffer
		if code := quickstartCmd([]string{"--dir", dir, "--addr", addr}, &out, &errb); code != 2 {
			t.Errorf("%s: exit %d, want 2", addr, code)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%s: the folder was created", addr)
		}
	}
	if err := checkQuickstartAddr("127.0.0.1:55421"); err != nil {
		t.Error(err)
	}
}

// A real GitHub App is not in this version: say so, point at the runbook, and touch nothing.
func TestQuickstartRealGitHubIsNotInThisVersion(t *testing.T) {
	for _, args := range [][]string{{"--playground=false"}, {"--github-app-id", "12345"}} {
		dir := filepath.Join(t.TempDir(), "qs")
		var out, errb bytes.Buffer
		if code := quickstartCmd(append([]string{"--dir", dir}, args...), &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(errb.String(), "not in this version") || !strings.Contains(errb.String(), "docs/runbooks/github-app-key.md") {
			t.Errorf("%v: %s", args, errb.String())
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%v: the folder was created", args)
		}
	}
}

func TestQuickstartRefusesFoldersItDidNotMake(t *testing.T) {
	// Not empty and no marker: a real install looks like this.
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "state.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkQuickstartDir(d); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a folder with a state.db and no marker: %v", err)
	}
	// A file.
	f := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(f, []byte("x"), 0o600)
	if _, _, err := checkQuickstartDir(f); err == nil {
		t.Error("a file was accepted")
	}
	// A marker of another kind, or a damaged one.
	for _, m := range []string{`{"kind":"other","version":1,"addr":"127.0.0.1:55421"}`, `{"kind":"chaperone-quickstart","version":2,"addr":"127.0.0.1:55421"}`, `nope`} {
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, quickstartMarker), []byte(m), 0o600)
		if _, _, err := checkQuickstartDir(d); err == nil {
			t.Errorf("marker %q accepted", m)
		}
	}
	// New and empty folders are fine.
	if _, st, err := checkQuickstartDir(filepath.Join(t.TempDir(), "new", "deeper")); err != nil || st != nil {
		t.Error(st, err)
	}
	if _, st, err := checkQuickstartDir(t.TempDir()); err != nil || st != nil {
		t.Error(st, err)
	}
}

// The real install's database folder is refused, and so is a folder above or below it.
func TestQuickstartRefusesTheRealInstallFolder(t *testing.T) {
	if !filepath.IsAbs(defaultDB) {
		t.Skip("the real install's default folder is a Windows path")
	}
	real := filepath.Dir(defaultDB)
	for _, d := range []string{real, filepath.Join(real, "scratch"), filepath.Dir(real)} {
		if _, _, err := checkQuickstartDir(d); err == nil || !strings.Contains(err.Error(), "real Chaperone install") {
			t.Errorf("%s: %v", d, err)
		}
	}
	var out, errb bytes.Buffer
	if code := quickstartCmd([]string{"--dir", real}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "real Chaperone install") {
		t.Errorf("exit %d: %s", code, errb.String())
	}
}

// A symlink is followed before the real-install comparison, and whatever the link is (a symlink, or a Windows junction,
// which Go's EvalSymlinks does not follow) the marker rule still refuses a folder that holds a state.db and no marker.
func TestQuickstartFollowsLinks(t *testing.T) {
	target := t.TempDir()
	_ = os.WriteFile(filepath.Join(target, "state.db"), []byte("x"), 0o600)
	link := filepath.Join(t.TempDir(), "link")
	symlink := true
	if err := os.Symlink(target, link); err != nil {
		symlink = false
		// Windows without the symlink privilege: a junction needs none.
		if runtime.GOOS != "windows" {
			t.Skipf("no symlinks here: %v", err)
		}
		if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); jerr != nil {
			t.Skipf("no symlinks or junctions here: %v %s", jerr, out)
		}
	}
	if _, _, err := checkQuickstartDir(link); err == nil {
		t.Error("a link to a folder holding a state.db and no marker was accepted")
	}
	if !symlink {
		return
	}
	got, _, err := checkQuickstartDir(filepath.Join(link, "new"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, filepath.Join(want, "new")) {
		t.Errorf("resolved to %s, want %s", got, filepath.Join(want, "new"))
	}
}

func TestQuickstartDefaultFolder(t *testing.T) {
	ok := func(s string) func() (string, error) { return func() (string, error) { return s, nil } }
	bad := func() (string, error) { return "", errors.New("unset") }
	cases := []struct {
		goos                string
		cache, config, home func() (string, error)
		want                string
		fail                bool
	}{
		{"windows", ok(`C:\Profiles\a\AppData\Local`), ok(`C:\Profiles\a\AppData\Roaming`), ok(`C:\Profiles\a`), filepath.Join(`C:\Profiles\a\AppData\Local`, "chaperone-quickstart"), false},
		{"darwin", ok("/Users/a/Library/Caches"), ok("/Users/a/Library/Application Support"), ok("/Users/a"), filepath.Join("/Users/a/Library/Application Support", "chaperone-quickstart"), false},
		{"linux", ok("/home/a/.cache"), ok("/home/a/.config"), ok("/home/a"), filepath.Join("/home/a/.config", "chaperone-quickstart"), false},
		{"linux", ok("/c"), bad, ok("/home/a"), filepath.Join("/home/a", ".chaperone-quickstart"), false},
		{"linux", bad, bad, bad, "", true},
	}
	for _, c := range cases {
		got, err := defaultQuickstartDir(c.goos, c.cache, c.config, c.home)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("%s: %q %v, want %q (fail %v)", c.goos, got, err, c.want, c.fail)
		}
	}
}

// ---- the playground cannot be turned on from `chapd run` or the service ----

func TestPlaygroundCannotBeEnabledFromRunOrService(t *testing.T) {
	for _, name := range []string{"chapd run", "chapd svc"} {
		flags := []string{"-playground", "--playground", "-playground=true", "-playground=false"}
		if name == "chapd svc" {
			// The -tags demo build gives its own dev flags to `chapd run` (and demo_flag_*_test.go pins that); never to the service.
			flags = append(flags, "-dev-fake-github", "-dev-enroll")
		}
		for _, flag := range flags {
			var errb bytes.Buffer
			args := []string{flag}
			if flag == "-dev-fake-github" {
				args = []string{flag, "x.json"}
			}
			if _, code := parseRunFlags(name, args, &errb, name == "chapd run"); code != 2 {
				t.Errorf("%s accepted %s (exit %d)", name, flag, code)
			}
		}
		var errb bytes.Buffer
		cfg, code := parseRunFlags(name, nil, &errb, name == "chapd run")
		if code != 0 || cfg.github != nil {
			t.Errorf("%s: exit %d, github client %v", name, code, cfg.github)
		}
	}
	// Through the top-level command too.
	for _, args := range [][]string{{"run", "--playground"}, {"svc", "--playground"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("chapd %v: exit %d", args, code)
		}
	}
}

// Config.github is the only way a GitHub client reaches chapd without the App key. Only quickstart.go (the
// playground) and demo.go (the -tags demo build) may set it; the shipped `run` and `svc` code paths never do.
func TestFakeGitHubIsOnlyWiredByQuickstartAndDemo(t *testing.T) {
	allowed := map[string]bool{"quickstart.go": true, "demo.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || allowed[name] {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "github" {
						t.Errorf("%s: sets .github (only quickstart.go and demo.go may)", fset.Position(s.Pos()))
					}
				}
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == "github" {
					// adapterDeps{github: c} in adapters.go hands Build's own client to the adapters; it is not a Config.
					if name != "adapters.go" {
						t.Errorf("%s: sets github: in a literal (only quickstart.go and demo.go may)", fset.Position(id.Pos()))
					}
				}
			}
			return true
		})
	}
}

// ---- state: a second run reuses the folder ----

func TestQuickstartSecondRunReusesState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qs")
	addr := qsFreeAddr(t)
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	r1 := startQuickstart(t, quickstartOptions{Dir: dir, Addr: addr})
	out1 := r1.ready()
	m1 := enrolRe.FindStringSubmatch(out1)
	if m1 == nil {
		t.Fatalf("no enrolment address in\n%s", out1)
	}
	if !strings.Contains(out1, "PLAYGROUND") {
		t.Errorf("the first run does not say PLAYGROUND:\n%s", out1)
	}
	keys, marker, tokenFile := read("run-keys.json"), read(quickstartMarker), read(quickstartTokenFile)
	if err := r1.stop(); err != nil {
		t.Fatal(err)
	}

	// Run two, same folder, no --addr: the folder's own address, the same files, the same token, a NEW first-passkey address.
	r2 := startQuickstart(t, quickstartOptions{Dir: dir})
	out2 := r2.ready()
	m2 := enrolRe.FindStringSubmatch(out2)
	if m2 == nil || m2[1] != m1[1] {
		t.Fatalf("second run: %v (first %v)\n%s", m2, m1, out2)
	}
	if m2[2] == m1[2] {
		t.Error("the second run printed the same one-time address")
	}
	for name, before := range map[string][]byte{"run-keys.json": keys, quickstartMarker: marker, quickstartTokenFile: tokenFile} {
		if !bytes.Equal(before, read(name)) {
			t.Errorf("%s was rewritten by the second run", name)
		}
	}
	if err := r2.stop(); err != nil {
		t.Fatal(err)
	}

	// Only the newest address is still alive.
	db, err := store.Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	var live int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM console_enrollments WHERE used_at IS NULL`).Scan(&live); err != nil || live != 1 {
		t.Fatalf("live enrolment addresses = %d (%v), want 1", live, err)
	}
	// Short-lived: it dies 15 minutes after it was made.
	var life int64
	if err := db.SQL().QueryRow(`SELECT expires_unix - strftime('%s', created_at) FROM console_enrollments WHERE used_at IS NULL`).Scan(&life); err != nil {
		t.Fatal(err)
	}
	if want := int64(quickstartEnrollTTL / time.Second); life < want-2 || life > want+2 {
		t.Errorf("address lifetime = %d s, want %d", life, want)
	}
	// An approver exists now.
	if _, err := db.SQL().Exec(`INSERT INTO approvers (user_handle, name, created_at) VALUES (randomblob(32), 'operator', '2026-11-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Run three: sign in instead. No enrolment address is printed or exists.
	r3 := startQuickstart(t, quickstartOptions{Dir: dir})
	deadline := time.Now().Add(60 * time.Second)
	var out3 string
	for time.Now().Before(deadline) {
		if out3 = r3.out.String(); strings.Contains(out3, "Extra: pull request 2") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(out3, "/enroll") || !strings.Contains(out3, "http://localhost:"+m1[1]+"/login") {
		t.Fatalf("with an approver the output must offer sign-in and no enrolment:\n%s", out3)
	}
	if err := r3.stop(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SQL().QueryRow(`SELECT count(*) FROM console_enrollments WHERE used_at IS NULL`).Scan(&live); err != nil || live != 0 {
		t.Fatalf("live enrolment addresses with an approver = %d (%v), want 0", live, err)
	}
}

// The folder's address cannot change: its passkey is bound to it.
func TestQuickstartKeepsItsAddress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qs")
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55431", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, st, err := checkQuickstartDir(dir)
	if err != nil || st == nil || st.Addr != "127.0.0.1:55431" {
		t.Fatal(st, err)
	}
	if _, err := prepareQuickstartFolder(dir, st, "127.0.0.1:55432", time.Now()); err == nil || !strings.Contains(err.Error(), "127.0.0.1:55431") {
		t.Errorf("a changed address was accepted: %v", err)
	}
	if f, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil || f.Addr != "127.0.0.1:55431" {
		t.Errorf("%v %v", f, err)
	}
	// An existing policy file is the user's and is kept.
	p := filepath.Join(dir, "policy", "playground.yaml")
	if err := os.WriteFile(p, []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "# mine\n" {
		t.Error("the policy file was overwritten")
	}
}

// ---- the token file: where it is written and who can read it ----

func qsApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "qs")
	f, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55433", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	app, err := Build(context.Background(), Config{DBPath: f.DB, KeysPath: f.Keys, PolicyDir: f.PolicyDir, Instance: quickstartInstance, Addr: f.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	return app, f.TokenFile
}

func TestQuickstartTokenFile(t *testing.T) {
	ctx := context.Background()
	app, path := qsApp(t)
	if err := ensureQuickstartToken(ctx, app, path, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(raw))
	p, err := app.Orch.Verify(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Scope.Projects, ",") != quickstartProject || strings.Join(p.Scope.Ops, ",") != strings.Join(quickstartOps, ",") || p.Scope.MintInterim {
		t.Errorf("scope %+v", p.Scope)
	}
	if life := p.ExpiresAt.Sub(time.Now()); life > quickstartTokenDays*24*time.Hour || life < (quickstartTokenDays-1)*24*time.Hour {
		t.Errorf("token life %v", life)
	}
	checkPrivateFile(t, path) // mode 0600 here, or one ACE for this user on Windows (quickstart_windows_test.go)

	// A live token with a day left is kept as it is.
	if err := ensureQuickstartToken(ctx, app, path, time.Now()); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, raw) {
		t.Error("a live token was replaced")
	}
	// Past the point where less than a day is left it is replaced, and the old one is revoked.
	if err := ensureQuickstartToken(ctx, app, path, time.Now().Add(quickstartTokenDays*24*time.Hour-time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if bytes.Equal(again, raw) {
		t.Error("a token with under a day left was kept")
	}
	var rerr *runtoken.Error
	if _, err := app.Orch.Verify(ctx, tok); !errors.As(err, &rerr) || rerr.Code != runtoken.CauseTokenRevoked {
		t.Errorf("the replaced token still verifies: %v", err)
	}
	checkPrivateFile(t, path)
	// A file that holds something else is replaced, never trusted.
	if err := os.WriteFile(path, []byte("not a token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureQuickstartToken(ctx, app, path, time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), runtoken.OrchPrefix) {
		t.Errorf("token file: %q", b)
	}
}

// The folder is private to the user on systems with modes; the files in it start at 0600.
func TestQuickstartFolderPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes do not apply; the token file's ACL is checked in quickstart_windows_test.go")
	}
	dir := filepath.Join(t.TempDir(), "qs")
	if err := os.MkdirAll(dir, 0o755); err != nil { // an existing folder with open permissions is closed again
		t.Fatal(err)
	}
	if _, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55434", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".", "policy", "logs", "run-keys.json", quickstartMarker, "policy/playground.yaml"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v", name, st.Mode().Perm())
		}
	}
}

// ---- the whole thing, over HTTP ----

func TestQuickstartServesLoopbackOnlyAndRefusesThenMakesACard(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qs")
	addr := qsFreeAddr(t)
	_, port, _ := net.SplitHostPort(addr)
	r := startQuickstart(t, quickstartOptions{Dir: dir, Addr: addr})
	out := r.ready()

	// The printed order: the passkey address, the Claude Code line, the three commands.
	iEnrol, iMCP, iCmd := strings.Index(out, "/enroll#"), strings.Index(out, "claude mcp add"), strings.Index(out, "chap pr view")
	if !(0 < iEnrol && iEnrol < iMCP && iMCP < iCmd) {
		t.Fatalf("wrong order (%d, %d, %d):\n%s", iEnrol, iMCP, iCmd, out)
	}
	m := enrolRe.FindStringSubmatch(out)
	if m == nil || m[1] != port {
		t.Fatalf("enrolment address: %v\n%s", m, out)
	}
	head := mergeRe.FindStringSubmatch(out)
	if head == nil {
		t.Fatalf("no merge command in\n%s", out)
	}

	call := func(method, url, host, auth string, body io.Reader) (int, string) {
		req, err := http.NewRequest(method, url, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// The enrolment page answers, to the right Host only.
	if code, body := call("GET", "http://"+addr+"/enroll", "localhost:"+port, "", nil); code != 200 || strings.Contains(body, m[2]) {
		t.Fatalf("enrol page: %d (token in page: %v)", code, strings.Contains(body, m[2]))
	}
	for _, host := range []string{"evil.example", "evil.example:" + port, "localhost:55398", "127.0.0.1"} {
		if code, _ := call("GET", "http://"+addr+"/enroll", host, "", nil); code != 403 {
			t.Errorf("Host %q: %d, want 403", host, code)
		}
	}
	// Not on any other address of this computer.
	if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), time.Second); err == nil {
				c.Close()
				t.Errorf("chapd answers on %s", ip)
			}
		}
	}

	// chap with the generated token: refused, then a card. Nothing runs.
	raw, err := os.ReadFile(filepath.Join(dir, quickstartTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(raw))
	merge := fmt.Sprintf(`{"op":"pr.merge","project":"playground","reason":"reword the checkout button","target":{"adapter":"github","ref":"playground/storefront#3"},"params":{"base":"main","head_sha":%q,"method":"squash"}}`, head[1])
	code, body := call("POST", "http://"+addr+"/v0/ops", "127.0.0.1:"+port, tok, strings.NewReader(merge))
	if code != 403 || !strings.Contains(body, "OP_APPROVAL_REQUIRED") {
		t.Fatalf("direct merge: %d %s", code, body)
	}
	card := strings.Replace(merge, `{"op"`, `{"kind":"op","op"`, 1)
	code, body = call("POST", "http://"+addr+"/v0/approvals", "127.0.0.1:"+port, tok, strings.NewReader(card))
	if code != 202 || !strings.Contains(body, "pending_approval") {
		t.Fatalf("request: %d %s", code, body)
	}
	// The red pull request is refused outright.
	redHead := regexp.MustCompile(`chap pr merge 2 --head ([0-9a-f]{40}) `).FindStringSubmatch(out)
	if redHead == nil {
		t.Fatalf("no command for pull request 2:\n%s", out)
	}
	red := fmt.Sprintf(`{"op":"pr.merge","project":"playground","reason":"x","target":{"adapter":"github","ref":"playground/storefront#2"},"params":{"base":"main","head_sha":%q,"method":"squash"}}`, redHead[1])
	if code, body = call("POST", "http://"+addr+"/v0/ops", "127.0.0.1:"+port, tok, strings.NewReader(red)); code != 403 || !strings.Contains(body, "CI_RED") {
		t.Fatalf("red merge: %d %s", code, body)
	}
	// Without a token nothing is served.
	if code, _ := call("POST", "http://"+addr+"/v0/ops", "127.0.0.1:"+port, "", strings.NewReader(merge)); code != 401 {
		t.Errorf("no token: %d", code)
	}
}

// ---- what it prints ----

func sampleInfo(goos string) quickstartInfo {
	return quickstartInfo{
		GOOS: goos, Dir: "/home/a/.config/chaperone-quickstart", LogDir: "/home/a/.config/chaperone-quickstart/logs",
		Addr: "127.0.0.1:55421", Origin: "http://localhost:55421", EnrollToken: "TOKEN123", Fresh: true, TTL: 15 * time.Minute,
		TokenFile: "/home/a/.config/chaperone-quickstart/orchestrator.token", Project: "playground", Repo: "playground/storefront", Base: "main",
		PRs: []fakePR{
			{Number: 1, Kind: "green", Head: strings.Repeat("1", 40)}, {Number: 2, Kind: "red", Head: strings.Repeat("2", 40)},
			{Number: 3, Kind: "medium", Head: strings.Repeat("3", 40)},
		},
		Chap: "/opt/chap/chap", ChapOnPath: true,
	}
}

func TestRenderQuickstart(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		i := sampleInfo(goos)
		out := renderQuickstart(i)
		a, b, c := strings.Index(out, "/enroll#TOKEN123"), strings.Index(out, "claude mcp add --scope user chaperone-playground"), strings.Index(out, "chap pr view 3")
		if !(0 < a && a < b && b < c) {
			t.Errorf("%s: order %d %d %d\n%s", goos, a, b, c, out)
		}
		if !strings.Contains(out, "for 15 minutes") {
			t.Errorf("%s: the address lifetime is not stated", goos)
		}
		for _, banned := range []string{"Edge", "Windows Hello", "Touch ID"} {
			if strings.Contains(out, banned) {
				t.Errorf("%s: output names %q", goos, banned)
			}
		}
		// Every line that names the fake GitHub says PLAYGROUND, or is a command whose repository is "playground/...".
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), "fake") && !strings.Contains(line, "PLAYGROUND") {
				t.Errorf("%s: %q names the fake without PLAYGROUND", goos, line)
			}
			if strings.Contains(line, "storefront") && !strings.Contains(line, "PLAYGROUND") && !strings.Contains(line, "playground/storefront") {
				t.Errorf("%s: %q names the repository without the playground label", goos, line)
			}
		}
		if !strings.Contains(out, "--head "+strings.Repeat("3", 40)+" --base main --repo playground/storefront --request --reason") {
			t.Errorf("%s: no request command", goos)
		}
		if goos == "windows" {
			if !strings.Contains(out, "$env:CHAP_URL = 'http://127.0.0.1:55421'") {
				t.Errorf("windows: %s", out)
			}
		} else if !strings.Contains(out, "export CHAP_URL='http://127.0.0.1:55421'") {
			t.Errorf("%s: %s", goos, out)
		}
	}
	// With an approver: sign-in, and no enrolment address at all.
	i := sampleInfo("linux")
	i.EnrollToken = ""
	out := renderQuickstart(i)
	if strings.Contains(out, "/enroll") || !strings.Contains(out, "http://localhost:55421/login") {
		t.Errorf("sign-in variant:\n%s", out)
	}
	// chap not found: say so; chap off PATH: add its folder to PATH for the terminal.
	i = sampleInfo("linux")
	i.Chap, i.ChapOnPath = "chap", false
	if !strings.Contains(renderQuickstart(i), "chap was not found") {
		t.Error("no note when chap is missing")
	}
	i = sampleInfo("linux")
	i.ChapOnPath = false
	if !strings.Contains(renderQuickstart(i), `export PATH='/opt/chap':"$PATH"`) {
		t.Error("no PATH line")
	}
}

func TestQuoteArg(t *testing.T) {
	cases := []struct{ goos, in, want string }{
		{"linux", "CHAP_URL=http://127.0.0.1:55421", "CHAP_URL=http://127.0.0.1:55421"},
		{"linux", "/home/a b/chap", `'/home/a b/chap'`},
		{"linux", "it's", `'it'\''s'`},
		{"linux", `a\b`, `'a\b'`},
		{"linux", "", "''"},
		{"windows", `C:\Profiles\a\chap.exe`, `C:\Profiles\a\chap.exe`},
		{"windows", `C:\Profiles\a b\chap.exe`, `'C:\Profiles\a b\chap.exe'`},
		{"windows", "it's", "'it''s'"},
		{"windows", "$x", "'$x'"},
	}
	for _, c := range cases {
		if got := quoteArg(c.goos, c.in); got != c.want {
			t.Errorf("quoteArg(%s, %q) = %s, want %s", c.goos, c.in, got, c.want)
		}
	}
}

// The embedded starter policy loads, and says what the playground needs.
func TestQuickstartPolicyLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qs")
	f, err := prepareQuickstartFolder(dir, nil, "127.0.0.1:55435", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	app, err := Build(context.Background(), Config{DBPath: f.DB, KeysPath: f.Keys, PolicyDir: f.PolicyDir, Instance: quickstartInstance, Addr: f.Addr})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	eff := app.Policy.For(quickstartProject)
	if eff.Invalid != nil {
		t.Fatal(eff.Invalid)
	}
	if eff.PR == nil || eff.PR.Repo != playgroundOwner+"/"+playgroundRepo || eff.PR.Base != playgroundBase {
		t.Errorf("pr block: %+v", eff.PR)
	}
}

// The lifetime of the first address is the one in the documentation.
func TestQuickstartEnrollLifetime(t *testing.T) {
	if quickstartEnrollTTL != 15*time.Minute {
		t.Errorf("the first address lives %v; docs/quickstart.md says 15 minutes", quickstartEnrollTTL)
	}
}
