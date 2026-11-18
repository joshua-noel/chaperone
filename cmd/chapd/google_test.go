package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// syncBuf is a bytes.Buffer safe for the browser goroutine to poll.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func useFakeGoogle(t *testing.T) *googletest.Server {
	t.Helper()
	f := googletest.New(t)
	old := connectEndpoints
	connectEndpoints = google.Endpoints{Auth: f.URL + "/auth", Token: f.URL + "/token", Revoke: f.URL + "/revoke", Gmail: f.URL, Drive: f.URL}
	t.Cleanup(func() { connectEndpoints = old })
	return f
}

func clientFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "client_secret_123.json")
	doc := `{"installed":{"client_id":"` + googletest.ClientID + `","client_secret":"` + googletest.ClientSecret + `","redirect_uris":["http://localhost"]}}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConnectGoogleSignInStatusRevoke(t *testing.T) {
	useTestWrapper(t)
	fake := useFakeGoogle(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, stderr := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	cf := clientFile(t, dir)

	// Before sign-in: status says so.
	var out, errb bytes.Buffer
	if code := run([]string{"connect", "google", "status", "-db", db}, &out, &errb); code != 1 || !strings.Contains(out.String(), "not connected") {
		t.Fatalf("status before: %d %q %q", code, out.String(), errb.String())
	}

	// Sign in: the command prints the address; the test plays the browser.
	var so syncBuf
	var se bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"connect", "google", "-db", db, "-client-file", cf, "-delete", "-drive", "-timeout", "20s"}, &so, &se)
	}()
	re := regexp.MustCompile(`http://\S+/auth\?\S+`)
	var authURL string
	for range 400 {
		if m := re.FindString(so.String()); m != "" {
			authURL = m
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if authURL == "" {
		t.Fatalf("no sign-in address printed: %q %q", so.String(), se.String())
	}
	if err := fake.Approve(authURL, nil); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != 0 {
		t.Fatalf("connect: %d %s %s", code, so.String(), se.String())
	}
	if !strings.Contains(so.String(), "connected as operator@example.com") || !strings.Contains(so.String(), "gmail.send") || !strings.Contains(so.String(), "drive") {
		t.Errorf("output: %s", so.String())
	}
	if strings.Contains(so.String()+se.String(), "ya29.") || strings.Contains(so.String()+se.String(), "1//0fake") || strings.Contains(so.String()+se.String(), googletest.ClientSecret) {
		t.Errorf("a secret reached the terminal: %s %s", so.String(), se.String())
	}
	if _, err := os.Stat(cf); !os.IsNotExist(err) {
		t.Errorf("-delete left the client file behind: %v", err)
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"connect", "google", "status", "-db", db}, &out, &errb); code != 0 || !strings.Contains(out.String(), "operator@example.com") || !strings.Contains(out.String(), "no fixed end") {
		t.Fatalf("status after: %d %q %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "ya29.") {
		t.Error("status prints a token")
	}

	out.Reset()
	if code := run([]string{"connect", "google", "revoke", "-db", db}, &out, &errb); code != 0 {
		t.Fatalf("revoke: %d %s", code, errb.String())
	}
	// The grant is gone at Google: status (no network) still reads the vault,
	// and the next refresh would find invalid_grant.
	fake.ExpireAccess()
}

func TestConnectGoogleRefusals(t *testing.T) {
	useTestWrapper(t)
	useFakeGoogle(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, stderr := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	for name, args := range map[string][]string{
		"not google":      {"connect", "github"},
		"no client":       {"connect", "google", "-db", db},
		"stray argument":  {"connect", "google", "-db", db, "extra"},
		"flags on status": {"connect", "google", "status", "-db", db, "-drive"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code == 0 {
			t.Errorf("%s: exit 0 (%s)", name, out.String())
		}
	}
	web := filepath.Join(dir, "web.json")
	_ = os.WriteFile(web, []byte(`{"web":{"client_id":"a","client_secret":"b"}}`), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"connect", "google", "-db", db, "-client-file", web}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "Desktop") {
		t.Errorf("a web client: %d %q", code, errb.String())
	}
	if _, err := os.Stat(web); err != nil {
		t.Error("a rejected client file must stay where it was")
	}
}

func TestInstallGoogleAddsAdaptersAndTurnsNothingOn(t *testing.T) {
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, stderr := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	ctx := context.Background()
	d, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v, err := vault.Open(ctx, vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: d, Wrapper: newWrapper()})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	cat, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	a := &App{vault: v, Reg: v.Registry(), Policy: policy.NewEngine(cat, base, ""), log: slog.Default()}
	ads := map[string]ops.Adapter{}
	if err := a.installGoogle(ads); err != nil {
		t.Fatal(err)
	}
	if ads["mail.send"] == nil || ads["drive.share"] == nil || a.googleMon == nil {
		t.Fatalf("adapters: %v monitor: %v", ads, a.googleMon)
	}
	eff := a.Policy.For("storefront")
	if eff.Enabled("mail.send") || eff.Enabled("drive.share") {
		t.Fatal("installing the adapters turned an op on")
	}
	// No vault: nothing is installed.
	none := map[string]ops.Adapter{}
	if err := (&App{}).installGoogle(none); err != nil || len(none) != 0 {
		t.Fatalf("%v %v", err, none)
	}
}

// The operator cannot run chapd as the vault's account once the installer has
// closed its sign-in: -out signs in with no vault, and the two files go in
// through the console's Secrets screen (here: `chapd vault import`, which is the
// same Import call). The client file is imported exactly as Google downloaded it.
func TestConnectGoogleOutFileThenImport(t *testing.T) {
	useTestWrapper(t)
	fake := useFakeGoogle(t)
	dir := t.TempDir()
	cf := clientFile(t, dir)
	out := filepath.Join(dir, "token.json")

	var so syncBuf
	var se bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"connect", "google", "-client-file", cf, "-out", out, "-timeout", "20s"}, &so, &se)
	}()
	re := regexp.MustCompile(`http://\S+/auth\?\S+`)
	var authURL string
	for range 400 {
		if m := re.FindString(so.String()); m != "" {
			authURL = m
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if authURL == "" {
		t.Fatalf("no sign-in address: %q %q", so.String(), se.String())
	}
	if err := fake.Approve(authURL, nil); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != 0 {
		t.Fatalf("connect -out: %d %s %s", code, so.String(), se.String())
	}
	if strings.Contains(so.String()+se.String(), "ya29.") || strings.Contains(so.String()+se.String(), "1//0fake") {
		t.Fatalf("a token reached the terminal: %s", so.String())
	}
	if !strings.Contains(so.String(), "google-token") || !strings.Contains(so.String(), "Secrets screen") {
		t.Errorf("the next step is not told: %s", so.String())
	}

	// A second run never overwrites the file.
	before, _ := os.ReadFile(out)
	var o2, e2 bytes.Buffer
	if code := run([]string{"connect", "google", "-client-file", cf, "-out", out, "-timeout", "1s"}, &o2, &e2); code == 0 {
		t.Fatal("-out overwrote an existing file")
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Fatal("the token file changed")
	}

	// Import both files as the Secrets screen does, then read them back.
	db := filepath.Join(dir, "state.db")
	if code, _, stderr := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: %d %s", code, stderr)
	}
	for _, imp := range [][]string{
		{"import", "-db", db, "--name", "google-token", "--file", out, "--kind", "google-oauth-token"},
		{"import", "-db", db, "--name", "google-client", "--file", cf, "--kind", "google-oauth-client"},
	} {
		if code, _, stderr := runVault(t, imp...); code != 0 {
			t.Fatalf("%v: %d %s", imp, code, stderr)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"connect", "google", "status", "-db", db}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "operator@example.com") {
		t.Fatalf("status after the import: %d %q %q", code, stdout.String(), stderr.String())
	}
}
