package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// TestDevTokenThroughTheRealRedactor runs `chap dev-token` (the real binary)
// against the real chapd stack: real vault registry as the redactor, real
// interim issuer signing from the vault. The minted token is a JWT, which the
// redactor matches; the mint answer is the one response allowed to carry it.
func TestDevTokenThroughTheRealRedactor(t *testing.T) {
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, e := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: exit %d: %s", code, e)
	}
	seed, interimPub, err := runtoken.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(dir, "interim.seed")
	if err := os.WriteFile(seedFile, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runVault(t, "import", "--name", "interim-key", "--kind", "interim-key", "--file", seedFile, "--delete", "-db", db); code != 0 {
		t.Fatalf("vault import: exit %d: %s", code, e)
	}
	farPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(map[string]any{"version": 1, "allow_interim": true, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.test", "public_key": base64.RawURLEncoding.EncodeToString(farPub)},
		map[string]any{"kid": "interim-1", "issuer": "chaperone.interim", "public_key": interimPub, "interim": map[string]any{"max_seconds": 7200, "ops": []string{"pr.open", "health"}}},
	}})
	keysPath := filepath.Join(dir, "run-keys.json")
	if err := os.WriteFile(keysPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	var out, errb bytes.Buffer
	if code := orchCmd([]string{"issue", "-db", db, "-project", "acme-shop", "-ops", "pr.open,health", "-mint-interim", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}

	ctx := context.Background()
	vdb, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer vdb.Close()
	v, err := vault.Open(ctx, vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: vdb, Wrapper: newWrapper()})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	var logs bytes.Buffer
	srv := httptest.NewUnstartedServer(nil)
	hosts := []string{srv.Listener.Addr().String()}
	app, err := Build(ctx, Config{
		DBPath: db, KeysPath: keysPath, Instance: "test", Hosts: hosts,
		InterimSecretID: "interim-key", InterimKID: "interim-1", testVault: v,
		Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = app.Handler()
	srv.Start()
	t.Cleanup(func() { srv.Close(); app.Close() })

	// The vault feeds the redactor, and the redactor matches the JWT shape.
	if _, res := app.Reg.Redact("eyJhbGciOiJFZERTQSJ9.eyJydW4iOiJyLTdmM2EifQ.c2ln"); !res.Blocked() {
		t.Fatal("the redactor is not live")
	}

	// Build the real chap and run it as an operator would.
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		gobin += ".exe"
	}
	chap := filepath.Join(dir, "chap")
	if runtime.GOOS == "windows" {
		chap += ".exe"
	}
	if b, err := exec.Command(gobin, "build", "-o", chap, "github.com/joshua-noel/chaperone/cmd/chap").CombinedOutput(); err != nil {
		t.Fatalf("go build chap: %v\n%s", err, b)
	}
	outFile := filepath.Join(dir, "run.token")
	cmd := exec.Command(chap, "dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "agent/r-9a2b",
		"--path", "docs/**", "--op", "pr.open", "--op", "health", "--minutes", "30", "--out", outFile)
	cmd.Env = append(os.Environ(), "CHAP_URL="+srv.URL, "CHAP_ORCHESTRATOR_TOKEN_FILE="+tokenFile, "CHAP_RUN_TOKEN=")
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		t.Fatalf("chap dev-token: %v\nstdout: %s\nstderr: %s", err, so.String(), se.String())
	}
	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if strings.Count(token, ".") != 2 || !strings.HasPrefix(token, "eyJ") {
		t.Fatalf("the token file does not hold a JWT: %q", token)
	}
	if !strings.Contains(so.String(), "token written to") {
		t.Errorf("stdout: %s", so.String())
	}

	// chap never prints it; chapd never logs it; the ledger and database never hold it.
	for name, text := range map[string]string{"chap stdout": so.String(), "chap stderr": se.String(), "chapd log": logs.String()} {
		if strings.Contains(text, token) || strings.Contains(text, token[:40]) {
			t.Errorf("the token is in %s:\n%s", name, text)
		}
	}
	rows, err := app.DB.SQL().Query(`SELECT event FROM ledger_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		n++
		if strings.Contains(s, token[:40]) {
			t.Errorf("the token is in the ledger: %s", s)
		}
	}
	if n == 0 {
		t.Error("the ledger has no events; the check above proves nothing")
	}
	for _, f := range []string{db, db + "-wal"} {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte(token[:40])) {
			t.Errorf("the token is in %s", f)
		}
	}

	// The token is real: it is a registered run that chapd accepts.
	cmd = exec.Command(chap, "health")
	cmd.Env = append(os.Environ(), "CHAP_URL="+srv.URL, "CHAP_RUN_TOKEN="+token)
	// Every op is disabled in the baseline, so the answer is a policy denial
	// that names the run: proof the token itself was accepted.
	if b, _ := cmd.CombinedOutput(); !strings.Contains(string(b), "profile host-interim, run r-") || strings.Contains(string(b), "TOKEN_") {
		t.Errorf("the minted token was not accepted as a registered interim run:\n%s", b)
	}
}
