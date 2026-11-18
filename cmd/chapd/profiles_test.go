package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// goldenDigest is sha256(JCS(the spec's golden profile)).
const goldenDigest = "sha256:39581aa52a1ebd4d262dc34c0ad375c805af99d2ddd6b90d54c3fdf38e6a931f"

// runner is a test the runner: the private half of the key pinned in run-keys.json.
type runner struct {
	priv ed25519.PrivateKey
	keys string
}

func newRunner(t *testing.T, dir string) runner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"version": 1, "allow_interim": false, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.test", "public_key": base64.RawURLEncoding.EncodeToString(pub)},
	}}
	b, _ := json.Marshal(doc)
	path := filepath.Join(dir, "run-keys.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return runner{priv: priv, keys: path}
}

func (f runner) sign(t *testing.T, typ string, claims any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "runner-1", "typ": typ})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload)
	return in + "." + enc.EncodeToString(ed25519.Sign(f.priv, []byte(in)))
}

func (f runner) runToken(t *testing.T, digest string) (run, control string) {
	t.Helper()
	now := time.Now().Unix()
	c := spec.RunTokenClaims{
		Iss: "runner.test", Sub: "run:r-lf3a", Aud: "chaperone",
		Iat: now, Exp: now + 90*60,
		JTI: "n8Gf3kQ2xV7bTz1LwA9cYd", RunID: "r-lf3a", Project: "acme-shop",
		Profile:   spec.TokenProfile{Name: "code", Version: "1.0.0", Digest: digest},
		BriefSHA:  "sha256:7ed2358fdd424519b90502f453c9ab84266b75d6c17db83fdb89511dd61d67c1",
		Isolation: "gvisor",
		TaskScope: spec.TaskScope{Repo: "acme/shop", Base: "main", Branch: "agent/r-lf3a",
			Paths: []string{"services/sync/src/**"}, Ops: []string{"pr.open", "branch.push"}},
		Budget: spec.Budget{Minutes: 90, Tokens: 2000000},
	}
	ctl := map[string]any{"iss": "runner.test", "aud": "chaperone", "iat": now, "exp": now + 60,
		"jti": "ctl-" + digest[7:23], "act": "run.start", "run_id": "r-lf3a"}
	return f.sign(t, "factory-run+jwt", c), f.sign(t, "factory-ctl+jwt", ctl)
}

// goldenProfileFile writes the spec's golden generic profile to a file.
func goldenProfileFile(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile("../../internal/spec/specdata/vectors/v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RunTokens []struct {
			Profile json.RawMessage `json:"profile"`
		} `json:"run_tokens"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "code-1.0.0.json")
	if err := os.WriteFile(path, doc.RunTokens[0].Profile, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func registerRun(t *testing.T, cfg Config, digest string, f runner) (int, map[string]any) {
	t.Helper()
	app, err := Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	e := &e2e{t: t, app: app, srv: srv}
	run, control := f.runToken(t, digest)
	return e.call("POST", "/v0/runs", "", map[string]string{"control": control, "token": run})
}

// TestRunnerRunAdmittedWithProfileSource is LF-3 end to end: chapd with a
// -profiles-dir admits a runner.* token for a profile `chapd profile add` put
// there (201), and refuses an unknown digest, a tampered file and a chapd that
// has no profile source.
func TestRunnerRunAdmittedWithProfileSource(t *testing.T) {
	dir := t.TempDir()
	f := newRunner(t, dir)
	profiles := filepath.Join(dir, "profiles")
	file := goldenProfileFile(t, dir)

	var out, errb bytes.Buffer
	if code := profileCmd([]string{"digest", "-file", file}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != goldenDigest {
		t.Fatalf("profile digest: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := profileCmd([]string{"add", "-file", file, "-profiles-dir", profiles}, &out, &errb); code != 0 || !strings.Contains(out.String(), goldenDigest) {
		t.Fatalf("profile add: %d %q %q", code, out.String(), errb.String())
	}
	cfg := func(name, profilesDir string) Config {
		return Config{DBPath: filepath.Join(dir, name+".db"), KeysPath: f.keys, Instance: "test", ProfilesDir: profilesDir}
	}

	t.Run("known digest is admitted", func(t *testing.T) {
		st, body := registerRun(t, cfg("ok", profiles), goldenDigest, f)
		if st != 201 {
			t.Fatalf("status %d, want 201: %v", st, body)
		}
	})
	t.Run("unknown digest is refused", func(t *testing.T) {
		st, body := registerRun(t, cfg("unknown", profiles), "sha256:"+strings.Repeat("ab", 32), f)
		if st == 201 || !strings.Contains(toJSON(body), "TOKEN_INVALID") || !strings.Contains(toJSON(body), "is not admitted") {
			t.Fatalf("status %d: %v", st, body)
		}
	})
	t.Run("tampered profile file is refused", func(t *testing.T) {
		// A running chapd re-reads the file on every token: widen ops.allow after start.
		c := cfg("tamper", profiles)
		app, err := Build(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(app.Handler())
		t.Cleanup(func() { srv.Close(); app.Close() })
		path := filepath.Join(profiles, strings.TrimPrefix(goldenDigest, "sha256:")+".json")
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(path, orig, 0o600) })
		if err := os.WriteFile(path, bytes.Replace(orig, []byte(`"pr.open"`), []byte(`"deploy","pr.open"`), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		run, control := f.runToken(t, goldenDigest)
		e := &e2e{t: t, app: app, srv: srv}
		st, body := e.call("POST", "/v0/runs", "", map[string]string{"control": control, "token": run})
		if st == 201 || !strings.Contains(toJSON(body), "TOKEN_INVALID") || !strings.Contains(toJSON(body), "is not admitted") {
			t.Fatalf("status %d: %v", st, body)
		}
		// chapd does not start on that folder.
		if _, err := Build(context.Background(), cfg("tamper2", profiles)); err == nil || !strings.Contains(err.Error(), "tampered or misnamed") {
			t.Fatalf("Build on a tampered folder: %v", err)
		}
	})
	t.Run("no profile source says so", func(t *testing.T) {
		st, body := registerRun(t, cfg("none", ""), goldenDigest, f)
		if st == 201 || !strings.Contains(toJSON(body), "no profile source is configured") || !strings.Contains(toJSON(body), "-profiles-dir") {
			t.Fatalf("status %d: %v", st, body)
		}
	})
	t.Run("an explicit folder that is missing stops chapd", func(t *testing.T) {
		_, err := Build(context.Background(), cfg("missing", filepath.Join(dir, "nope")))
		if err == nil || !strings.Contains(err.Error(), "profile source") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestProfilesDirDefaultsNextToTheDatabase(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	cfg, code := parseRunFlags("chapd run", []string{"-db", db}, &bytes.Buffer{}, false)
	if code != 0 || cfg.ProfilesDir != "" {
		t.Fatalf("no folder: %d %q", code, cfg.ProfilesDir)
	}
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, code = parseRunFlags("chapd run", []string{"-db", db}, &bytes.Buffer{}, false)
	if code != 0 || cfg.ProfilesDir != filepath.Join(dir, "profiles") {
		t.Fatalf("with a folder: %d %q", code, cfg.ProfilesDir)
	}
	cfg, _ = parseRunFlags("chapd run", []string{"-db", db, "-profiles-dir", "x"}, &bytes.Buffer{}, false)
	if cfg.ProfilesDir != "x" {
		t.Fatalf("explicit folder: %q", cfg.ProfilesDir)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
