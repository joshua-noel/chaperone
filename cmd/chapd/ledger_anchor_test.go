package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

type anchorPhone struct {
	mu  sync.Mutex
	got []notify.Anchor
}

func (p *anchorPhone) NotifyAnchor(_ context.Context, a notify.Anchor) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, a)
	return nil
}

// anchorApp builds a real chapd stack (real vault with the test key wrapper, real
// ledger) with the ledger key imported into the vault, and returns it with the
// seed's public key.
func anchorApp(t *testing.T) (*App, ed25519.PublicKey, string) {
	t.Helper()
	return anchorAppWith(t, nil)
}

func anchorAppWith(t *testing.T, tune func(*Config, string)) (*App, ed25519.PublicKey, string) {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if code, _, e := runVault(t, "init", "-db", db); code != 0 {
		t.Fatalf("vault init: exit %d: %s", code, e)
	}
	seedFile := filepath.Join(dir, "ledger.seed")
	var out, errb bytes.Buffer
	if code := ledgerCmd([]string{"keygen", "--seed-out", seedFile}, &out, &errb); code != 0 {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	if code, _, e := runVault(t, "import", "--name", "ledger-key", "--kind", "ed25519-seed", "--file", seedFile, "--delete", "-db", db); code != 0 {
		t.Fatalf("vault import: exit %d: %s", code, e)
	}
	farPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(map[string]any{"version": 1, "allow_interim": false, "keys": []any{
		map[string]any{"kid": "runner-1", "issuer": "runner.test", "public_key": base64.RawURLEncoding.EncodeToString(farPub)},
	}})
	keysPath := filepath.Join(dir, "run-keys.json")
	if err := os.WriteFile(keysPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	vdb, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vdb.Close() })
	v, err := vault.Open(ctx, vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "vault-keys"), DB: vdb, Wrapper: newWrapper()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	export := filepath.Join(dir, "ledger")
	cfg := Config{
		DBPath: db, KeysPath: keysPath, Instance: "test", ExportDir: export, testVault: v,
		Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	if tune != nil {
		tune(&cfg, dir)
	}
	app, err := Build(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	pubLine := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if p, ok := strings.CutPrefix(l, "ledger public key: "); ok {
			pubLine = p
		}
	}
	pub, err := ledger.ParsePublicKey(pubLine)
	if err != nil {
		t.Fatalf("keygen output: %v\n%s", err, out.String())
	}
	return app, pub, export
}

func TestLedgerKeygen(t *testing.T) {
	dir := t.TempDir()
	seedFile := filepath.Join(dir, "ledger.seed")
	var out, errb bytes.Buffer
	if code := ledgerCmd([]string{"keygen", "--seed-out", seedFile}, &out, &errb); code != 0 {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	seed, err := os.ReadFile(seedFile)
	if err != nil || len(seed) != base64.RawURLEncoding.EncodedLen(ed25519.SeedSize) {
		t.Fatalf("seed file: %q %v", seed, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(seed))
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)
	if !strings.Contains(out.String(), base64.RawURLEncoding.EncodeToString(pub)) || !strings.Contains(out.String(), ledger.KeyID(pub)) {
		t.Errorf("output does not show the public key: %s", out.String())
	}
	if strings.Contains(out.String(), string(seed)) {
		t.Errorf("the seed was printed")
	}
	// Never overwrites.
	out.Reset()
	errb.Reset()
	if code := ledgerCmd([]string{"keygen", "--seed-out", seedFile}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "never overwrites") {
		t.Errorf("second keygen: %d %s", code, errb.String())
	}
	if code := ledgerCmd(nil, &out, &errb); code != 2 {
		t.Errorf("no subcommand: %d", code)
	}
}

func TestSetupAnchorsRefusals(t *testing.T) {
	app, _, _ := anchorApp(t)
	ctx := context.Background()
	phone := &anchorPhone{}
	if s, err := app.setupAnchors(ctx, anchorConfig{}, phone); s != nil || err != nil {
		t.Fatalf("off: %v %v", s, err)
	}
	c := anchorConfig{KeySecretID: "ledger-key"}
	if _, err := app.setupAnchors(ctx, c, nil); err == nil || !strings.Contains(err.Error(), "phone") {
		t.Errorf("no phone: %v", err)
	}
	if _, err := app.setupAnchors(ctx, anchorConfig{KeySecretID: "nope"}, phone); err == nil {
		t.Error("a missing vault secret was accepted")
	}
	saved := app.cfg.ExportDir
	app.cfg.ExportDir = ""
	if _, err := app.setupAnchors(ctx, c, phone); err == nil || !strings.Contains(err.Error(), "-export-dir") {
		t.Errorf("no export dir: %v", err)
	}
	app.cfg.ExportDir = saved
	vsaved := app.vault
	app.vault = nil
	if _, err := app.setupAnchors(ctx, c, phone); err == nil || !strings.Contains(err.Error(), "vault") {
		t.Errorf("no vault: %v", err)
	}
	app.vault = vsaved
}

// The whole L1-21 path on the real stack: the ledger key from the vault signs,
// the record and the push agree, and `chap ledger verify --anchor`'s backend
// answers with the verdict and finds a record that does not belong.
func TestAnchorsOnTheRealStack(t *testing.T) {
	app, pub, export := anchorApp(t)
	ctx := context.Background()
	for i := range 4 {
		if err := app.ledgerOperatorOp(ctx, "approvers.enroll", "enrolled test credential "+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	phone := &anchorPhone{}
	set, err := app.setupAnchors(ctx, anchorConfig{KeySecretID: "ledger-key"}, phone)
	if err != nil || set == nil {
		t.Fatalf("setup: %v", err)
	}
	if !set.signer.Public().Equal(pub) {
		t.Fatal("the signer's key is not the key keygen made")
	}
	set.sched.RunOnce(ctx)
	if len(phone.got) != 1 {
		t.Fatalf("pushes = %d", len(phone.got))
	}

	be, ok := set.backend().(ops.AnchorVerifier)
	if !ok {
		t.Fatal("the anchored backend does not verify anchors")
	}
	v, err := be.VerifyAnchors(ctx, ops.AnchorVerifyRequest{AgainstExport: true})
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["ok"] != true || m["anchors_checked"] != 1 {
		t.Fatalf("verdict = %v", m)
	}
	newest := m["newest_anchor"].(map[string]any)
	if newest["head_hash"] != phone.got[0].HeadHash || newest["head_seq"] != phone.got[0].HeadSeq {
		t.Fatalf("newest anchor %v does not match the push %+v", newest, phone.got[0])
	}

	// The copy from the backup set verifies the same way, with the key typed in.
	data, err := os.ReadFile(ledger.AnchorsPath(export, app.Ledger.Chain()))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	v, err = be.VerifyAnchors(ctx, ops.AnchorVerifyRequest{Records: []string{line}, Keys: []string{base64.RawURLEncoding.EncodeToString(pub)}})
	if err != nil || v.(map[string]any)["ok"] != true {
		t.Fatalf("restored copy: %v %v", err, v)
	}

	// A record whose signature was edited is a problem, and the verdict is not ok.
	forged := strings.Replace(line, `"head_seq":7`, `"head_seq":6`, 1)
	if forged == line {
		t.Fatalf("test setup: no head_seq 7 in %s", line)
	}
	v, err = be.VerifyAnchors(ctx, ops.AnchorVerifyRequest{Records: []string{forged}})
	if err != nil {
		t.Fatal(err)
	}
	m = v.(map[string]any)
	if m["ok"] != false || !strings.Contains(strings.Join(m["problems"].([]string), "\n"), "ANCHOR_BAD_SIGNATURE") {
		t.Fatalf("forged record: %v", m)
	}
	for _, p := range m["problems"].([]string) {
		if len([]rune(p)) > maxProblemText {
			t.Errorf("problem too long for the contract: %d", len(p))
		}
	}

	// Malformed input is the caller's error, not a verdict.
	var in *ops.AnchorInputError
	if _, err := be.VerifyAnchors(ctx, ops.AnchorVerifyRequest{Records: []string{"not json"}}); !errors.As(err, &in) {
		t.Errorf("bad record: %v", err)
	}
	if _, err := be.VerifyAnchors(ctx, ops.AnchorVerifyRequest{Keys: []string{"short"}}); !errors.As(err, &in) {
		t.Errorf("bad key: %v", err)
	}

	// A scheduler that was started stops with its context and exports on the way out.
	runCtx, cancel := context.WithCancel(ctx)
	set.start(runCtx)
	cancel()
	set.wait()
}

// bothPhone is a stand-in for the ntfy driver: it takes wake-ups and anchors.
type bothPhone struct{ anchorPhone }

func (*bothPhone) Notify(context.Context, notify.Wake) error { return nil }

// The wiring in Build and Start: with -ledger-key-secret and a phone driver,
// chapd anchors by itself, and `POST /v0/ledger/verify` with anchor: true is
// answered by the anchored backend, over real HTTP with an orchestrator token.
func TestAnchorsAreWiredIntoChapd(t *testing.T) {
	phone := &bothPhone{}
	var tokenFile string
	srv := httptest.NewUnstartedServer(nil)
	app, _, export := anchorAppWith(t, func(c *Config, dir string) {
		c.Anchors = anchorConfig{KeySecretID: "ledger-key"}
		c.notifier = phone
		c.Hosts = []string{srv.Listener.Addr().String()}
		tokenFile = filepath.Join(dir, "home", "orchestrator.token")
		var out, errb bytes.Buffer
		if code := orchCmd([]string{"issue", "-db", c.DBPath, "-project", "acme-shop", "-ops", "health", "-token-file", tokenFile, "-days", "1"}, &out, &errb); code != 0 {
			t.Fatalf("orch issue: %d %s", code, errb.String())
		}
	})
	if app.anchors == nil {
		t.Fatal("Build did not set the anchors up")
	}
	srv.Config.Handler = app.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	if err := app.ledgerOperatorOp(ctx, "approvers.enroll", "enrolled test credential"); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); app.anchors.wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		phone.mu.Lock()
		n := len(phone.got)
		phone.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("chapd did not deliver an anchor to the phone by itself")
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v0/ledger/verify", strings.NewReader(`{"anchor":true,"against_export":true}`))
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v struct {
		OK             bool     `json:"ok"`
		Problems       []string `json:"problems"`
		AnchorsChecked int      `json:"anchors_checked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %d: %v", resp.StatusCode, err)
	}
	if !v.OK || v.AnchorsChecked < 1 {
		t.Fatalf("verdict %+v", v)
	}
	if _, err := os.Stat(ledger.AnchorsPath(export, app.Ledger.Chain())); err != nil {
		t.Fatalf("no records file: %v", err)
	}
}
