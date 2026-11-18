package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
	"github.com/joshua-noel/chaperone/internal/policy"
)

func TestDeployFlagsAreAllOrNothing(t *testing.T) {
	var c deployConfig
	if c.enabled() {
		t.Fatal("no flags: deploy is off")
	}
	abs := func(p string) string { return filepath.Join(t.TempDir(), p) }
	full := deployConfig{Script: abs("pilot.sh"), GrantSecretID: "grant-key", HostTokenFile: abs("host.token"),
		LoadGateFile: abs("load-gate.json"), BackupFile: abs("last-valid-backup.json")}
	if !full.enabled() || full.validate() != nil {
		t.Fatalf("a full config: %v", full.validate())
	}
	// One flag alone turns deploy on and then fails loudly: a half-configured
	// deploy must not start quietly without its gate or its backup check.
	for name, mut := range map[string]func(*deployConfig){
		"no script":        func(c *deployConfig) { c.Script = "" },
		"no grant key":     func(c *deployConfig) { c.GrantSecretID = "" },
		"no host token":    func(c *deployConfig) { c.HostTokenFile = "" },
		"no load gate":     func(c *deployConfig) { c.LoadGateFile = "" },
		"no backup file":   func(c *deployConfig) { c.BackupFile = "" },
		"alerts half set":  func(c *deployConfig) { c.AlertsScript = abs("alerts.ps1") },
		"relative script":  func(c *deployConfig) { c.Script = "pilot.sh" },
		"relative backups": func(c *deployConfig) { c.BackupFile = "health/last-valid-backup.json" },
	} {
		c := full
		mut(&c)
		if !c.enabled() || c.validate() == nil {
			t.Errorf("%s: enabled=%v validate=%v", name, c.enabled(), c.validate())
		}
	}
	alone := deployConfig{LoadGateFile: abs("x")}
	if !alone.enabled() || alone.validate() == nil {
		t.Error("a single flag must turn deploy on and fail validation")
	}

	var parsed Config
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	parsed.Deploy.register(fs)
	if err := fs.Parse([]string{"-deploy-script", full.Script, "-grant-secret", "grant-key", "-host-token-file", full.HostTokenFile,
		"-load-gate-file", full.LoadGateFile, "-backup-file", full.BackupFile}); err != nil {
		t.Fatal(err)
	}
	if parsed.Deploy.validate() != nil {
		t.Errorf("flags: %v", parsed.Deploy.validate())
	}
}

func TestDeployPolicyOnlyForThePilotProject(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "policy"))
	if err != nil {
		t.Fatal(err)
	}
	cat, base, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	pol := deployPolicy(policy.NewEngine(cat, base, dir))
	p, ok := pol("storefront")
	if !ok || p.PR.Repo != "example-org/storefront" || p.PR.Base != "feat/d1-private-pilot" {
		t.Fatalf("storefront: %+v %v", p, ok)
	}
	// chaperone-sandbox has a pr: block (it may merge) but is not the pilot.
	for _, project := range []string{"chaperone-sandbox", "acme-shop", "", "Storefront-Mirror"} {
		if _, ok := pol(project); ok {
			t.Errorf("project %q must not deploy", project)
		}
	}
}

type seedVault struct{ secret string }

func (v seedVault) Use(_ context.Context, id string, fn func([]byte) error) error {
	if id != "grant-key" {
		return os.ErrNotExist
	}
	return fn([]byte(v.secret))
}

func TestHostKeygenAndVaultGrantSigner(t *testing.T) {
	dir := t.TempDir()
	seedFile, tokenFile := filepath.Join(dir, "grant.seed"), filepath.Join(dir, "host.token")
	var out, errb bytes.Buffer
	if code := hostCmd([]string{"keygen", "-seed-out", seedFile, "-token-out", tokenFile}, &out, &errb); code != 0 {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	seed, _ := os.ReadFile(seedFile)
	token, _ := os.ReadFile(tokenFile)
	if len(seed) != 43 || strings.ContainsAny(string(seed), "\r\n") {
		t.Fatalf("the seed file must hold exactly the seed text, got %d bytes", len(seed))
	}
	if strings.TrimSpace(string(token)) == "" || len(strings.TrimSpace(string(token))) < 40 {
		t.Errorf("host token %q", token)
	}
	if strings.Contains(out.String(), string(seed)) || strings.Contains(out.String(), strings.TrimSpace(string(token))) {
		t.Error("keygen must print the public key only, never the seed or the token")
	}
	var pub string
	for _, line := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "chapd_public_key: "); ok {
			pub = v
		}
	}
	pk, err := base64.RawURLEncoding.Strict().DecodeString(pub)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		t.Fatalf("public key %q: %v", pub, err)
	}

	// A signature made from the vault seed verifies under the printed key, as
	// chap-host verifies it.
	signer := vaultGrantSigner{v: seedVault{secret: string(seed)}, id: "grant-key"}
	now := time.Now()
	tok, err := signer.SignGrant(context.Background(), grant.Grant{
		Op: "deploy", OpHash: "sha256:" + strings.Repeat("a", 64), RunID: "r-7f3a", Runbook: "deploy",
		ScriptSHA256: "sha256:" + strings.Repeat("b", 64), Args: map[string]string{"sha": strings.Repeat("c", 40)},
		Nonce: strings.Repeat("n", 22), IssuedAt: now.Unix(), ExpiresAt: now.Add(4 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := grant.NewVerifier(ed25519.PublicKey(pk), grant.NewMemoryNonces())
	if g, err := v.Verify(tok); err != nil || g.Args["sha"] != strings.Repeat("c", 40) {
		t.Fatalf("verify: %v %+v", err, g)
	}

	// Never overwrites; a bad secret is not a key.
	if code := hostCmd([]string{"keygen", "-seed-out", seedFile, "-token-out", filepath.Join(dir, "other")}, &out, &errb); code == 0 {
		t.Error("keygen overwrote a seed")
	}
	if _, err := os.Stat(filepath.Join(dir, "other")); err == nil {
		t.Error("a failed keygen left a token behind")
	}
	if code := hostCmd([]string{"keygen", "-seed-out", filepath.Join(dir, "s2"), "-token-out", tokenFile}, &out, &errb); code == 0 {
		t.Error("keygen overwrote a token")
	}
	if _, err := os.Stat(filepath.Join(dir, "s2")); err == nil {
		t.Error("a failed keygen left a seed behind")
	}
	for _, bad := range []string{"", string(seed) + "\n", "not-a-seed", strings.Repeat("A", 44)} {
		if _, err := (vaultGrantSigner{v: seedVault{secret: bad}, id: "grant-key"}).SignGrant(context.Background(), grant.Grant{}); err == nil {
			t.Errorf("secret %q must not sign", bad)
		}
	}
}

func TestHealthAdapterIsInstalled(t *testing.T) {
	ads, err := adapters(adapterDeps{})
	if err != nil {
		t.Fatal(err)
	}
	if ads["health"] == nil {
		t.Error("health is read-only and needs nothing: it is always installed")
	}
	if ads["deploy"] != nil {
		t.Error("deploy is installed only by its flags")
	}
}
