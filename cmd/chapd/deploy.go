package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// pilotProject is the one project whose pilot `deploy` may reach.
const pilotProject = "storefront"

// deployExecTimeout bounds one `deploy` execution: the runbook's own limit in
// chap-host (45 minutes) plus the wait for the pilot to come back.
const deployExecTimeout = 50 * time.Minute

// deployConfig is the host side of `deploy` (ticket L1-15). All of it is
// off until one flag is set; then every required flag must be set.
type deployConfig struct {
	Script        string // stable copy of scripts/pilot-host/pilot.sh: hashed into every grant
	GrantSecretID string // vault secret holding the grant-signing Ed25519 seed
	HostTokenFile string // chap-host's bearer token
	LoadGateFile  string // %LOCALAPPDATA%\Storefront\load-gate.json of the operator's profile
	BackupFile    string // D:\Storefront\health\last-valid-backup.json
	AlertsScript  string // optional: stable copy of alerts.ps1
	AlertsFolder  string // optional: the health folder alerts.ps1 writes to
	PowerShell    string // optional: Windows PowerShell 5.1; default under %SystemRoot%

	// health and host replace the pilot and chap-host in tests.
	health ops.HealthChecker
	host   ops.HostRunner
}

func (c *deployConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&c.Script, "deploy-script", "", "turns on `deploy`: absolute path of the stable copy of pilot.sh (its SHA-256 goes into every grant)")
	fs.StringVar(&c.GrantSecretID, "grant-secret", "", "vault secret id of the grant-signing Ed25519 seed (chapd host keygen)")
	fs.StringVar(&c.HostTokenFile, "host-token-file", "", "chap-host's bearer token file (chapd host keygen)")
	fs.StringVar(&c.LoadGateFile, "load-gate-file", "", "the server's load-gate.json (%LOCALAPPDATA%\\Storefront\\load-gate.json)")
	fs.StringVar(&c.BackupFile, "backup-file", "", `last-valid-backup.json (D:\Storefront\health\last-valid-backup.json)`)
	fs.StringVar(&c.AlertsScript, "alerts-script", "", "stable copy of alerts.ps1: a failed deploy raises an alert through it")
	fs.StringVar(&c.AlertsFolder, "alerts-folder", "", `the health folder alerts.ps1 writes to (D:\Storefront\health)`)
}

func (c deployConfig) enabled() bool {
	return c.Script != "" || c.GrantSecretID != "" || c.HostTokenFile != "" || c.LoadGateFile != "" || c.BackupFile != "" ||
		c.AlertsScript != "" || c.AlertsFolder != ""
}

func (c deployConfig) validate() error {
	var missing []string
	for _, f := range []struct{ flag, val string }{
		{"-deploy-script", c.Script}, {"-grant-secret", c.GrantSecretID}, {"-host-token-file", c.HostTokenFile},
		{"-load-gate-file", c.LoadGateFile}, {"-backup-file", c.BackupFile},
	} {
		if f.val == "" {
			missing = append(missing, f.flag)
		}
	}
	if len(missing) > 0 {
		return errors.New("chapd: deploy needs " + strings.Join(missing, ", ") + " as well")
	}
	if (c.AlertsScript == "") != (c.AlertsFolder == "") {
		return errors.New("chapd: -alerts-script and -alerts-folder go together")
	}
	for _, p := range []string{c.Script, c.HostTokenFile, c.LoadGateFile, c.BackupFile, c.AlertsScript, c.AlertsFolder} {
		if p != "" && !filepath.IsAbs(p) {
			return errors.New("chapd: deploy paths must be absolute: " + p)
		}
	}
	return nil
}

// deployPolicy lets only the pilot's project deploy, and only when its policy
// file has a `pr:` block (the repository, the base branch and the checks).
func deployPolicy(e *policy.Engine) ops.DeployPolicyFunc {
	pr := ops.PRPolicyFromEngine(e)
	return func(project string) (ops.DeployPolicy, bool) {
		if project != pilotProject {
			return ops.DeployPolicy{}, false
		}
		p, ok := pr(project)
		if !ok {
			return ops.DeployPolicy{}, false
		}
		return ops.DeployPolicy{PR: p}, true
	}
}

// vaultGrantSigner signs grants with a seed that exists only inside one
// vault.Use call.
type vaultGrantSigner struct {
	v  runtoken.SecretUser
	id string
}

func (s vaultGrantSigner) SignGrant(ctx context.Context, g grant.Grant) (string, error) {
	var token string
	err := s.v.Use(ctx, s.id, func(secret []byte) error {
		if len(secret) != base64.RawURLEncoding.EncodedLen(ed25519.SeedSize) {
			return errors.New("the grant key secret is not a base64url Ed25519 seed")
		}
		seed := make([]byte, ed25519.SeedSize)
		defer clear(seed)
		if n, err := base64.RawURLEncoding.Strict().Decode(seed, secret); err != nil || n != ed25519.SeedSize {
			return errors.New("the grant key secret is not a base64url Ed25519 seed")
		}
		key := ed25519.NewKeyFromSeed(seed)
		defer clear(key)
		var serr error
		token, serr = grant.Sign(key, g)
		return serr
	})
	return token, err
}

// deploy builds the `deploy` adapter and chap-host's routes, or returns nil for
// both when no deploy flag is set. An op with no adapter is refused
// (OP_DISABLED), whatever the baseline says.
func (a *App) deploy(deps adapterDeps) (ops.Adapter, http.Handler, error) {
	c := a.cfg.Deploy
	if !c.enabled() {
		return nil, nil, nil
	}
	if err := c.validate(); err != nil {
		return nil, nil, err
	}
	if deps.github == nil || a.vault == nil {
		return nil, nil, errors.New("chapd: deploy needs the GitHub App (-github-app-id) and the vault (-vault-dir)")
	}
	health := c.health
	if health == nil {
		h, err := ops.NewPilotHealth(ops.PilotHealthConfig{})
		if err != nil {
			return nil, nil, err
		}
		health = h
	}
	host := c.host
	var handler http.Handler
	if host == nil {
		bus, err := ops.NewHostBus(ops.HostBusConfig{
			Signer:    vaultGrantSigner{v: a.vault, id: c.GrantSecretID},
			Scripts:   map[string]string{ops.DeployRunbook: c.Script},
			TokenFile: c.HostTokenFile,
			Redact:    func(s string) string { m, _ := a.Reg.Redact(s); return m },
			Pending:   a.pendingCount,
		})
		if err != nil {
			return nil, nil, err
		}
		host, handler = bus, bus.Handler()
	}
	cfg := ops.DeployConfig{
		GitHub: deps.github, Tokens: deps.minter, Policy: deployPolicy(a.Policy),
		Facts: ops.HostFacts{
			GatePath: c.LoadGateFile, BackupPath: c.BackupFile,
			DumpSize: func(p string) (int64, error) {
				fi, err := os.Stat(p)
				if err != nil {
					return 0, err
				}
				return fi.Size(), nil
			},
		},
		Health: health, Host: host, Now: a.cfg.now,
	}
	if s := c.alertsScript(a.log); s != nil {
		cfg.Alert = s
	}
	d, err := ops.NewDeploy(cfg)
	if err != nil {
		return nil, nil, err
	}
	return d, handler, nil
}
