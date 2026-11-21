package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/linear"
	"github.com/joshua-noel/chaperone/internal/console"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gitproxy"
	keystore "github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/loopback"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
	"github.com/joshua-noel/chaperone/internal/version"
)

// Config is everything `chapd run` needs. Paths are on the server; nothing here is a
// secret.
type Config struct {
	DBPath    string
	PolicyDir string // policy/<project>.yaml; empty means baseline only
	KeysPath  string // pinned run-token key set (ADR-005)
	// ProfilesDir holds the generic profiles a runner.* token's profile.digest
	// may name (LF-3); empty means no profile source, so every non-interim
	// token is refused TOKEN_INVALID.
	ProfilesDir string
	Instance    string // ledger chain id is chaperone.<Instance>
	ExportDir   string // daily JSONL export root
	LogDir      string // when set, slog output also goes to a size-rotated chapd.log here (a service has no stderr)

	// Vault (optional). With it: secrets are redacted everywhere and the
	// interim issuer can sign. Without it neither exists.
	VaultDir        string
	VaultKeyDir     string
	VaultWrap       wrapperChoice // -vault-wrapper, -vault-passphrase-fd
	InterimSecretID string        // vault secret holding the interim issuer's Ed25519 seed
	InterimKID      string

	// GitHubAppID turns on the GitHub ops (pr.merge, pr.update): chapd signs the
	// App JWT with the key `chapd vault import` stored (needs the vault).
	GitHubAppID string

	// Deploy (L1-15) is off unless its flags are set; see deployConfig.
	Deploy deployConfig

	// NtfyTopicSecretID turns on the phone wake-up (ADR-004, L1-13): the vault
	// secret that holds the ntfy topic (import it with `chapd vault import`;
	// the topic is a password). NtfyURL is a self-hosted server; empty is ntfy.sh.
	NtfyTopicSecretID string
	NtfyURL           string
	// Google (L1-16): staged mail attachments.
	Google googleConfig
	// Linear: the operator-board intake's poll interval and budget.
	Linear linearConfig

	// PhoneHost turns on the phone passkey (ADR-004 section 5, L1-22): the server's
	// full tailnet name, e.g. server.tail1234.ts.net, which `tailscale serve` shows
	// at https://<name> in front of this listener. Empty: no phone. The console
	// then also answers on that Host and binds the phone's passkey to it.
	PhoneHost string

	// FrameAncestors are the origins that may show the console's framable pages in a frame and ask for a passkey there
	// (-console-frame-ancestor, repeatable; internal/console Config.FrameAncestors). Empty: nothing is framed.
	FrameAncestors []string

	// Authenticators is which kinds of authenticator may be enrolled and used to approve (-approver-authenticators):
	// "platform", the default, only one built into the device; "any" also a hardware security key and a phone through
	// the browser's cross-device prompt. An existing install keeps "platform" until its operator opts in (ADR-004 amendment 15).
	Authenticators console.Authenticators

	Addr  string   // loopback only
	Hosts []string // Host header allowlist; empty means 127.0.0.1:55398 and localhost:55398
	Log   *slog.Logger

	// testVault lets tests supply a vault opened with a fake key wrapper.
	testVault *vault.Vault
	// github, when set, replaces the App client built from GitHubAppID (tests
	// point it at a fake GitHub).
	github *gh.Client
	// notifier, when set, replaces the ntfy driver (tests point it at a fake).
	notifier notify.Notifier
	// linearEndpoints, when set, replaces Linear's production endpoints (tests
	// point it at a fake Linear).
	linearEndpoints *linear.Endpoints
	// sentryHTTP, when set, is the HTTP client of the Sentry connector (tests give
	// one that sends every request to a fake Sentry). chapd never sets it: the
	// connector still holds every base URL to the policy rule.
	sentryHTTP *http.Client
	// baselineYAML, when set, replaces the embedded baseline pack (tests turn
	// the intake ops on with it).
	baselineYAML []byte
	// Anchors turns on the ledger export schedule and the anchors (L1-21).
	Anchors anchorConfig
	// approvalVerifier, when set, replaces the console as the engine's
	// assertion verifier: a Windows Hello stand-in for the end-to-end test.
	approvalVerifier approvals.Verifier
	now              func() time.Time
	// afterBuild, when set, runs once chapd is built and started (the demo
	// build's -dev-enroll prints an enrolment address).
	afterBuild func(context.Context, *App) error
	// onListening, when set, is called once the console port is held, before Start (the Windows service reports that it
	// is running then, not before).
	onListening func()
}

// App is a built chapd: the database, the ledger, the services and the handler.
type App struct {
	cfg        Config
	log        *slog.Logger
	DB         *store.DB
	Ledger     *ledger.Ledger
	Policy     *policy.Engine
	Ops        *ops.Service
	Runs       *runtoken.Runs
	Orch       *runtoken.Orchestrators
	Keys       *keystore.Store
	KeyDecider *keystore.Decider
	Console    *console.Console
	// Approvals is the approvals engine (L1-12); bridge connects it to Ops.
	Approvals *approvals.Engine
	bridge    *approvalsBridge
	notifier  *notify.Service
	// googleMon refreshes the Google token on a timer so a revoked sign-in is alerted (L1-16).
	googleMon *google.Monitor
	// linearBoard caches the operator board and runs its poller;
	// nil without a vault.
	linearBoard *linear.Board
	// phone is the ntfy driver the notifier wraps; the anchors use it too.
	phone   notify.Notifier
	anchors *anchorSet // L1-21; nil when -ledger-key-secret is not set
	// git is the git proxy; nil without a GitHub App. Its tokens are revoked
	// when a run ends (AfterEnd below) and when chapd closes.
	git     *gitproxy.Handler
	Reg     *redact.Registry
	vault   *vault.Vault
	handler http.Handler

	auditCh   chan console.Event
	auditDone chan struct{}
	closeOnce sync.Once
}

// Build opens everything and wires it. It fails closed: a missing key set, a
// ledger that does not verify its head, or an unreadable policy stops chapd.
func Build(ctx context.Context, cfg Config) (*App, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Instance == "" {
		cfg.Instance = "pc"
	}
	if cfg.KeysPath == "" {
		return nil, errors.New("chapd: -keys is required (the pinned run-token key set, ADR-005)")
	}
	a := &App{cfg: cfg, log: cfg.Log}
	ok := false
	defer func() {
		if !ok {
			a.Close()
		}
	}()

	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a.DB = db
	ms, err := store.Migrations()
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, ms); err != nil {
		return nil, err
	}

	a.Reg = redact.NewRegistry()
	switch {
	case cfg.testVault != nil:
		a.vault = cfg.testVault
	case cfg.VaultDir != "":
		wrapper, err := cfg.VaultWrap.build()
		if err != nil {
			return nil, fmt.Errorf("chapd: the vault key wrapper: %w", err)
		}
		v, err := vault.Open(ctx, vault.Config{Dir: cfg.VaultDir, KeyDir: cfg.VaultKeyDir, DB: db, Wrapper: wrapper, Registry: a.Reg})
		if err != nil {
			return nil, fmt.Errorf("chapd: open the vault: %w", err)
		}
		a.vault = v
	}
	if a.vault != nil {
		a.Reg = a.vault.Registry()
		if err := a.vault.LoadRegistry(ctx); err != nil {
			return nil, fmt.Errorf("chapd: load the redaction registry: %w", err)
		}
	}

	led, err := ledger.Open(ctx, db, ledger.Config{
		Instance: cfg.Instance, Version: version.Version, ExportDir: cfg.ExportDir, Redactor: a.Reg, Clock: cfg.now,
	})
	if err != nil {
		return nil, fmt.Errorf("chapd: open the ledger: %w", err)
	}
	a.Ledger = led
	sink := ledgerSink{l: led}

	cat, base, err := policy.Default()
	if err == nil && cfg.baselineYAML != nil {
		base, err = policy.LoadBaseline(cfg.baselineYAML, cat)
	}
	if err != nil {
		return nil, err
	}
	a.Policy = policy.NewEngine(cat, base, cfg.PolicyDir)
	for _, p := range a.Policy.Problems() {
		if p.Block == "" {
			a.log.Warn("policy: a project file is invalid, so every op of the project is refused until it is fixed", "project", p.Project, "file", p.File, "err", p.Err.Error())
		} else if p.Block == "sentry" {
			a.log.Warn("policy: a project file has an unusable sentry block; the Sentry operations (errors.*) are off for the project, its other ops work", "project", p.Project, "file", p.File, "err", p.Err.Error())
		} else if p.Block == "linear.issues" {
			a.log.Warn("policy: a project file has an unusable linear.issues block; the Linear issue operations (and Linear's issue.comment) are off for the project, the intake and its other ops work", "project", p.Project, "file", p.File, "err", p.Err.Error())
		} else {
			a.log.Warn("policy: a project file has an unusable "+p.Block+" block; pr.merge and pr.update are off for the project, its other ops work", "project", p.Project, "file", p.File, "err", p.Err.Error())
		}
	}

	ghc, err := a.githubClient()
	if err != nil {
		return nil, err
	}
	// The console is built first: the approvals engine's verifier is the
	// console (a decision needs a fresh Windows Hello assertion), and the engine
	// is built before the ops service, which asks it for cards.
	a.auditCh = make(chan console.Event, 64)
	a.auditDone = make(chan struct{})
	localOrigin, hosts := localEndpoints(cfg.Addr, cfg.Hosts)
	origins := []console.Origin{localOrigin}
	if cfg.PhoneHost != "" {
		po, err := console.NewPhoneOrigin(cfg.PhoneHost)
		if err != nil {
			return nil, fmt.Errorf("chapd: -phone-host: %w", err)
		}
		origins = append(origins, po)
	}
	con, err := console.New(console.Config{
		DB: db, Origins: origins, Log: a.log, Now: cfg.now, FrameAncestors: cfg.FrameAncestors, Authenticators: cfg.Authenticators,
		OnEvent: func(e console.Event) {
			select {
			case a.auditCh <- e:
			default: // the console never blocks; a full queue is logged by the worker's drops counter
				a.log.Warn("console audit queue full; event not ledgered", "event", e.Name)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	a.Console = con
	if cfg.Authenticators == console.AuthenticatorsAny {
		a.log.Warn("approver authenticators: any. A hardware security key or a phone passkey may be enrolled and may approve, as well as one built into the device (ADR-004 amendment 15)")
	}
	// A setting that refuses enrolled passkeys (narrowed from "any", or a built-in passkey whose browser did not
	// report its kind under "any") is said at start. A full lockout is logged as an error, with the way out. It does
	// not stop chapd: that would turn a setting mistake into an outage for the agents doing routine work, and the
	// routine ops that need no approval go on without the console; the operator is locked out of approving either way, and the fix is
	// the same flag.
	if refused, usable, err := con.RefusedCredentials(ctx); err != nil {
		return nil, err
	} else if refused > 0 && usable == 0 {
		a.log.Error("nobody can sign in or approve: every enrolled passkey is refused by the authenticators setting. Start chapd again with -approver-authenticators any (chapd enroll cannot add one while an approver exists)", "refused", refused)
	} else if refused > 0 {
		a.log.Warn("some enrolled passkeys are refused by the authenticators setting and cannot sign in or approve: a security key or phone passkey made while it was any, or a built-in passkey whose browser did not report its kind. Start chapd with -approver-authenticators any to allow them again", "refused", refused, "usable", usable)
	}

	ntf, err := a.buildNotifier(ctx)
	if err != nil {
		return nil, err
	}
	var notifier notify.Notifier // an interface holding a nil *notify.Service would not be nil
	if ntf != nil {
		a.notifier, notifier = ntf, ntf
	}
	bridge := &approvalsBridge{db: db, log: a.log}
	alerts := &alerter{log: a.log, script: cfg.Deploy.alertsScript(a.log)}
	var hello approvals.Verifier = con // a decision rests on a fresh Windows Hello assertion, checked by the console
	if cfg.approvalVerifier != nil {
		hello = cfg.approvalVerifier
	}
	eng, err := approvals.New(approvals.Config{
		DB: db, Ledger: approvalsLedger{l: led}, Catalog: policyCatalog{c: cat}, Verifier: hello, Notifier: notifier,
		// No PolicyVersion: policy versions are per project (the digest of the
		// project file), so ops compares each op's version at release instead.
		OnDecided: bridge.onDecided, AfterApproved: bridge.afterApproved, PhoneOrigins: con.PhoneOrigins(),
		Stop: stopRaiser(led, idMaker("s-")), Alert: alerts.engineAlert, Log: a.log, Now: cfg.now,
	})
	if err != nil {
		return nil, err
	}
	bridge.eng = eng
	a.Approvals, a.bridge = eng, bridge

	// ADR-008: custom keys. The store needs the ops service only to cancel a revoked key's waiting ops,
	// and the service needs the keys.issue adapter, so the service is reached through a variable.
	var svcRef *ops.Service
	keyStore, err := keystore.New(keystore.Config{
		DB: db, Ledger: sink, Redact: a.Reg, Now: cfg.now, PolicyVersion: base.BaselineVersion,
		Catalog: a.Policy.Catalog(), Log: a.log,
		// Agents may be enrolled only for a project whose policy turns keys.request on; a looping agent is logged.
		EnrolProject: func(project string) bool { return a.Policy.For(project).Enabled(keystore.OpRequest) },
		OnLooping: func(_ context.Context, l keystore.Looping) {
			a.log.Warn("a looping agent: its key requests were refused again and again", "agent", l.Holder, "owner", l.Owner, "key", l.KeyID, "refusals", l.Refusals)
		},
		TxRevoke: func(ctx context.Context, tx *store.Tx, id string) error { return svcRef.CancelKeyOps(ctx, tx, id) },
	})
	if err != nil {
		return nil, err
	}
	a.Keys = keyStore

	deps := newAdapterDeps(ghc, a.Policy)
	deps.ciRun = ciRunLookup(func() *runtoken.Runs { return a.Runs })
	ads, err := adapters(deps)
	if err != nil {
		return nil, err
	}
	// ADR-008: the grant op. It is on only when a policy PR turns keys.issue on.
	approvalOf := func(ctx context.Context, requestID string) (string, string, error) {
		ap, err := eng.GetByRequest(ctx, requestID)
		if err != nil {
			return "", "", err
		}
		if ap == nil || ap.Approver == "" {
			return "", "", fmt.Errorf("chapd: no signed approval for %s", requestID)
		}
		return ap.ID, ap.Approver, nil
	}
	issue, err := keystore.NewIssueAdapter(keystore.IssueConfig{
		Store: keyStore, Catalog: a.Policy.Catalog(),
		Enabled: func(project, op string) bool { return a.Policy.For(project).Enabled(op) },
		Project: func(name string) (ops.PRProject, bool) {
			eff := a.Policy.For(name)
			if eff.Invalid != nil || eff.PR == nil {
				return ops.PRProject{}, false
			}
			return ops.PRProject{Repo: eff.PR.Repo, Base: eff.PR.Base}, true
		},
		Approval: approvalOf,
	})
	if err != nil {
		return nil, err
	}
	ads[keystore.OpIssue] = issue
	// ADR-008, tracer 2: an agent asks for a key (keys.request, routine), and its owner makes a key last longer
	// (keys.extend, a card). Both are on only when a policy PR turns them on.
	request, err := keystore.NewRequestAdapter(keystore.RequestConfig{
		Store: keyStore, Catalog: a.Policy.Catalog(),
		Enabled: func(project, op string) bool { return a.Policy.For(project).Enabled(op) },
		Project: func(name string) (ops.PRProject, bool) {
			eff := a.Policy.For(name)
			if eff.Invalid != nil || eff.PR == nil {
				return ops.PRProject{}, false
			}
			return ops.PRProject{Repo: eff.PR.Repo, Base: eff.PR.Base}, true
		},
	})
	if err != nil {
		return nil, err
	}
	ads[keystore.OpRequest] = request
	extend, err := keystore.NewExtendAdapter(keyStore, approvalOf)
	if err != nil {
		return nil, err
	}
	ads[keystore.OpExtend] = extend
	// L1-16: mail.send and drive.share adapters; both ops stay off in the baseline.
	if err := a.installGoogle(ads); err != nil {
		return nil, err
	}
	// the operator-board intake ops; on in the baseline, refused for a project with no `linear:` block.
	if err := a.installLinear(ads); err != nil {
		return nil, err
	}
	// the six Sentry errors.* ops; off in the baseline, refused for a project with no valid `sentry:` block.
	if err := a.installSentry(ads); err != nil {
		return nil, err
	}
	// L1-15: `deploy` and chap-host's routes, only when its flags are set.
	deployAd, hostRoutes, err := a.deploy(deps)
	if err != nil {
		return nil, err
	}
	execTimeout := time.Duration(0) // the service default
	if deployAd != nil {
		ads["deploy"] = deployAd
		execTimeout = deployExecTimeout
	}
	svc, err := ops.NewService(ops.Config{
		DB: db, Ledger: sink, Policy: a.Policy, Adapters: ads, Redactor: a.Reg, Log: a.log, Now: cfg.now,
		Approvals: bridge, Alerter: alerts, ExecTimeout: execTimeout,
		// ADR-008: an approved op of a key is released only while the key lives (checked in the release transaction).
		KeyLive: func(ctx context.Context, tx *store.Tx, id string) error { return keyStore.Live(ctx, tx, id) },
	})
	if err != nil {
		return nil, err
	}
	a.Ops = svc
	svcRef = svc
	bridge.svc = svc
	a.KeyDecider = keystore.NewDecider(keyStore, svc)

	keys, err := runtoken.LoadKeySet(cfg.KeysPath)
	if err != nil {
		return nil, fmt.Errorf("chapd: load the key set: %w", err)
	}
	var profiles runtoken.ProfileFunc // nil without -profiles-dir: Verify says so
	if cfg.ProfilesDir != "" {
		pd, n, err := runtoken.OpenProfileDir(cfg.ProfilesDir, a.log)
		if err != nil {
			return nil, fmt.Errorf("chapd: profile source: %w", err)
		}
		profiles = pd.Lookup
		a.log.Info("profile source", "dir", cfg.ProfilesDir, "profiles", n)
	} else {
		a.log.Warn("no profile source (-profiles-dir): every runner.* run token will be refused TOKEN_INVALID")
	}
	orchTxRevoke, orchTxReissue := orchestratorHooks(svc, keyStore)
	orch, err := runtoken.NewOrchestrators(runtoken.OrchConfig{
		DB: db, Appender: sink, Redact: a.Reg, Now: cfg.now,
		PolicyVersion: base.BaselineVersion,
		TxRevoke:      orchTxRevoke, TxReissue: orchTxReissue,
	})
	if err != nil {
		return nil, err
	}
	a.Orch = orch
	if deps.github != nil {
		a.git = &gitproxy.Handler{Gate: svc, Tokens: deps.minter, Revoker: deps.github, Log: a.log}
	}
	runs, err := runtoken.NewRuns(runtoken.RunsConfig{
		DB: db, Keys: keys, Profiles: profiles, Appender: sink, Now: cfg.now,
		TxEnd: func(ctx context.Context, tx *store.Tx, run runtoken.RunRecord, info runtoken.EndInfo) error {
			return svc.CancelRunOps(ctx, tx, run.RunID, "run ended")
		},
		// Every way a run ends (the runner's end call, an operator revoke, the
		// reaper) comes through here, after the end committed (ADR-005 "End").
		AfterEnd: func(_ context.Context, run runtoken.RunRecord, _ runtoken.EndInfo) {
			if a.git != nil {
				a.git.EndRun(run.RunID)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	a.Runs = runs
	verifier, err := runtoken.NewVerifier(runtoken.VerifierConfig{DB: db, Keys: keys, Profiles: profiles, Now: cfg.now})
	if err != nil {
		return nil, err
	}

	scfg := ops.ServerConfig{
		Svc: svc, Version: version.Version,
		Auth: &ops.Auth{
			Run:  runVerifier{v: verifier, stop: raiseTokenMisuse(led, idMaker("s-"), a.log)},
			Orch: orchVerifier{o: orch},
			Key:  keyStore,
			Svc:  svc,
		},
		AllowInterim: keys.AllowInterim, Hosts: hosts,
		Runs:   runsBackend{r: runs},
		Keys:   keystore.NewAdmin(keyStore),
		Agents: keystore.NewEnrolment(keyStore),
		Ledger: ledgerBackend{l: led},
	}
	scfg.ApproverCredentials = func(ctx context.Context) (int, error) {
		var n int
		err := db.SQL().QueryRowContext(ctx, `SELECT count(*) FROM credentials WHERE revoked_at IS NULL`).Scan(&n)
		return n, err
	}
	if a.vault != nil {
		scfg.Vault = vaultBackend{v: a.vault}
		if cfg.InterimSecretID != "" {
			signer := runtoken.NewVaultSigner(a.vault, cfg.InterimSecretID, cfg.InterimKID)
			interim, err := runtoken.NewInterim(runtoken.InterimConfig{Runs: runs, Orch: orch, Signer: signer})
			if err != nil {
				return nil, fmt.Errorf("chapd: interim issuer: %w", err)
			}
			scfg.Interim = interimBackend{i: interim}
		}
	}
	if a.git != nil {
		scfg.Git = a.git
	}
	scfg.Host = hostRoutes
	// L1-21: the export schedule and the anchors. The phone leg needs the ntfy
	// driver itself (an anchor push is not an approval wake-up).
	var anchorPhone notify.AnchorNotifier // stays a nil interface without a topic
	if p, ok := a.phone.(notify.AnchorNotifier); ok {
		anchorPhone = p
	}
	if a.anchors, err = a.setupAnchors(ctx, cfg.Anchors, anchorPhone); err != nil {
		return nil, err
	}
	if a.anchors != nil {
		scfg.Ledger = a.anchors.backend()
	}
	api := ops.NewServer(scfg)

	// Order matters: the Approvals screen first, then the
	// screens that sit on it. UseApprovals turns on /approvals; UseScreens needs it.
	if err := con.UseApprovals(eng, console.ApprovalsOptions{ResolveToken: tokenHolder(verifier, orch, keyStore), Recheck: func(ctx context.Context, requestID string) (console.StaleCheck, error) {
		r, err := svc.Recheck(ctx, requestID)
		return console.StaleCheck{Stale: r.Stale, Why: r.Why, NewCard: r.NewCard}, err
	}}); err != nil {
		return nil, err
	}
	screens := console.ScreensConfig{
		Version: version.Version, Runs: runs, Orch: orch, Ledger: led, Policy: a.Policy,
		Record: approvalsLedger{l: led},
		Keys:   a.KeyDecider,
	}
	if a.vault != nil { // an interface holding a nil *vault.Vault would not be nil
		screens.Vault = a.vault
	}
	if err := con.UseScreens(screens); err != nil {
		return nil, err
	}
	if cfg.PhoneHost != "" {
		if err := con.UsePhone(console.PhoneConfig{Record: approvalsLedger{l: led}, PolicyVersion: a.Policy.Baseline().BaselineVersion}); err != nil {
			return nil, err
		}
	}
	go a.auditWorker(ctx)

	// One port, two Hosts: agents call 127.0.0.1:55398/v0 and /git, the operator
	// uses http://localhost:55398 (WebAuthn RP ID "localhost"). Paths split them;
	// each handler checks its own Host.
	mux := http.NewServeMux()
	mux.Handle("/v0/", api)
	mux.Handle("/git/", api)
	mux.Handle("/", con.Handler())
	a.handler = mux
	ok = true
	return a, nil
}

// githubClient returns the GitHub App client, or nil when none is configured.
func (a *App) githubClient() (*gh.Client, error) {
	if a.cfg.github != nil {
		return a.cfg.github, nil
	}
	if a.cfg.GitHubAppID == "" {
		return nil, nil
	}
	if a.vault == nil {
		return nil, errors.New("chapd: -github-app-id needs the vault (-vault-dir): the App key is read from it")
	}
	keys, err := gh.NewVaultKey(a.vault, "")
	if err != nil {
		return nil, err
	}
	c, err := gh.New(gh.Config{AppID: a.cfg.GitHubAppID, Keys: keys})
	if err != nil {
		return nil, fmt.Errorf("chapd: GitHub client: %w", err)
	}
	return c, nil
}

// Handler is the whole HTTP surface.
func (a *App) Handler() http.Handler { return a.handler }

// Start runs chapd's background work until ctx ends: crash recovery first (an op
// found executing becomes unconfirmed, an overdue run is reaped), then the
// expiry sweep and the reaper on timers.
func (a *App) Start(ctx context.Context) error {
	if n, err := a.Ops.Recover(ctx); err != nil {
		return fmt.Errorf("chapd: recover ops: %w", err)
	} else if n > 0 {
		a.log.Warn("ops found executing at start are now unconfirmed", "count", n)
	}
	if n, err := a.Runs.Reap(ctx); err != nil {
		return fmt.Errorf("chapd: reap runs: %w", err)
	} else if n > 0 {
		a.log.Info("runs past their exp ended at start", "count", n)
	}
	// Approvals: expire what ran out while chapd was down (each expiry moves its
	// op in the same commit), release the ops that were approved but not yet
	// released, then sweep on a timer. A release re-checks the approval, so a
	// stale one is refused and never run.
	if n, err := a.Approvals.Sweep(ctx); err != nil {
		return fmt.Errorf("chapd: sweep approvals: %w", err)
	} else if n > 0 {
		a.log.Info("approvals past their expiry at start are now expired", "count", n)
	}
	if err := a.bridge.releaseAllowed(ctx); err != nil {
		return fmt.Errorf("chapd: release approved ops: %w", err)
	}
	go a.Approvals.Run(ctx, 30*time.Second)
	if a.anchors != nil {
		a.anchors.start(ctx)
	}
	go a.Runs.RunReaper(ctx, 30*time.Second, func(err error) { a.log.Error("run reaper", "err", err) })
	if a.googleMon != nil {
		go a.googleMon.Run(ctx)
	}
	if a.linearBoard != nil {
		go a.linearBoard.Run(ctx)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := a.Ops.Sweep(ctx); err != nil && ctx.Err() == nil {
					a.log.Error("op expiry sweep", "err", err)
				}
				// A granted key nobody claimed within its hour is revoked, and the revoke is written down.
				if n, err := a.Keys.Sweep(ctx); err != nil && ctx.Err() == nil {
					a.log.Error("unclaimed key sweep", "err", err)
				} else if n > 0 {
					a.log.Warn("keys not claimed in time were revoked", "count", n)
				}
			}
		}
	}()
	return nil
}

// Listen takes the console's port on cfg.Addr (loopback only): 127.0.0.1:PORT and [::1]:PORT (internal/loopback). It
// is called before Start, so a port somebody else holds stops chapd before crash recovery, the sweeps and the release of
// approved ops run (each service restart would repeat them), and before the
// service reports that it is running. The system completes connections into the backlog, but nothing is read or answered until Serve.
func (a *App) Listen() ([]net.Listener, error) { return a.listenWith(loopback.Listen) }

func (a *App) listenWith(listen loopback.ListenFunc) ([]net.Listener, error) {
	addr := a.cfg.Addr
	if addr == "" {
		addr = ops.ListenAddr
	}
	if err := requireLoopback(addr); err != nil {
		return nil, err
	}
	lns, err := loopback.Bind(addr, listen, "\nIs another chapd running? Stop it first, or use -addr with another port")
	if err != nil {
		return nil, err
	}
	if len(lns) == 1 {
		a.log.Warn("no IPv6 loopback on this machine: listening on IPv4 only", "addr", lns[0].Addr().String())
	}
	return lns, nil
}

// Serve serves the handler on the listeners Listen returned until ctx ends, then closes them.
func (a *App) Serve(ctx context.Context, lns []net.Listener) error {
	defer loopback.CloseAll(lns)
	return serveListeners(ctx, a, lns)
}

// localEndpoints is the console's origin and the Host allowlist for the listen
// address. The shipped port is 55398 (ADR-004). A different -addr port (a
// scratch chapd next to the real one) moves the WebAuthn origin with it, so a
// passkey made there is bound to that port and no other.
func localEndpoints(addr string, hosts []string) (console.Origin, []string) {
	origin := console.LocalOrigin
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "55398" {
		return origin, hosts
	}
	origin.URL = "http://localhost:" + port
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1:" + port, "localhost:" + port}
	}
	return origin, hosts
}

// requireLoopback refuses a listen address that is not a loopback IP: chapd's
// API is not for the network (ADR-004; the phone path is Tailscale Serve in
// front of the console, not a wider bind).
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("chapd: bad listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback)) {
		// Only these two: the console is held on both (internal/loopback), so another 127.x address would
		// name a port whose 127.0.0.1 side nobody holds, and the Host allowlist knows no other.
		return fmt.Errorf("chapd: listen address %q must be 127.0.0.1 or ::1 with a port (both are held)", addr)
	}
	return nil
}

// clock is the time now. Config.now is set only by tests; every other consumer of it takes the func as a Now option
// that treats nil as time.Now, so a nil here must too (a refused ceremony crashed chapd by calling a nil func).
func (a *App) clock() time.Time {
	if a.cfg.now != nil {
		return a.cfg.now()
	}
	return time.Now()
}

// auditWorker writes console audit events. Sign-ins and refused ceremonies
// are ledgered as console.login and console.refused (spec v0.1.1, section 8);
// a new credential is ledgered as the operator-recorded op approvers.enroll.
func (a *App) auditWorker(ctx context.Context) {
	defer close(a.auditDone)
	var gate refusalGate
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-a.auditCh:
			if !ok {
				return
			}
			a.audit(ctx, e, &gate)
		}
	}
}

// refusalGate coalesces a burst of refused ceremonies: any local process can
// trigger one, so at most one console.refused event is ledgered per second
// and it reports how many it left out (factory.console.suppressed).
type refusalGate struct {
	last       time.Time
	suppressed int
}

// allow reports whether a refusal at now is ledgered, and how many refusals
// since the previous ledgered one were not.
func (g *refusalGate) allow(now time.Time) (suppressed int, ok bool) {
	if !g.last.IsZero() && now.Sub(g.last) < time.Second {
		g.suppressed++
		return 0, false
	}
	suppressed, g.suppressed, g.last = g.suppressed, 0, now
	return suppressed, true
}

func (a *App) audit(ctx context.Context, e console.Event, gate *refusalGate) {
	switch e.Name {
	case console.EventEnrolled:
		a.log.Warn("approver credential enrolled", "approver", e.ApproverID, "rp_id", e.RPID, "origin", e.Origin, "uv", e.UserVerified, "bootstrap", e.Bootstrap,
			"attachment", e.Attachment, "transports", e.Transports, "backup_eligible", e.BackupEligible)
		// Only the first approver is recorded here: no approver existed to approve it
		// (spec v0.1.1, "Operator-recorded ops"). A later device is the approvers.enroll op.
		if !e.Bootstrap {
			return
		}
		if err := a.ledgerOperatorOp(ctx, "approvers.enroll", fmt.Sprintf("operator enrolled the first approver %d at %s; %s", e.ApproverID, e.Origin, authenticatorText(e))); err != nil {
			a.log.Error("could not ledger the enrolment", "err", err)
		}
	case console.EventLogin:
		a.log.Info("console sign-in", "approver", e.ApproverID, "rp_id", e.RPID, "uv", e.UserVerified, "attachment", e.Attachment, "transports", e.Transports, "backup_eligible", e.BackupEligible)
		if e.ApproverSpecID == "" || !e.UserVerified {
			return // a sign-in the spec cannot describe is not ledgered as one
		}
		a.ledgerConsole(ctx, "console.login", "INFO", authenticatorText(e), map[string]any{
			"factory.approver.id": e.ApproverSpecID, "factory.console.rp_id": e.RPID, "factory.console.user_verified": true})
	default:
		a.log.Warn("console refused a ceremony", "ceremony", e.Ceremony, "reason", e.Reason, "origin", e.Origin, "attachment", e.Attachment, "detail", e.Detail)
		suppressed, ok := gate.allow(a.clock())
		if !ok {
			return
		}
		attrs := map[string]any{"factory.console.ceremony": e.Ceremony, "factory.console.reason": e.Reason}
		if e.RPID != "" {
			attrs["factory.console.rp_id"] = e.RPID
		}
		if suppressed > 0 {
			attrs["factory.console.suppressed"] = float64(suppressed)
		}
		a.ledgerConsole(ctx, "console.refused", "WARN", "", attrs)
	}
}

// authenticatorText says what kind of authenticator an event came from, for a ledger body (ADR-004 amendment 15):
// the browser-reported attachment, its transports, and whether the passkey may be synced to an account.
func authenticatorText(e console.Event) string {
	return fmt.Sprintf("authenticator=%s; transports=%s; backup_eligible=%t",
		cmp.Or(e.Attachment, "unreported"), cmp.Or(strings.Join(e.Transports, ","), "none"), e.BackupEligible)
}

// ledgerConsole appends one console event: about the console, so no run and no project.
func (a *App) ledgerConsole(ctx context.Context, name, severity, body string, attrs map[string]any) {
	err := a.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return ledgerSink{l: a.Ledger}.AppendTx(ctx, tx, ops.Event{Name: name, Severity: severity, Body: body, Attributes: attrs})
	})
	if err != nil {
		a.log.Error("could not ledger the console event", "event", name, "err", err)
	}
}

// ledgerOperatorOp records an operator-only op as op.request and op.result,
// the same shape runtoken uses for orchestrator.issue (ADR-007 item 8).
func (a *App) ledgerOperatorOp(ctx context.Context, op, body string) error {
	project := "chaperone"
	pv := a.Policy.Baseline().BaselineVersion()
	rid, xid := idMaker("q-")(), idMaker("x-")()
	hash := strings.Repeat("0", 64)
	if h, err := opHashOf(project, op); err == nil {
		hash = h
	}
	return a.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		sink := ledgerSink{l: a.Ledger}
		for _, ev := range []ops.Event{
			{Name: "op.request", Project: project, Body: body, Severity: "WARN", Attributes: map[string]any{
				"factory.request_id": rid, "factory.op": op, "factory.op_hash": "sha256:" + hash, "factory.reversibility": "compensable",
				"factory.requester.kind": "orchestrator", "factory.orchestrator.id": runtoken.OperatorID}},
			{Name: "op.result", Project: project, Severity: "WARN", Attributes: map[string]any{
				"factory.request_id": rid, "factory.op_hash": "sha256:" + hash, "factory.execution_id": xid, "factory.outcome": "succeeded",
				"factory.policy_version": pv, "factory.requester.kind": "orchestrator", "factory.orchestrator.id": runtoken.OperatorID}},
		} {
			if err := sink.AppendTx(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close stops the ledger writer and closes the database and vault.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		if a.git != nil {
			a.git.Close() // revoke the GitHub tokens of every run, best effort
		}
		if a.bridge != nil {
			a.bridge.wait(15 * time.Second) // releases that are still waiting for an adapter
		}
		if a.notifier != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.notifier.Close(ctx)
			cancel()
		}
		if a.anchors != nil {
			a.anchors.wait() // its last export needs the ledger
		}
		if a.Ledger != nil {
			_ = a.Ledger.Close()
		}
		if a.vault != nil && a.cfg.testVault == nil {
			a.vault.Close()
		}
		if a.DB != nil {
			_ = a.DB.Close()
		}
	})
}

// defaultKeysPath sits next to the database (ADR-003 folder).
func defaultKeysPath(db string) string { return filepath.Join(filepath.Dir(db), "run-keys.json") }

// opHashOf is the op_hash (hex, no tag) of an operator-only op recorded by chapd
// itself: no params, target chaperone:console.
func opHashOf(project, op string) (string, error) {
	h, err := spec.OpHash(map[string]any{
		"spec_version": spec.SpecVersion, "project": project, "op": op,
		"target": map[string]any{"adapter": "chaperone", "ref": "console"}, "params": map[string]any{},
	})
	return strings.TrimPrefix(h, "sha256:"), err
}
