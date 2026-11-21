package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/joshua-noel/chaperone/internal/console"
	"github.com/joshua-noel/chaperone/internal/logrot"
	"github.com/joshua-noel/chaperone/internal/loopback"
)

// runCmd is `chapd run`: chapd in the foreground. The Windows service host
// (`chapd svc`) runs the same code under the service manager.
func runCmd(args []string, stdout, stderr io.Writer) int {
	cfg, code := parseRunFlags("chapd run", args, stderr, true)
	if code != 0 {
		return code
	}
	logger, closeLog, err := newLogger(cfg.LogDir, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer closeLog()
	cfg.Log = logger
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := runDaemon(ctx, cfg); err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	return 0
}

// parseRunFlags reads the flags of `chapd run` and `chapd svc`. demo is true only
// for `chapd run`: a -tags demo build adds its dev-only flags there, never to
// the service.
func parseRunFlags(name string, args []string, stderr io.Writer, demo bool) (Config, int) {
	var cfg Config
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.DBPath, "db", defaultDB, "path of state.db")
	fs.StringVar(&cfg.PolicyDir, "policy-dir", "", "directory of policy/<project>.yaml files (default: baseline only)")
	fs.StringVar(&cfg.KeysPath, "keys", "", "pinned run-token key set JSON (default: run-keys.json next to the database)")
	fs.StringVar(&cfg.ProfilesDir, "profiles-dir", "", "folder of generic profiles <digest hex>.json that runner.* run tokens may name (default: profiles next to the database, if it exists; without one every runner.* token is refused)")
	fs.StringVar(&cfg.Instance, "instance", "pc", "ledger instance (chain chaperone.<instance>)")
	fs.StringVar(&cfg.ExportDir, "export-dir", "", "daily ledger JSONL export root")
	fs.StringVar(&cfg.VaultDir, "vault-dir", "", "vault ciphertext folder (enables redaction of secrets and the interim issuer)")
	fs.StringVar(&cfg.VaultKeyDir, "vault-key-dir", "", "vault wrapped-key folder")
	cfg.VaultWrap.register(fs)
	fs.StringVar(&cfg.InterimSecretID, "interim-secret", "", "vault secret id of the interim issuer's Ed25519 seed")
	fs.StringVar(&cfg.InterimKID, "interim-kid", "", "kid of the interim issuer in the key set")
	fs.StringVar(&cfg.GitHubAppID, "github-app-id", "", "GitHub App id or client id; turns on pr.merge and pr.update (needs -vault-dir and `chapd vault import`)")
	fs.StringVar(&cfg.Addr, "addr", "", "listen address: 127.0.0.1 or ::1 and a port (default 127.0.0.1:55398); both loopback addresses are held on that port")
	fs.StringVar(&cfg.LogDir, "log-dir", "", "write the log to a size-rotated chapd.log in this folder as well (10 MiB x 10 files)")
	fs.StringVar(&cfg.NtfyTopicSecretID, "ntfy-topic-secret", "", "vault secret id of the ntfy topic: turns on the phone wake-up (needs -vault-dir)")
	fs.StringVar(&cfg.NtfyURL, "ntfy-url", "", "ntfy server base URL (default https://ntfy.sh)")
	fs.StringVar(&cfg.PhoneHost, "phone-host", "", "the server's full tailnet name, e.g. server.tail1234.ts.net: turns on the phone passkey with number matching (Tailscale Serve in front of the console; docs/runbooks/phone.md)")
	fs.Func("approver-authenticators", "which authenticators may be enrolled and approve: platform (the default: built into the device, such as Windows Hello or Touch ID) or any (also a hardware security key, and a phone through the browser's cross-device prompt). User verification is required either way. docs/running-chapd.md", func(v string) error {
		var err error
		cfg.Authenticators, err = console.ParseAuthenticators(v)
		return err
	})
	fs.Func("console-frame-ancestor", "an origin (scheme://host[:port], e.g. http://localhost:55440) that may show the console's approvals, ledger and runs pages in a frame and ask for a passkey there; repeatable; off by default (docs/runbooks/dashboard-frame.md)", func(v string) error {
		cfg.FrameAncestors = append(cfg.FrameAncestors, v)
		return nil
	})
	cfg.Deploy.register(fs)
	cfg.Google.register(fs)
	cfg.Linear.register(fs)
	cfg.Anchors.register(fs)
	if demo {
		demoFlags(fs, &cfg)
	}
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s [flags]\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return cfg, 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return cfg, 2
	}
	if cfg.KeysPath == "" {
		cfg.KeysPath = defaultKeysPath(cfg.DBPath)
	}
	if cfg.ProfilesDir == "" {
		if d := filepath.Join(filepath.Dir(cfg.DBPath), "profiles"); isDir(d) {
			cfg.ProfilesDir = d
		}
	}
	if code := applyGitHubAppRecord(&cfg, stderr); code != 0 {
		return cfg, code
	}
	return cfg, 0
}

// newLogger builds chapd's slog logger. Without dir it writes to w only. With
// dir it also writes <dir>/chapd.log, rotated by size. `chapd svc` passes
// io.Discard as w because a service has no console.
func newLogger(dir string, w io.Writer) (*slog.Logger, func(), error) {
	if dir == "" {
		return slog.New(slog.NewTextHandler(w, nil)), func() {}, nil
	}
	f, err := logrot.Open(dir, "chapd", logrot.Options{})
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewTextHandler(io.MultiWriter(w, f), nil)), func() { _ = f.Close() }, nil
}

// runDaemon builds chapd, takes the console's port, starts its background work and serves until ctx ends. The port is
// taken before Start (and so before anything printed for the operator, such as the demo's enrolment address): if
// another program holds it, chapd stops there, and a service that restarts does not repeat start-up work each time.
// Connections made meanwhile wait in the system's backlog: nothing is read or answered until Start has finished.
func runDaemon(ctx context.Context, cfg Config) error {
	app, err := Build(ctx, cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	lns, err := app.Listen()
	if err != nil {
		return err
	}
	defer loopback.CloseAll(lns)
	if cfg.onListening != nil {
		cfg.onListening()
	}
	if err := app.Start(ctx); err != nil {
		return err
	}
	if cfg.afterBuild != nil {
		if err := cfg.afterBuild(ctx, app); err != nil {
			return err
		}
	}
	return app.Serve(ctx, lns)
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
