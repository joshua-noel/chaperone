// Command chap-host is the user-session helper (ticket L1-14). It runs in the
// operator's logon session because a service cannot show a toast. It does two
// things for chapd: it shows "N approvals waiting", and it runs allowlisted
// runbooks when given a Chaperone-signed execution grant (internal/grant).
//
// It listens on nothing. It connects out to chapd on loopback, so there is no
// pipe or port for another process to write to, and anything that claims to
// be a grant is verified (signature, expiry, nonce, script hash) before a
// single byte of a script runs. It has no command that takes a command line,
// and it never imports the vault or the store.
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
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
	"github.com/joshua-noel/chaperone/internal/logrot"
	"github.com/joshua-noel/chaperone/internal/version"
)

const usage = "usage: chap-host version | chap-host run [-config <file>]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one invocation and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		if err := version.Fprint(stdout, "chap-host"); err != nil {
			fmt.Fprintf(stderr, "chap-host: %v\n", err)
			return 1
		}
		return 0
	case "run":
		return runHost(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "chap-host: unknown command %q (known: version, run)\n", args[0])
		return 2
	}
}

func runHost(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("chap-host run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config file (default %LOCALAPPDATA%\\Chaperone\\host\\chap-host.json)")
	logDir := fs.String("log-dir", "", "also write a size-rotated chap-host.log in this folder (10 MiB x 10 files)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *cfgPath == "" {
		p, err := defaultConfigPath()
		if err != nil {
			fmt.Fprintf(stderr, "chap-host: %v\n", err)
			return 1
		}
		*cfgPath = p
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "chap-host: %v\n", err)
		return 1
	}

	var logW io.Writer = stderr
	if *logDir != "" {
		f, err := logrot.Open(*logDir, "chap-host", logrot.Options{})
		if err != nil {
			fmt.Fprintf(stderr, "chap-host: %v\n", err)
			return 1
		}
		defer f.Close()
		logW = io.MultiWriter(stderr, f)
	}
	log := slog.New(slog.NewTextHandler(logW, nil))
	key, _ := cfg.PublicKey() // checked by LoadConfig
	nonces, err := grant.OpenFileNonces(filepath.Join(cfg.StateDir, "nonces.jsonl"), time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "chap-host: %v\n", err)
		return 1
	}
	defer nonces.Close()
	verifier, err := grant.NewVerifier(key, nonces)
	if err != nil {
		fmt.Fprintf(stderr, "chap-host: %v\n", err)
		return 1
	}
	runner, err := NewRunner(verifier, builtinRunbooks(cfg.Scripts), filepath.Join(cfg.StateDir, "tmp"), log)
	if err != nil {
		fmt.Fprintf(stderr, "chap-host: %v\n", err)
		return 1
	}
	svc := &Service{Chapd: NewHTTPChapd(cfg.ChapdURL, cfg.ChapdTokenFile, nil), Toast: PowerShellToaster{}, Runner: runner, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log.Info("chap-host started", "chapd", cfg.ChapdURL, "runbooks", grant.Names())
	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "chap-host: %v\n", err)
		return 1
	}
	return 0
}
