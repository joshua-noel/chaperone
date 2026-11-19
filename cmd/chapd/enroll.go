package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/joshua-noel/chaperone/internal/console"
)

// defaultDB is where ADR-006 puts the state database. Reading and writing it
// needs the service account or an elevated prompt (ADR-003 ACLs), so the
// operator runs `chapd enroll` elevated (step H3).
const defaultDB = `D:\Storefront\chaperone\state.db`

// enrollCmd is `chapd enroll`: enrol the first Windows Hello passkey, then check
// one sign-in. It serves the console on 127.0.0.1:55398 until both are done.
func enrollCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("chapd enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", defaultDB, "path of state.db (created and migrated if missing)")
	scratch := fs.Bool("scratch", false, `use %LOCALAPPDATA%\Chaperone-h3\state.db (created if missing); for the H3 try-out, not for the real database`)
	check := fs.Bool("check", false, "skip enrolment; wait for one sign-in (an approver must exist)")
	name := fs.String("name", "operator", "approver name for the first enrolment")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long each step may take")
	addr := fs.String("addr", "", "listen address, loopback (default 127.0.0.1:55398); another port moves the console origin with it, for a scratch chapd next to the real one")
	var authn console.Authenticators
	fs.Func("approver-authenticators", "which authenticators may be enrolled: platform (the default: built into the device) or any (also a hardware security key, or a phone); use the same value as chapd run", func(v string) (err error) {
		authn, err = console.ParseAuthenticators(v)
		return err
	})
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: chapd enroll [-db PATH | -scratch] [-addr HOST:PORT] [-approver-authenticators platform|any] [-name NAME] [-timeout 10m] [-check]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	path := *db
	if *scratch {
		if path != defaultDB {
			fmt.Fprintln(stderr, "chapd enroll: -scratch and -db cannot be used together")
			return 2
		}
		dir, err := os.UserCacheDir() // %LOCALAPPDATA% on Windows
		if err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		dir = filepath.Join(dir, "Chaperone-h3")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		path = filepath.Join(dir, "state.db")
		fmt.Fprintf(stdout, "Scratch database: %s\n\n", path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *addr != "" {
		if err := requireLoopback(*addr); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	origin, _ := localEndpoints(*addr, nil)
	err := console.RunEnroll(ctx, console.EnrollOptions{
		DBPath: path, Addr: *addr, Origin: origin, Name: *name, TTL: *timeout, CheckOnly: *check, Authenticators: authn, Out: stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	return 0
}
