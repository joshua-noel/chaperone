package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	keystore "github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/version"
)

const orchUsage = `usage: chapd orch issue  -project p[,p] -ops op[,op] [-id main] [-days 30] [-mint-interim] [-token-file F] [-db PATH]
       chapd orch revoke -id main [-db PATH]
       chapd orch list   [-db PATH]

Run elevated, as the operator (ADR-007). issue writes the token to a file only the
invoking user can read and prints its fingerprint and expiry, never the token.`

// defaultTokenFile is %LOCALAPPDATA%\Chaperone\orchestrator.token of the
// invoking user (ADR-007 item 5).
func defaultTokenFile() (string, error) {
	dir, err := os.UserCacheDir() // %LOCALAPPDATA% on Windows
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Chaperone", "orchestrator.token"), nil
}

type orchEnv struct {
	db   *store.DB
	led  *ledger.Ledger
	orch *runtoken.Orchestrators
}

func (e *orchEnv) close() {
	_ = e.led.Close()
	_ = e.db.Close()
}

// openOrch opens the database, the ledger and the orchestrator registry the same
// way `chapd run` does, so an issue or revoke is ledgered like any other op and
// a revoke cancels the orchestrator's waiting ops in the same transaction.
func openOrch(ctx context.Context, dbPath, instance string) (*orchEnv, error) {
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*orchEnv, error) { _ = db.Close(); return nil, err }
	ms, err := store.Migrations()
	if err != nil {
		return fail(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		return fail(err)
	}
	reg := redact.NewRegistry()
	led, err := ledger.Open(ctx, db, ledger.Config{Instance: instance, Version: version.Version, Redactor: reg})
	if err != nil {
		return fail(fmt.Errorf("open the ledger: %w", err))
	}
	cat, base, err := policy.Default()
	if err != nil {
		_ = led.Close()
		return fail(err)
	}
	sink := ledgerSink{l: led}
	svc, err := ops.NewService(ops.Config{DB: db, Ledger: sink, Policy: policy.NewEngine(cat, base, "")})
	if err != nil {
		_ = led.Close()
		return fail(err)
	}
	ks, err := keystore.New(keystore.Config{
		DB: db, Ledger: sink, PolicyVersion: base.BaselineVersion,
		TxRevoke: func(ctx context.Context, tx *store.Tx, id string) error { return svc.CancelKeyOps(ctx, tx, id) },
	})
	if err != nil {
		_ = led.Close()
		return fail(err)
	}
	txRevoke, txDrop := orchestratorHooks(svc, ks)
	o, err := runtoken.NewOrchestrators(runtoken.OrchConfig{
		DB: db, Appender: sink, Redact: reg, PolicyVersion: base.BaselineVersion,
		TxRevoke: txRevoke, TxDropProjects: txDrop,
	})
	if err != nil {
		_ = led.Close()
		return fail(err)
	}
	return &orchEnv{db: db, led: led, orch: o}, nil
}

func orchCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, orchUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("chapd orch "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, orchUsage) }
	db := fs.String("db", defaultDB, "path of state.db")
	instance := fs.String("instance", "pc", "ledger instance (chain chaperone.<instance>)")
	id := fs.String("id", "main", "orchestrator id")
	var projects, opList, tokenFile string
	var days int
	var mint bool
	switch sub {
	case "issue":
		fs.StringVar(&projects, "project", "", "comma-separated projects the token may ask for")
		fs.StringVar(&opList, "ops", "", "comma-separated op kinds (or prefix.* patterns) the token may ask for")
		fs.IntVar(&days, "days", runtoken.MaxOrchDays, "lifetime in days (1 to 30)")
		fs.BoolVar(&mint, "mint-interim", false, "let the holder mint interim run tokens (chap dev-token)")
		fs.StringVar(&tokenFile, "token-file", "", `where to write the token (default %LOCALAPPDATA%\Chaperone\orchestrator.token)`)
	case "revoke", "list":
	default:
		fmt.Fprintf(stderr, "chapd orch: unknown command %q\n%s\n", sub, orchUsage)
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if sub == "issue" && (projects == "" || opList == "") {
		fmt.Fprintln(stderr, "chapd orch issue: -project and -ops are required")
		return 2
	}
	// Elevation is demanded for the real database; a test or scratch database
	// elsewhere is not the operator's state.
	if *db == defaultDB && !elevated() {
		fmt.Fprintln(stderr, "chapd orch: run this from an elevated prompt as the operator (ADR-007)")
		return 1
	}

	ctx := context.Background()
	env, err := openOrch(ctx, *db, *instance)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer env.close()

	switch sub {
	case "issue":
		return orchIssue(ctx, env, runtoken.IssueParams{
			ID:    *id,
			Scope: runtoken.OrchScope{Projects: splitList(projects), Ops: splitList(opList), MintInterim: mint},
			Days:  days,
		}, tokenFile, stdout, stderr)
	case "revoke":
		if err := env.orch.Revoke(ctx, *id, "chapd orch revoke"); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "revoked the orchestrator token of %q; its next request is TOKEN_REVOKED\n", *id)
	case "list":
		infos, err := env.orch.List(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tFINGERPRINT\tSTATE\tEXPIRES(-04)\tPROJECTS\tOPS\tINTERIM")
		now := time.Now()
		for _, i := range infos {
			state := "live"
			switch {
			case !i.RevokedAt.IsZero():
				state = "revoked"
			case !now.Before(i.ExpiresAt):
				state = "expired"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n", i.ID, i.Fingerprint, state, localtime.RFC3339(i.ExpiresAt),
				strings.Join(i.Scope.Projects, ","), strings.Join(i.Scope.Ops, ","), i.Scope.MintInterim)
		}
		_ = tw.Flush()
	}
	return 0
}

func orchIssue(ctx context.Context, env *orchEnv, p runtoken.IssueParams, tokenFile string, stdout, stderr io.Writer) int {
	if tokenFile == "" {
		var err error
		if tokenFile, err = defaultTokenFile(); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
	}
	res, err := env.orch.Issue(ctx, p)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	if err := writePrivate(tokenFile, []byte(res.Token+"\n")); err != nil {
		// A token nobody holds must not stay live.
		if rerr := env.orch.Revoke(ctx, p.ID, "chapd orch issue: could not write the token file"); rerr != nil {
			err = errors.Join(err, rerr)
		}
		fmt.Fprintf(stderr, "chapd: could not write %s, so the new token was revoked again: %v\n", tokenFile, err)
		return 1
	}
	fmt.Fprintf(stdout, "orchestrator %q issued\n  fingerprint: %s\n  expires:     %s\n  token file:  %s (readable by this user only)\n",
		p.ID, res.Fingerprint, localtime.RFC3339(res.ExpiresAt), tokenFile)
	return 0
}

// writePrivate writes data to a new file that only the invoking user can read
// and renames it over path, so there is no moment when the token sits in a file
// others can read, and a rotation replaces the old file whole.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".orch-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func(err error) error { _ = f.Close(); _ = os.Remove(tmp); return err }
	if err := restrictToCurrentUser(tmp); err != nil {
		return cleanup(err)
	}
	if _, err := f.Write(data); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
