package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/privfile"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// `chapd connect github` sets up the operator's OWN GitHub App through GitHub's
// app-manifest flow, replacing the manual runbook: it asks GitHub (through the
// operator's browser) to create an App with the smallest permissions the shipped
// operations need, receives the App's private key, and puts it straight into the
// vault. See connect_github_flow.go for the local web server and its rules.
//
// Like `chapd vault import` and `chapd connect google`, it is an operator
// command run as the account that runs chapd: it writes no ledger event of its
// own (the spec has no event for it; docs/runbooks/github-app-setup.md says so).

const githubConnectUsage = `usage: chapd connect github (-org ORG | -user LOGIN) [-with GROUPS] [-timeout D]   create your own GitHub App, keep its key in the vault
       chapd connect github status                                         what is saved, then ask GitHub who the App is and where it is installed
       (both take [-db PATH] [-vault-dir D] [-vault-key-dir D] [-vault-wrapper NAME] [-vault-passphrase-fd N];
        see chapd vault for the key wrappers)

Run as the account that runs chapd, after 'chapd vault init' (ADR-003). The command
prints one address. You open it in your browser on this computer; it takes you to
GitHub, where you check the name and press "Create GitHub App". GitHub sends the
browser back to a port on this computer; the command takes the App's private key
from GitHub's answer into the vault. The key is never written to a file, printed
or logged.

The App is private to the account you name, has no webhook, and asks for the
smallest permissions the shipped GitHub operations need: contents write,
pull_requests write, checks read, metadata read. -with adds the permissions of
operations that are off by default, a comma-separated list of:
  deploy      deployments write (the deploy op)
  issues      issues write (issue.open, issue.comment, issue.reopen)
  ci-report   checks write instead of read (ci.report)

The command refuses to run when the vault already holds github-app-key: this is
the first setup. To replace a key, follow docs/runbooks/github-app-key.md.

When it is done, install the App on the repositories you choose (the command says
where). chapd finds the installation itself: you do not copy an installation id.
The App's id is recorded in github-app.json next to the database, and chapd run
reads it when -github-app-id is not given.`

// githubWebBase and githubAPIBase are GitHub's production addresses. Tests
// replace them with the fake (internal/gh/ghtest), as connectEndpoints is for Google.
var (
	githubWebBase = "https://github.com"
	githubAPIBase = gh.DefaultBaseURL
	// githubClock is the clock of the App client; nil is time.Now. Only tests set it, to the fake's own clock.
	githubClock func() time.Time
)

// githubAppFile is the record of the App, next to the database. It holds no secret.
const githubAppFile = "github-app.json"

// githubAppRecord is that file. chapd run reads it when -github-app-id is not given.
type githubAppRecord struct {
	Version  int    `json:"version"`
	AppID    int64  `json:"app_id"`
	ClientID string `json:"client_id"` // the iss of the App JWT; GitHub recommends the client id over the numeric id
	Slug     string `json:"slug"`
	Owner    string `json:"owner"`
	Created  string `json:"created"`
}

var (
	recSlugRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	recClientRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	recOwnerRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	orgRE       = recOwnerRE
)

func githubAppPath(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), githubAppFile) }

// readGitHubAppRecord reads the record next to the database. A missing file is
// (nil, nil); one that is not a plain file, too big, unknown in shape or with a
// value of an unexpected form is an error, and chapd does not start on it.
func readGitHubAppRecord(dbPath string) (*githubAppRecord, error) {
	path := githubAppPath(dbPath)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 4096 {
		return nil, fmt.Errorf("%s is not a small plain file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec githubAppRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return nil, fmt.Errorf("%s is not the record `chapd connect github` writes", path)
	}
	if rec.Version != 1 || rec.AppID <= 0 || !recClientRE.MatchString(rec.ClientID) || !recSlugRE.MatchString(rec.Slug) || !recOwnerRE.MatchString(rec.Owner) {
		return nil, fmt.Errorf("%s holds a value of an unexpected form", path)
	}
	return &rec, nil
}

// writeGitHubAppRecord makes the record, a NEW file only this user can open. It never replaces one.
func writeGitHubAppRecord(dbPath string, rec githubAppRecord) error {
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	f, err := privfile.Create(githubAppPath(dbPath))
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(githubAppPath(dbPath))
		return err
	}
	return nil
}

// applyGitHubAppRecord is called by the flag parser of `chapd run` and `chapd
// svc`: when -github-app-id was not given and the record exists, chapd uses the
// record's App. An explicit -github-app-id always wins. A record needs the vault
// to be open, so without -vault-dir chapd stops and says why.
func applyGitHubAppRecord(cfg *Config, stderr io.Writer) int {
	if cfg.GitHubAppID != "" {
		return 0
	}
	rec, err := readGitHubAppRecord(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 2
	}
	if rec == nil {
		return 0
	}
	if cfg.VaultDir == "" {
		fmt.Fprintf(stderr, "chapd: %s names the GitHub App %s, and its key is in the vault: start with -vault-dir and -vault-key-dir (chapd run needs both), or delete that file to run without GitHub\n",
			githubAppPath(cfg.DBPath), rec.Slug)
		return 2
	}
	cfg.GitHubAppID = rec.ClientID
	return 0
}

// cleanText makes text that came from GitHub safe to show.
func cleanText(s string) string { return untrusted.Clean(untrusted.Line(s), 80) }

// githubConnectCmd implements `chapd connect github`.
func githubConnectCmd(args []string, stdout, stderr io.Writer) int {
	action := "setup"
	if len(args) > 0 && args[0] == "status" {
		action, args = "status", args[1:]
	}
	fs := flag.NewFlagSet("chapd connect github", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, githubConnectUsage) }
	db := fs.String("db", defaultDB, "path of state.db")
	vaultDir := fs.String("vault-dir", "", "vault ciphertext folder (default: vault next to the database)")
	keyDir := fs.String("vault-key-dir", "", "vault wrapped-key folder (default: vault-keys next to the database)")
	var wc wrapperChoice
	wc.register(fs)
	org := fs.String("org", "", "create the App in this GitHub organization (exactly one of -org and -user is required)")
	user := fs.String("user", "", "create the App in this personal GitHub account: your login (exactly one of -org and -user is required)")
	with := fs.String("with", "", "extra permission groups for operations that are off by default: deploy, issues, ci-report (comma-separated)")
	timeout := fs.Duration("timeout", flowDefaultTimeout, "how long to wait for the browser (at most 30m)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (action == "status" && (*org != "" || *user != "" || *with != "")) {
		fs.Usage()
		return 2
	}
	var extras []string
	for _, e := range strings.Split(*with, ",") {
		if e = strings.TrimSpace(e); e != "" {
			extras = append(extras, e)
		}
	}
	perms, err := gh.ManifestPermissions(extras...)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: -with: %v (known: %s, %s, %s)\n", err, gh.ExtraDeploy, gh.ExtraIssues, gh.ExtraCIReport)
		return 2
	}
	if action == "setup" {
		switch {
		case (*org == "") == (*user == ""):
			fmt.Fprintln(stderr, "chapd: give exactly one of -org ORG or -user LOGIN. The command must know whose App it is making: it refuses an App that GitHub made under any other account, and it can only do that if you say which account is yours")
			return 2
		case *org != "" && !orgRE.MatchString(*org):
			fmt.Fprintln(stderr, "chapd: -org is not a GitHub organization name")
			return 2
		case *user != "" && !orgRE.MatchString(*user):
			fmt.Fprintln(stderr, "chapd: -user is not a GitHub account name")
			return 2
		}
	}
	if *timeout <= 0 || *timeout > flowMaxTimeout {
		fmt.Fprintf(stderr, "chapd: -timeout must be more than 0 and at most %s\n", flowMaxTimeout)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	d, err := store.Open(ctx, *db)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer d.Close()
	ms, err := store.Migrations()
	if err == nil {
		err = d.Migrate(ctx, ms)
	}
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	wrapper, err := wc.build()
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	vcfg := vault.Config{Dir: *vaultDir, KeyDir: *keyDir, DB: d, Wrapper: wrapper}
	if base := filepath.Dir(*db); vcfg.Dir == "" || vcfg.KeyDir == "" {
		if vcfg.Dir == "" {
			vcfg.Dir = filepath.Join(base, "vault")
		}
		if vcfg.KeyDir == "" {
			vcfg.KeyDir = filepath.Join(base, "vault-keys")
		}
	}
	v, err := vault.Open(ctx, vcfg)
	if errors.Is(err, vault.ErrNotInitialized) {
		fmt.Fprintf(stderr, "chapd: there is no vault yet. Run `chapd vault init` first (it shows a recovery identity once: keep it offline), then run this again\n")
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer v.Close()

	if action == "status" {
		return githubStatus(ctx, v, *db, stdout, stderr)
	}
	return githubSetup(ctx, v, *db, *org, *user, perms, *timeout, stdout, stderr)
}

// dbFlag is the flag text that points a command the operator runs next at the same database.
func dbFlag(db string) string {
	if db == defaultDB {
		return ""
	}
	return " -db " + db
}

func githubSetup(ctx context.Context, v *vault.Vault, db, org, user string, perms map[string]string, timeout time.Duration, stdout, stderr io.Writer) int {
	// Before anything starts: this command makes a first setup and replaces nothing.
	switch _, err := v.Info(ctx, gh.AppKeySecretID); {
	case err == nil:
		fmt.Fprintf(stderr, "chapd: the vault already holds %s. This command only makes a first setup. To check the App, run `chapd connect github status`. To replace the key, see docs/runbooks/github-app-key.md. To start over from nothing, both of these must go: the vault secret %s and the file %s (see docs/runbooks/github-app-setup.md, \"Starting over\")\n", gh.AppKeySecretID, gh.AppKeySecretID, githubAppPath(db))
		return 1
	case !errors.Is(err, vault.ErrNotFound):
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	if rec, err := readGitHubAppRecord(db); rec != nil || err != nil {
		fmt.Fprintf(stderr, "chapd: %s already exists. To start over from nothing, both of these must go: that file and the vault secret %s (see docs/runbooks/github-app-setup.md, \"Starting over\")\n", githubAppPath(db), gh.AppKeySecretID)
		return 1
	}

	flow, err := startManifestFlow(flowConfig{
		WebBase: githubWebBase, Org: org, User: user, Permissions: perms, Timeout: timeout,
		Note: func(reason string) { fmt.Fprintf(stderr, "chapd: refused a request to the setup page (%s)\n", reason) },
	})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	spec := flow.Spec()
	account := "the GitHub account " + user
	appsSettings := githubWebBase + "/settings/apps"
	owner := user
	if org != "" {
		account = "the GitHub organization " + org
		appsSettings = githubWebBase + "/organizations/" + url.PathEscape(org) + "/settings/apps"
		owner = org
	}
	fmt.Fprintf(stdout, "Chaperone will ask GitHub to create an App in %s. The App is private to it and has no webhook.\nIt asks for these permissions and no others:\n", account)
	names := make([]string, 0, len(perms))
	for k := range perms {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(stdout, "  %s: %s\n", k, perms[k])
	}
	fmt.Fprintf(stdout, "\nOpen this address in your browser on this computer. It works once, from this computer only, for %s:\n\n%s\n\nWaiting ...\n", timeout, flow.StartURL())

	code, err := flow.Wait(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v. Nothing was stored. If GitHub already created an App, delete it at %s\n", err, appsSettings)
		return 1
	}

	conv, err := gh.NewAnonymous(gh.Config{BaseURL: githubAPIBase})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	app, err := conv.ConvertManifest(ctx, code)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: GitHub did not give the App over: %v\nNothing was stored. If GitHub created an App, delete it at %s and run this again\n", err, appsSettings)
		return 1
	}
	defer app.Wipe()
	deleteHint := appsSettings + "/" + app.Slug + "/advanced"
	refuse := func(why string) int {
		fmt.Fprintf(stderr, "chapd: %s. Nothing was stored.\nIf that App is in your account, delete it at %s. If it belongs to somebody else you cannot delete it, and there is nothing to clean up here. Then run this again.\n", why, deleteHint)
		return 1
	}
	// The owner is checked before anything is stored: whose App this is must be known, not read off GitHub afterwards.
	if !strings.EqualFold(app.OwnerLogin, owner) {
		fmt.Fprintf(stderr, "chapd: the App GitHub made belongs to the account %s, not to %s, the account you named. Nothing was stored.\n"+
			"You cannot delete an App that belongs to somebody else, and there is nothing to clean up here. "+
			"If you did press \"Create GitHub App\" while signed in as another account, delete the App there at %s, then run this again.\n",
			cleanText(app.OwnerLogin), owner, deleteHint)
		return 1
	}
	if err := app.Check(spec); err != nil {
		return refuse(err.Error())
	}
	if _, err := gh.ParsePrivateKeyPEM(app.PEM); err != nil {
		return refuse("the private key GitHub sent is not a usable RSA key")
	}

	// From here the key is stored before anything else is tried: GitHub shows it only once.
	info, err := v.Import(ctx, vault.Meta{ID: gh.AppKeySecretID, Kind: gh.AppKeySecretID, Owner: "chapd connect github"}, app.PEM)
	app.Wipe()
	if err != nil {
		fmt.Fprintf(stderr, "chapd: the vault did not take the key: %v\nThe App %s exists on GitHub and its key is lost. Delete the App at %s and run this again\n", err, cleanText(app.Slug), deleteHint)
		return 1
	}
	fmt.Fprintf(stdout, "\nGitHub created the App %s for %s (App id %d), the account you named.\nIts private key is in the vault as %s (fingerprint %s). It was not written to a file.\n",
		cleanText(app.Slug), cleanText(app.OwnerLogin), app.ID, gh.AppKeySecretID, info.Fingerprint)

	rec := githubAppRecord{Version: 1, AppID: app.ID, ClientID: app.ClientID, Slug: app.Slug, Owner: app.OwnerLogin, Created: time.Now().UTC().Format(time.RFC3339)}
	if err := writeGitHubAppRecord(db, rec); err != nil {
		fmt.Fprintf(stderr, "chapd: the key is stored, but the App could not be recorded: %v\nStart chapd with -github-app-id %s instead\n", err, app.ClientID)
		return 1
	}
	fmt.Fprintf(stdout, "Recorded the App in %s (no secret in it). chapd run reads it when -github-app-id is not given.\n", githubAppPath(db))

	// Show that the stored key and the recorded id work together. A failure here changes nothing that is stored.
	if client, err := githubClient(v, rec.ClientID); err != nil {
		fmt.Fprintf(stdout, "Could not check the App with GitHub yet: %v\n", err)
	} else if got, err := client.GetApp(ctx); err != nil {
		fmt.Fprintf(stdout, "Could not check the App with GitHub yet (%v). Run `chapd connect github status%s` in a minute.\n", err, dbFlag(db))
	} else if got.ID != rec.AppID {
		fmt.Fprintf(stdout, "WARNING: GitHub answered as another App (id %d, not %d). Run `chapd connect github status%s`.\n", got.ID, rec.AppID, dbFlag(db))
	} else {
		fmt.Fprintf(stdout, "Checked with GitHub: the stored key signs in as %s.\n", cleanText(got.Slug))
	}

	installURL := githubWebBase + "/apps/" + app.Slug + "/installations/new"
	fmt.Fprintf(stdout, "\nOne step is left: install the App on the repositories you choose.\n  1. Open %s\n  2. Choose \"Only select repositories\", pick them, and press Install.\n", installURL)
	fmt.Fprintf(stdout, "You do not copy an installation id. For each repository chapd asks GitHub, with the App's key, which installation covers it.\nTo check, run `chapd connect github status%s`. Then start chapd with the vault open (-vault-dir and -vault-key-dir): it reads %s.\n", dbFlag(db), githubAppFile)
	return 0
}

// githubClient is the App client for the stored key and the App id given.
func githubClient(v *vault.Vault, issuer string) (*gh.Client, error) {
	keys, err := gh.NewVaultKey(v, gh.AppKeySecretID)
	if err != nil {
		return nil, err
	}
	return gh.New(gh.Config{AppID: issuer, Keys: keys, BaseURL: githubAPIBase, Now: githubClock})
}

func githubStatus(ctx context.Context, v *vault.Vault, db string, stdout, stderr io.Writer) int {
	rec, err := readGitHubAppRecord(db)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	info, kerr := v.Info(ctx, gh.AppKeySecretID)
	if rec == nil || kerr != nil {
		fmt.Fprintf(stdout, "No GitHub App is set up here (record %s: %s; vault key %s: %s). Run `chapd connect github%s`.\n",
			githubAppFile, yesNo(rec != nil), gh.AppKeySecretID, yesNo(kerr == nil), dbFlag(db))
		return 1
	}
	fmt.Fprintf(stdout, "App:         %s (App id %d, client id %s), owner %s\nKey:         %s in the vault, fingerprint %s\nRecorded in: %s\n",
		rec.Slug, rec.AppID, rec.ClientID, rec.Owner, gh.AppKeySecretID, info.Fingerprint, githubAppPath(db))
	client, err := githubClient(v, rec.ClientID)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	got, err := client.GetApp(ctx)
	if err != nil {
		fmt.Fprintf(stdout, "PROBLEM: GitHub did not accept the stored key for this App: %v\n", err)
		return 1
	}
	if got.ID != rec.AppID {
		fmt.Fprintf(stdout, "PROBLEM: GitHub says this key belongs to the App with id %d, but the record says %d.\n", got.ID, rec.AppID)
		return 1
	}
	perms := make([]string, 0, len(got.Permissions))
	for k, lvl := range got.Permissions {
		perms = append(perms, cleanText(k)+": "+cleanText(lvl))
	}
	sort.Strings(perms)
	fmt.Fprintf(stdout, "GitHub:      the key signs in as %s, owner %s\nPermissions: %s\n", cleanText(got.Slug), cleanText(got.OwnerLogin), strings.Join(perms, ", "))
	if len(got.Events) != 0 {
		fmt.Fprintln(stdout, "NOTE: the App subscribes to events. chapd needs none; consider turning them off in the App's settings.")
	}
	ins, err := client.ListInstallations(ctx)
	if err != nil {
		fmt.Fprintf(stdout, "PROBLEM: could not list the installations: %v\n", err)
		return 1
	}
	if len(ins) == 0 {
		fmt.Fprintf(stdout, "Installed:   nowhere yet. Open %s/apps/%s/installations/new, choose the repositories and press Install.\n", githubWebBase, rec.Slug)
		return 1
	}
	for _, in := range ins {
		sel := "selected repositories"
		if in.Selection == "all" {
			sel = "all repositories"
		}
		fmt.Fprintf(stdout, "Installed:   on %s (installation %d, %s)\n", cleanText(in.Account), in.ID, sel)
	}
	fmt.Fprintln(stdout, "chapd finds the installation of each repository by itself; these ids are for your information.")
	return 0
}

func yesNo(b bool) string {
	if b {
		return "found"
	}
	return "missing"
}
