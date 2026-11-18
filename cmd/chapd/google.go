package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// This file wires the Google connectors (L1-16): the `mail.send` and
// `drive.share` adapters and the token monitor inside `chapd run`, and the
// `chapd connect google` command that signs in once. Both ops stay disabled in
// the baseline policy; installing an adapter turns nothing on.

// googleConfig holds `chapd run`'s Google flags.
type googleConfig struct {
	// AttachmentsDir is the folder of staged mail attachments, files named by
	// their lower-case hex SHA-256. Empty means mail goes without attachments.
	AttachmentsDir string
}

func (c *googleConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&c.AttachmentsDir, "google-attachments-dir", "", "folder of staged mail attachments, each file named by its SHA-256 (empty: mail.send refuses attachments)")
}

// logAlerts is the alert path when no alerts script is configured: the alert is
// an error line in chapd's log.
type logAlerts struct{ log *slog.Logger }

func (l logAlerts) RaiseGoogleAlert(_ context.Context, key, text string) {
	l.log.Error("google alert", "key", key, "text", text)
}

// scriptAlerts raises the alert through the same alerts.ps1 path a failed
// deploy uses.
type scriptAlerts struct{ s *ops.AlertsScript }

func (s scriptAlerts) RaiseGoogleAlert(ctx context.Context, key, text string) {
	s.s.RaiseDeployAlert(ctx, key, text)
}

func (a *App) googleAlerter() google.Alerter {
	c := a.cfg.Deploy
	if c.AlertsScript == "" {
		return logAlerts{a.log}
	}
	ps := c.PowerShell
	if ps == "" {
		ps = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return scriptAlerts{&ops.AlertsScript{PowerShell: ps, Script: c.AlertsScript, Folder: c.AlertsFolder, Log: a.log}}
}

// installGoogle adds the two Google adapters when the vault is open. They
// refuse every request until the policy enables the op, the project has a
// `google:` block and `chapd connect google` has run.
func (a *App) installGoogle(ads map[string]ops.Adapter) error {
	if a.vault == nil {
		return nil
	}
	ep := google.DefaultEndpoints()
	src, err := google.NewSource(google.SourceConfig{
		Secrets: a.vault, Registry: a.Reg, Endpoints: ep, Alert: a.googleAlerter(), Now: a.cfg.now,
	})
	if err != nil {
		return err
	}
	pol := func(project string) *policy.Google {
		eff := a.Policy.For(project)
		if eff.Invalid != nil {
			return nil
		}
		return eff.Google
	}
	var atts google.AttachmentStore
	if a.cfg.Google.AttachmentsDir != "" {
		atts = google.DirStore{Dir: a.cfg.Google.AttachmentsDir}
	}
	gm, err := google.NewGmail(google.GmailConfig{Source: src, Policy: pol, Attachments: atts, Redactor: a.Reg, Endpoints: ep})
	if err != nil {
		return err
	}
	dr, err := google.NewDrive(google.DriveConfig{Source: src, Policy: pol, Endpoints: ep})
	if err != nil {
		return err
	}
	ads["mail.send"], ads["drive.share"] = gm, dr
	a.googleMon = &google.Monitor{Source: src}
	return nil
}

// ---- chapd connect google ---------------------------------------------------

const connectUsage = `usage: chapd connect google [-client-file F [-delete]] [-drive] [-timeout D]   sign in once, into the vault
       chapd connect google -client-file F -out T.json [-drive]                    sign in, write the token set to T.json
       chapd connect google status                                                 what is saved, no network
       chapd connect google revoke                                                 tell Google to forget the sign-in
       (all take [-db PATH] [-vault-dir D] [-vault-key-dir D])

Run as the account that runs chapd, like 'chapd vault import' (ADR-003): the vault
keys are bound to that account. Sign-in opens nothing by itself: it prints an
address, you open it in your browser on the server, choose the Google account and
allow the scopes; Google sends the browser back to a port on the server (loopback
redirect, PKCE).

-client-file is the JSON that Google Cloud's "Download JSON" gives for an OAuth
client of type Desktop app. It is stored in the vault; with -delete the file is
overwritten and removed afterwards. With -out nothing touches a vault: the token
set goes to a new owner-only file for the console's Secrets screen (see
docs/runbooks/google.md). -drive also asks for the Drive scope
(restricted by Google); without it only gmail.send is requested.`

// connectCmd implements `chapd connect`.
func connectCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "google" {
		fmt.Fprintln(stderr, connectUsage)
		return 2
	}
	rest := args[1:]
	action := "signin"
	if len(rest) > 0 && (rest[0] == "status" || rest[0] == "revoke") {
		action, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("chapd connect google", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, connectUsage) }
	db := fs.String("db", defaultDB, "path of state.db")
	vaultDir := fs.String("vault-dir", "", "vault ciphertext folder (default: vault next to the database)")
	keyDir := fs.String("vault-key-dir", "", "vault wrapped-key folder (default: vault-keys next to the database)")
	clientFile := fs.String("client-file", "", "OAuth client JSON downloaded from Google Cloud")
	del := fs.Bool("delete", false, "overwrite and delete -client-file after it is stored")
	drive := fs.Bool("drive", false, "also ask for the Drive scope")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for the browser")
	out := fs.String("out", "", "sign in without a vault and write the token set to this new file (then import it with the console's Secrets screen)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (action != "signin" && (*clientFile != "" || *drive)) {
		fs.Usage()
		return 2
	}

	if *out != "" {
		if action != "signin" || *clientFile == "" {
			fmt.Fprintln(stderr, "chapd: -out needs -client-file and is only for the sign-in")
			return 2
		}
		return googleSignInToFile(*clientFile, *out, *drive, *timeout, stdout, stderr)
	}

	ctx := context.Background()
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
	cfg := vault.Config{Dir: *vaultDir, KeyDir: *keyDir, DB: d, Wrapper: newWrapper()}
	base := filepath.Dir(*db)
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(base, "vault")
	}
	if cfg.KeyDir == "" {
		cfg.KeyDir = filepath.Join(base, "vault-keys")
	}
	v, err := vault.Open(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer v.Close()

	ep := connectEndpoints
	switch action {
	case "status":
		return googleStatus(ctx, v, ep, stdout, stderr)
	case "revoke":
		if err := google.RevokeSaved(ctx, v, nil, ep); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Google was told to revoke the sign-in. Mail and Drive ops now refuse until you run `chapd connect google` again.")
		return 0
	}

	if *clientFile != "" {
		if code := googleImportClient(ctx, v, *clientFile, *del, stdout, stderr); code != 0 {
			return code
		}
	}
	client, err := google.LoadClient(ctx, v)
	if err != nil {
		if errors.Is(err, google.ErrNotConnected) {
			fmt.Fprintln(stderr, "chapd: no OAuth client is stored yet; pass -client-file <the JSON from Google Cloud> (see docs/runbooks/google.md)")
		} else {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
		}
		return 1
	}
	scopes := []string{google.ScopeGmailSend}
	if *drive {
		scopes = append(scopes, google.ScopeDrive)
	}
	src, err := google.NewSource(google.SourceConfig{Secrets: v, Registry: v.Registry(), Endpoints: ep})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	ts, err := google.Connect(ctx, google.ConnectConfig{
		Client: client, Scopes: scopes, Endpoints: ep, Timeout: *timeout,
		OpenURL: func(u string) error {
			fmt.Fprintf(stdout, "Open this address in your browser on the server and sign in with the Google account Chaperone should use:\n\n%s\n\nWaiting up to %s ...\n", u, *timeout)
			return nil
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	if err := src.Connected(ctx, ts); err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "connected as %s, scopes: %s\n", ts.Account, strings.Join(shortScopes(ts.Scopes), " "))
	if !ts.RefreshExpiry.IsZero() {
		fmt.Fprintf(stdout, "WARNING: Google says this sign-in ends at %s. The consent screen is still in Testing; set it to In production and sign in again (docs/runbooks/google.md, step 3).\n", ts.RefreshExpiry.UTC().Format(time.RFC3339))
	}
	return 0
}

// connectEndpoints is Google's production endpoints; tests replace it.
var connectEndpoints = google.DefaultEndpoints()

func googleImportClient(ctx context.Context, v *vault.Vault, file string, del bool, stdout, stderr io.Writer) int {
	raw, err := readSecretFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer clear(raw)
	c, err := google.ParseClientJSON(raw)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %s: %v\n", file, err)
		return 1
	}
	if err := google.SaveClient(ctx, v, c); err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "stored the OAuth client %s in the vault\n", c.ClientID)
	if !del {
		fmt.Fprintf(stdout, "%s still exists; delete it now (or re-run with -delete next time)\n", file)
		return 0
	}
	if err := shredFile(file, int64(len(raw))); err != nil {
		fmt.Fprintf(stderr, "chapd: the client is stored, but %s could not be deleted: %v\ndelete it by hand now\n", file, err)
		return 1
	}
	fmt.Fprintf(stdout, "deleted %s\n", file)
	return 0
}

func shortScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimPrefix(s, "https://www.googleapis.com/auth/"))
	}
	return out
}

func googleStatus(ctx context.Context, v *vault.Vault, ep google.Endpoints, stdout, stderr io.Writer) int {
	src, err := google.NewSource(google.SourceConfig{Secrets: v, Registry: v.Registry(), Endpoints: ep})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	st := src.Status(ctx)
	if !st.Connected {
		fmt.Fprintln(stdout, "Google is not connected. Run `chapd connect google`.")
		return 1
	}
	fmt.Fprintf(stdout, "account:   %s\nscopes:    %s\nconnected: %s\naccess token ends: %s (renewed on use)\n",
		st.Account, strings.Join(shortScopes(st.Scopes), " "), st.ConnectedAt.UTC().Format(time.RFC3339), st.AccessExpiry.UTC().Format(time.RFC3339))
	if st.RefreshExpiry.IsZero() {
		fmt.Fprintln(stdout, "sign-in ends:      no fixed end (it ends if you revoke it, change the password, or leave it unused for six months)")
	} else {
		fmt.Fprintf(stdout, "sign-in ends:      %s (Testing mode)\n", st.RefreshExpiry.UTC().Format(time.RFC3339))
	}
	if p := st.Problem(time.Now()); p != "" {
		fmt.Fprintf(stdout, "PROBLEM: %s\n", p)
		return 1
	}
	return 0
}

// googleSignInToFile signs in with no vault and writes the token set to a new
// file, for the operator who cannot run chapd as the vault's account (the
// installer closes svc-chaperone's sign-in once the vault exists). The operator
// then imports the file as the secret `google-token` through the console's
// Secrets screen, as the GitHub App key is imported, and deletes it. The file
// is created exclusively with an owner-only mode and is never overwritten.
func googleSignInToFile(clientFile, out string, drive bool, timeout time.Duration, stdout, stderr io.Writer) int {
	raw, err := readSecretFile(clientFile)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	client, err := google.ParseClientJSON(raw)
	clear(raw)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %s: %v\n", clientFile, err)
		return 1
	}
	scopes := []string{google.ScopeGmailSend}
	if drive {
		scopes = append(scopes, google.ScopeDrive)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(out)
		}
	}()
	ctx := context.Background()
	ts, err := google.Connect(ctx, google.ConnectConfig{
		Client: client, Scopes: scopes, Endpoints: connectEndpoints, Timeout: timeout,
		OpenURL: func(u string) error {
			fmt.Fprintf(stdout, "Open this address in your browser on the server and sign in with the Google account Chaperone should use:\n\n%s\n\nWaiting up to %s ...\n", u, timeout)
			return nil
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	doc, err := json.Marshal(ts)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	_, werr := f.Write(doc)
	clear(doc)
	if werr != nil || f.Sync() != nil {
		fmt.Fprintf(stderr, "chapd: write %s: %v\n", out, werr)
		return 1
	}
	ok = true
	fmt.Fprintf(stdout, "connected as %s, scopes: %s\n", ts.Account, strings.Join(shortScopes(ts.Scopes), " "))
	if !ts.RefreshExpiry.IsZero() {
		fmt.Fprintf(stdout, "WARNING: Google says this sign-in ends at %s. The consent screen is still in Testing; set it to In production and sign in again (docs/runbooks/google.md, step 3).\n", ts.RefreshExpiry.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(stdout, "wrote the token set to %s. It holds a refresh token: import it now through the console's Secrets screen as id google-token, kind google-oauth-token, and import %s as id google-client, kind google-oauth-client; then delete both files.\n", out, clientFile)
	return 0
}
