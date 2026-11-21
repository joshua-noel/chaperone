package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

const vaultUsage = `usage: chapd vault init   [-db PATH] [-vault-dir D] [-vault-key-dir D] [KEY WRAPPER]
       chapd vault import --name ID --file PATH [--kind K] [--project P] [--delete] [-db PATH] [-vault-dir D] [-vault-key-dir D] [KEY WRAPPER]
       chapd vault delete --name ID [--yes] [-instance NAME] [-db PATH] [-vault-dir D] [-vault-key-dir D] [KEY WRAPPER]
       chapd vault list   [-db PATH] [-vault-dir D] [-vault-key-dir D] [KEY WRAPPER]
       chapd vault recover [-db PATH] [-vault-dir D] [-vault-key-dir D] [KEY WRAPPER]   (recovery identity on standard input)

KEY WRAPPER is [-vault-wrapper NAME] [-vault-passphrase-fd N]. It says what
protects the vault's own keys. NAME is dpapi-user (Windows, the default there),
keychain-macos (the macOS login keychain, the default there), secret-service (a
Linux keyring through secret-tool, the default there) or age-passphrase (a
passphrase, on any system; the choice for a server with no keyring). Nothing is
chosen for you if the default cannot work, and a vault opens only with the wrapper
that made it. age-passphrase asks on the terminal without echo; for a service,
-vault-passphrase-fd N reads the first line of descriptor N (0 is standard input;
not available for recover, which reads standard input itself) and the passphrase is
never taken from a flag or an environment variable. See docs/running-chapd.md.

Run as the account that runs chapd (ADR-003): the keys are bound to that account
(DPAPI scope, or that user's keychain). -vault-dir and -vault-key-dir default to "vault" and
"vault-keys" next to the database; pass the same values to chapd run.

import reads the secret from --file, stores it, and prints only its fingerprint.
For the GitHub App key (--name github-app-key) the file must be an RSA private key
in PEM form. With --delete the file is overwritten with zeros and removed once the
import has succeeded; without it the file stays and you must delete it yourself.

delete removes one secret: its file and its index row, in one step. It needs the exact
name (it refuses a name the vault does not have), shows the name, kind and import time
(never the value), and asks you to type the name on a terminal; where there is no
terminal it needs --yes. The file is removed, not overwritten: an overwrite does not
destroy the old blocks on a modern file system, so none is claimed. The deletion is
written to the ledger (op vault.delete, by the operator; -instance names the chain,
default pc). It is the way to undo a mistaken import. If chapd is running it can no
longer use the secret at once; run the same command again if it is interrupted.

recover re-keys a vault whose service identity cannot be unwrapped any more (the
account was reset or recreated). It reads the offline recovery identity from
standard input, decrypts every secret with it, then writes a new service identity,
re-encrypts each secret to it and to the same recovery recipient, and records the
new recipient. Stop chapd first. It refuses a vault that opens normally.`

func vaultCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, vaultUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("chapd vault "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, vaultUsage) }
	db := fs.String("db", defaultDB, "path of state.db")
	vaultDir := fs.String("vault-dir", "", "vault ciphertext folder (default: vault next to the database)")
	keyDir := fs.String("vault-key-dir", "", "vault wrapped-key folder (default: vault-keys next to the database)")
	var wc wrapperChoice
	wc.register(fs)
	var name, file, kind, project string
	var del, yes bool
	instance := "pc"
	switch sub {
	case "import":
		fs.StringVar(&name, "name", "", "secret id (lower-case letters, digits, - and _)")
		fs.StringVar(&file, "file", "", "file holding the secret")
		fs.StringVar(&kind, "kind", "", `secret kind (default "github-app-key" for --name github-app-key, else required)`)
		fs.StringVar(&project, "project", "", "project the secret belongs to (optional)")
		fs.BoolVar(&del, "delete", false, "overwrite and delete --file after a successful import")
	case "delete":
		fs.StringVar(&name, "name", "", "the exact id of the secret to delete")
		fs.BoolVar(&yes, "yes", false, "confirm without being asked (only where standard input is not a terminal)")
		fs.StringVar(&instance, "instance", "pc", "ledger instance (chain chaperone.<instance>)")
	case "init", "list", "recover":
	default:
		fmt.Fprintf(stderr, "chapd vault: unknown command %q\n%s\n", sub, vaultUsage)
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if sub == "recover" && wc.fdSet && wc.fd == 0 {
		fmt.Fprintln(stderr, "chapd vault recover: -vault-passphrase-fd 0 is refused: recover reads the recovery identity from standard input. Use another descriptor, or leave the flag out to be asked on the terminal")
		return 2
	}
	terminal := false
	if sub == "delete" {
		if name == "" {
			fmt.Fprintln(stderr, "chapd vault delete: --name is required")
			return 2
		}
		if err := vault.ValidID(name); err != nil {
			fmt.Fprintf(stderr, "chapd vault delete: --name %q is not a secret id: %v\n", name, err)
			return 2
		}
		terminal = vaultStdinTerminal()
		if why := deleteConfirmation(terminal, yes); why != "" {
			fmt.Fprintf(stderr, "chapd vault delete: %s\n", why)
			return 2
		}
	}
	if sub == "import" {
		if name == "" || file == "" {
			fmt.Fprintln(stderr, "chapd vault import: --name and --file are required")
			return 2
		}
		if kind == "" && name == gh.AppKeySecretID {
			kind = gh.AppKeySecretID
		}
		if kind == "" {
			fmt.Fprintln(stderr, "chapd vault import: --kind is required for a secret other than github-app-key")
			return 2
		}
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
	wrapper, err := wc.build()
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	cfg := vault.Config{Dir: *vaultDir, KeyDir: *keyDir, DB: d, Wrapper: wrapper}
	base := filepath.Dir(*db)
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(base, "vault")
	}
	if cfg.KeyDir == "" {
		cfg.KeyDir = filepath.Join(base, "vault-keys")
	}

	if sub == "recover" {
		return vaultRecover(ctx, cfg, vaultStdin, stdout, stderr)
	}

	if sub == "init" {
		if err := vault.RunInit(ctx, cfg, stdout); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		return 0
	}
	v, err := vault.Open(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer v.Close()
	if sub == "list" {
		return vaultList(ctx, v, stdout, stderr)
	}
	if sub == "delete" {
		return vaultDelete(ctx, v, cfg.Dir, d, instance, name, terminal, vaultStdin, stdout, stderr)
	}
	return vaultImport(ctx, v, vault.Meta{ID: name, Kind: kind, Project: project, Owner: "chapd vault import"}, file, del, stdout, stderr)
}

func vaultList(ctx context.Context, v *vault.Vault, stdout, stderr io.Writer) int {
	infos, err := v.List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tPROJECT\tFINGERPRINT\tCREATED\tLAST USED")
	for _, i := range infos {
		used := "never"
		if !i.LastUsed.IsZero() {
			used = localtime.RFC3339(i.LastUsed)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Kind, i.Project, i.Fingerprint, localtime.RFC3339(i.Created), used)
	}
	_ = tw.Flush()
	return 0
}

func vaultImport(ctx context.Context, v *vault.Vault, m vault.Meta, file string, del bool, stdout, stderr io.Writer) int {
	value, err := readSecretFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	defer clear(value)
	if m.Kind == gh.AppKeySecretID {
		// Refuse a wrong download before it is stored and the file deleted.
		// The parse error names no key bytes.
		if _, err := gh.ParsePrivateKeyPEM(value); err != nil {
			fmt.Fprintf(stderr, "chapd: %s is not a usable GitHub App key: %v\n", file, err)
			return 1
		}
	}
	info, err := v.Import(ctx, m, value)
	if err != nil {
		if errors.Is(err, vault.ErrExists) {
			fmt.Fprintf(stderr, "chapd: a secret named %q already exists; the file was not deleted\n", m.ID)
		} else {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
		}
		return 1
	}
	fmt.Fprintf(stdout, "imported %s (%s), fingerprint %s\n", info.ID, info.Kind, info.Fingerprint)
	if !del {
		fmt.Fprintf(stdout, "%s still exists; delete it now (or re-run with --delete next time)\n", file)
		return 0
	}
	if err := shredFile(file, int64(len(value))); err != nil {
		fmt.Fprintf(stderr, "chapd: the secret is imported, but %s could not be deleted: %v\ndelete it by hand now\n", file, err)
		return 1
	}
	fmt.Fprintf(stdout, "deleted %s\n", file)
	return 0
}

// readSecretFile reads a regular file of at most [vault.MaxSecretSize] bytes.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > vault.MaxSecretSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, vault.MaxSecretSize)
	}
	return io.ReadAll(io.LimitReader(f, vault.MaxSecretSize+1))
}

// shredFile overwrites the first size bytes of path with zeros, syncs, and
// removes it. A disk snapshot or an SSD may still hold the old blocks; this
// removes the casual copy, which is the aim.
func shredFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(make([]byte, size))
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		// Still try to remove it: an unlinked file beats a readable one.
		return errors.Join(err, os.Remove(path))
	}
	return os.Remove(path)
}
