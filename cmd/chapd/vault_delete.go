package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// vaultStdinTerminal says whether `chapd vault delete` has a person at a
// terminal to ask. Tests replace it.
var vaultStdinTerminal = func() bool { return vault.IsTerminal(os.Stdin) }

// deleteConfirmation is the rule for the one question of `chapd vault delete`:
// on a terminal the person types the name; anywhere else (a script, a pipe)
// only --yes confirms, and on a terminal --yes is refused so that a person is
// always asked. It returns a usage error text, or "".
func deleteConfirmation(terminal, yes bool) string {
	switch {
	case terminal && yes:
		return "--yes is for scripts. On a terminal you are asked to type the name; run the command again without --yes"
	case !terminal && !yes:
		return "this is not a terminal, so there is nobody to ask. Add --yes to delete without being asked"
	}
	return ""
}

// vaultDelete is `chapd vault delete`: it shows what will be removed, asks for
// the name to be typed (or takes --yes), and removes the secret and records it.
// It never prints a value, and it has none: the vault is opened for its index
// and folder, and the secret is not decrypted.
func vaultDelete(ctx context.Context, v *vault.Vault, vaultDir string, db *store.DB, instance, name string, terminal bool, in io.Reader, stdout, stderr io.Writer) int {
	info, err := v.Info(ctx, name)
	if errors.Is(err, vault.ErrNotFound) {
		fmt.Fprintf(stderr, "chapd: the vault has no secret named %q. Nothing was deleted. `chapd vault list` shows the names\n", name)
		if _, serr := os.Lstat(filepath.Join(vaultDir, name+".age")); serr == nil {
			fmt.Fprintf(stderr, "(%s is in the vault folder with no index row: a leftover of an interrupted import. chapd does not use it. Delete that file by hand if you want it gone)\n", name+".age")
		}
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}

	// The ledger is opened before the person is asked: a command that cannot be
	// recorded is refused, not half done.
	led, err := openOperatorLedger(ctx, db, instance, v.Registry())
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v. Nothing was deleted\n", err)
		return 1
	}
	defer led.Close()

	fmt.Fprintf(stdout, "This will remove one secret from the vault:\n  name:      %s\n  kind:      %s\n", info.ID, info.Kind)
	if info.Project != "" {
		fmt.Fprintf(stdout, "  project:   %s\n", info.Project)
	}
	fmt.Fprintf(stdout, "  imported:  %s\n\n", localtime.RFC3339(info.Created))
	fmt.Fprint(stdout, "The file is removed, not overwritten. On a modern file system an overwrite does not destroy the old blocks\n"+
		"(journals, copy-on-write, SSD wear levelling, snapshots), so none is attempted and none is claimed.\n"+
		"If the secret may have leaked, revoke it where it came from as well.\n"+
		"If chapd is running, it can no longer use this secret from now on.\n\n")

	if terminal {
		fmt.Fprint(stdout, "Type the name to confirm: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimRight(line, "\r\n") != info.ID {
			fmt.Fprintln(stderr, "\nchapd: the name was not typed exactly. Nothing was deleted")
			return 1
		}
	}

	body := fmt.Sprintf("operator deleted vault secret %s (kind %s, imported %s) with chapd vault delete", info.ID, info.Kind, info.Created.UTC().Format("2006-01-02T15:04:05Z"))
	_, err = v.Delete(ctx, name, func(ctx context.Context, tx *store.Tx, i vault.Info) error {
		return led.appendTx(ctx, tx, operatorOp{
			Op: "vault.delete", Ref: "vault:" + i.ID, Reversibility: "irreversible", Body: body,
			Params: map[string]any{"name": i.ID, "kind": i.Kind, "created": i.Created.UTC().Format("2006-01-02T15:04:05Z")},
		})
	})
	switch {
	case errors.Is(err, vault.ErrNotFound):
		fmt.Fprintf(stderr, "\nchapd: the secret %q is gone already (another command removed it). Nothing more to do\n", name)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "\nchapd: could not delete %q: %v\nThe secret may be half removed: chapd refuses a secret whose file is missing. Run `chapd vault delete --name %s` again to finish, or `chapd vault list` to see what is left\n", name, err, name)
		return 1
	}
	fmt.Fprintf(stdout, "\ndeleted %s (%s); the vault file and its index row are gone and the ledger has the record\n", info.ID, info.Kind)
	return 0
}
