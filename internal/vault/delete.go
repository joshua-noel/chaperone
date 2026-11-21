package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/joshua-noel/chaperone/internal/store"
)

// DeleteRecorder is called by [Vault.Delete] inside the database transaction
// that removes the index row, before anything is removed from disk. A caller
// uses it to write the ledger event in the same transaction: if it returns an
// error nothing is deleted and nothing is recorded. info is the metadata of
// the secret about to go; it holds no value.
type DeleteRecorder func(ctx context.Context, tx *store.Tx, info Info) error

// Delete removes a secret: its index row and its ciphertext file.
//
// Order, so a crash fails closed. Inside one write transaction the row is
// deleted, record runs, and only then is the file removed; the transaction
// commits last.
//
//   - A crash or error before the file is removed rolls the whole transaction
//     back: the secret is whole and was not recorded as deleted.
//   - A crash or failed commit after the file is removed rolls the row back
//     but not the file. The index then names a secret whose file is gone. That
//     is never a valid secret: [Vault.Use] reports [ErrIntegrity] and uses
//     nothing, and the same Delete, run again, finishes the job (a missing file
//     is not an error there).
//
// No state exists in which a file without a row, or a row that is trusted
// without its file, was left by Delete. Delete removes the file by name; it
// does not overwrite it first. On a journalled or copy-on-write file system, an
// SSD or a snapshot, overwriting does not destroy the old blocks, so Delete
// does not pretend to: the ciphertext is gone from the folder, and anyone who
// holds both the vault folder's old blocks and the service or recovery
// identity could still read it. If that matters, rotate the secret at its
// source (revoke the key or token) as well.
//
// A missing id is [ErrNotFound]. The caller (chapd) may still be running on
// the same database: it fails closed on this secret from the moment the row or
// the file is gone.
func (v *Vault) Delete(ctx context.Context, id string, record DeleteRecorder) (Info, error) {
	if err := ValidID(id); err != nil {
		return Info{}, err
	}
	var info Info
	v.mu.Lock()
	defer v.mu.Unlock()
	err := v.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		info, err = scanInfo(tx.QueryRowContext(ctx, `SELECT `+infoCols+` FROM vault_secrets WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM vault_secrets WHERE id = ?`, id); err != nil {
			return fmt.Errorf("vault: remove the index row of %s: %w", id, err)
		}
		if record != nil {
			if err := record(ctx, tx, info); err != nil {
				return err
			}
		}
		if err := v.deleteHook("index-deleted"); err != nil {
			return err
		}
		if err := os.Remove(v.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: remove the file of %s: %w", id, err)
		}
		return v.deleteHook("file-removed")
	})
	if err != nil {
		return Info{}, err
	}
	v.reg.Remove(id)
	return info, nil
}

// deleteHook is the crash point of a test: a non-nil error from it stands for
// the process stopping at that stage. It is nil in the program.
func (v *Vault) deleteHook(stage string) error {
	if v.afterDeleteStep == nil {
		return nil
	}
	return v.afterDeleteStep(stage)
}
