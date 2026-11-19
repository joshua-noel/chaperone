package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/joshua-noel/chaperone/internal/store"
)

// ErrRecoveryNotNeeded is what [Recover] returns when the vault opens
// normally: the service identity is intact, so nothing is re-keyed.
var ErrRecoveryNotNeeded = errors.New("vault: the vault opens normally; nothing to recover")

// ErrWrongRecoveryIdentity is what [Recover] returns when the identity it was
// given is not the one whose public half was recorded at init.
var ErrWrongRecoveryIdentity = errors.New("vault: that is not this vault's recovery identity")

// Recover re-keys a vault whose service identity can no longer be unwrapped:
// the service account was reset or recreated, its profile was lost, or the
// vault moved to another account (ADR-003, "Loss of the server profile or reset of
// svc-chaperone"). It runs as the account that will run chapd, because the new
// keys are wrapped by cfg.Wrapper.
//
// recoveryIdentity is the "AGE-SECRET-KEY-1..." string [Init] showed once. It
// must be the identity whose public half the index records. Recover decrypts
// every secret with it first; if any file fails, nothing is changed. Then it
// writes a new service identity and a new fingerprint key, re-encrypts each
// secret to the new service recipient and to the same recovery recipient (the
// offline copy stays valid and is not shown again), recomputes every
// fingerprint under the new key, and records the new recipient in the index.
//
// The wrapped key files it replaces are moved into KeyDir/retired-<time>/, not
// deleted. A run that stops half way is repeated: both the old and the new
// ciphertext files decrypt with the recovery identity, and the index still
// names the old service recipient, so the vault still does not open and
// Recover is allowed again.
//
// Stop chapd first: it is the vault's one writer. Recover returns the number of
// secrets it re-keyed. It returns [ErrRecoveryNotNeeded] if [Open] succeeds,
// [ErrNotInitialized] if there is no vault to recover.
func Recover(ctx context.Context, cfg Config, recoveryIdentity string) (n int, err error) {
	if err := cfg.check(); err != nil {
		return 0, err
	}
	defer forgetSecrets(cfg.Wrapper)
	if err := ensureSchema(ctx, cfg.DB); err != nil {
		return 0, err
	}
	db := cfg.DB.SQL()
	if _, ok, err := metaGet(ctx, db, "service_recipient"); err != nil {
		return 0, err
	} else if !ok {
		return 0, ErrNotInitialized
	}
	recRecipient, _, err := metaGet(ctx, db, "recovery_recipient")
	if err != nil {
		return 0, err
	}
	recID, err := age.ParseX25519Identity(string(bytes.TrimSpace([]byte(recoveryIdentity))))
	if err != nil {
		return 0, fmt.Errorf("%w: it is not an age identity", ErrWrongRecoveryIdentity)
	}
	if recID.Recipient().String() != recRecipient {
		return 0, ErrWrongRecoveryIdentity
	}
	if v, oerr := open(ctx, cfg); oerr == nil {
		v.Close()
		return 0, ErrRecoveryNotNeeded
	}

	rows, err := db.QueryContext(ctx, `SELECT id FROM vault_secrets ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("vault: list secrets: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("vault: list secrets: %w", err)
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("vault: list secrets: %w", err)
	}

	// New keys first, so a wrapper that cannot round-trip fails before any
	// file is touched.
	service, err := age.GenerateX25519Identity()
	if err != nil {
		return 0, fmt.Errorf("vault: generate service identity: %w", err)
	}
	fpKey := make([]byte, fpKeyLen)
	if _, err := rand.Read(fpKey); err != nil {
		return 0, fmt.Errorf("vault: generate fingerprint key: %w", err)
	}
	defer clear(fpKey)
	serviceSecret := []byte(service.String())
	defer clear(serviceSecret)
	wrapped := make([][]byte, 2)
	for i, secret := range [][]byte{serviceSecret, fpKey} {
		w, werr := cfg.Wrapper.Wrap(secret)
		if werr != nil {
			return 0, werr
		}
		back, uerr := cfg.Wrapper.Unwrap(w)
		same := uerr == nil && bytes.Equal(back, secret)
		clear(back)
		if uerr != nil {
			return 0, uerr
		}
		if !same {
			return 0, fmt.Errorf("vault: %s wrapper round trip changed the key", cfg.Wrapper.Name())
		}
		wrapped[i] = w
	}

	// Decrypt everything with the recovery identity and stage the new files.
	recips := []age.Recipient{service.Recipient(), recID.Recipient()}
	v := &Vault{cfg: cfg, recips: recips, fpKey: fpKey}
	type staged struct{ id, tmp, fp string }
	var work []staged
	defer func() {
		for _, s := range work {
			_ = os.Remove(s.tmp) // no-op once renamed
		}
	}()
	for _, id := range ids {
		plain, derr := decryptWith(filepath.Join(cfg.Dir, id+".age"), recID)
		if derr != nil {
			return 0, fmt.Errorf("vault: recover %s: %w", id, derr)
		}
		tmp, serr := v.stage(plain)
		fp := v.fingerprint(plain)
		clear(plain)
		if serr != nil {
			return 0, serr
		}
		work = append(work, staged{id, tmp, fp})
	}

	// The key folder may be gone (a rebuilt server, or moved aside on purpose).
	if err := os.MkdirAll(cfg.KeyDir, 0o700); err != nil {
		return 0, fmt.Errorf("vault: %w", err)
	}
	// Commit: retire the dead key files, write the new ones, replace the
	// ciphertexts, then the index.
	retired := filepath.Join(cfg.KeyDir, "retired-"+cfg.now().Format("20060102T150405Z"))
	for i, name := range []string{identityFile, fpKeyFile} {
		path := filepath.Join(cfg.KeyDir, name)
		if _, err := os.Stat(path); err == nil {
			if err := os.MkdirAll(retired, 0o700); err != nil {
				return 0, fmt.Errorf("vault: %w", err)
			}
			if err := os.Rename(path, filepath.Join(retired, name)); err != nil {
				return 0, fmt.Errorf("vault: retire %s: %w", name, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("vault: %w", err)
		}
		if err := writeNew(path, wrapped[i]); err != nil {
			return 0, err
		}
	}
	for _, s := range work {
		if err := os.Rename(s.tmp, filepath.Join(cfg.Dir, s.id+".age")); err != nil {
			return 0, fmt.Errorf("vault: place %s: %w", s.id, err)
		}
	}
	err = cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, s := range work {
			if _, err := tx.ExecContext(ctx, `UPDATE vault_secrets SET fingerprint = ? WHERE id = ?`, s.fp, s.id); err != nil {
				return fmt.Errorf("vault: index %s: %w", s.id, err)
			}
		}
		for _, kv := range [][2]string{
			{"service_recipient", service.Recipient().String()},
			{"key_wrapper", cfg.Wrapper.Name()},
			{"recovered", cfg.now().Format(time.RFC3339)},
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vault_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, kv[0], kv[1]); err != nil {
				return fmt.Errorf("vault: store %s: %w", kv[0], err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(work), nil
}

// decryptWith reads one ciphertext file and decrypts it with id.
func decryptWith(path string, id age.Identity) ([]byte, error) {
	ct, err := readLimited(path, MaxSecretSize+4096)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	buf := make([]byte, 0, len(ct))
	for {
		n, rerr := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			clear(buf[:cap(buf)])
			return nil, fmt.Errorf("decrypt: %w", rerr)
		}
		if len(buf) == cap(buf) {
			clear(buf[:cap(buf)])
			return nil, fmt.Errorf("%w: plaintext larger than its ciphertext", ErrIntegrity)
		}
	}
}
