// Package vault keeps Chaperone's credentials (ADR-003, ticket L1-03).
//
// One age file holds each secret, encrypted to two recipients: the service
// recipient, whose identity [KeyWrapper] (DPAPI under svc-chaperone) protects
// on disk, and an offline recovery recipient whose identity [Init] shows once
// and never stores. An index table in the state database records metadata and
// a keyed fingerprint, never a value.
//
// # Use, never read
//
// The only way to reach a value is [Vault.Use], which runs a closure that
// receives the secret and zeroes it on return. No function in this package
// returns a secret, and none of the errors it returns holds one: a closure
// error that quotes the secret is replaced by a masked copy
// ([ErrSecretInError]). Every value that enters or leaves the vault is also
// registered in the [redact.Registry], so the other output boundaries mask it.
//
// # Files and database
//
//	<Dir>/<id>.age              ciphertext, one file per secret
//	<KeyDir>/vault-identity.dpapi   age service identity, wrapped by the KeyWrapper
//	<KeyDir>/vault-fpkey.dpapi      HMAC key for fingerprints, wrapped the same way
//	state.db: vault_meta, vault_secrets
//
// The two tables are created by [Open] and [Init] with CREATE TABLE IF NOT
// EXISTS and a schema_version row, not by a store migration: the shared
// migration list is numbered by every ticket, and a second numbering source
// would collide. Folding them into internal/store/migrations is a mechanical
// change for whoever owns the final list.
//
// # Manual check: wrong account cannot decrypt
//
// The acceptance check "a blob wrapped by one account is refused for another"
// needs a second Windows user, which needs an administrator to create. The
// automated suite proves the two properties it can prove as one user (a blob
// made with other entropy is refused; the code never passes the machine-scope
// flag). To prove the account boundary by hand, once, on the server:
//
//  1. As account A (for example svc-chaperone): set CHAP_VAULT_DPAPI_WRITE to a
//     path both accounts can read and run
//     go test -run TestDPAPIWrongAccount ./internal/vault
//     It writes a wrapped blob and also checks that A unwraps it.
//  2. As account B (for example the operator's account): set
//     CHAP_VAULT_DPAPI_READ to the same path and run the same command.
//     The test passes only if Unwrap fails.
//  3. Delete the blob. Record the date and the two account names in the
//     ticket.
package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/store"
)

// MaxSecretSize is the largest value the vault stores (a PEM or a JSON token
// set is a few KiB).
const MaxSecretSize = 256 << 10

const (
	identityFile = "vault-identity.dpapi"
	fpKeyFile    = "vault-fpkey.dpapi"
	fpKeyLen     = 32
	fpBytes      = 16 // HMAC-SHA256 truncated to 128 bits, hex encoded
	schemaV      = "1"
)

// Errors. Test with errors.Is; none contains a secret value.
var (
	ErrNotInitialized     = errors.New("vault: not initialised (run the vault init command as the service account)")
	ErrAlreadyInitialized = errors.New("vault: already initialised")
	ErrNotFound           = errors.New("vault: no such secret")
	ErrExists             = errors.New("vault: secret already exists (use rotate)")
	ErrInvalid            = errors.New("vault: invalid argument")
	// ErrIntegrity: the file on disk does not match the index (replaced,
	// truncated, or an interrupted rotation). The secret is not used.
	ErrIntegrity = errors.New("vault: secret file does not match its index fingerprint")
	// ErrSecretInError: the closure passed to Use returned an error that
	// quoted a secret; the error was replaced by a masked copy.
	ErrSecretInError = errors.New("vault: error text contained a secret and was masked")
)

// Config says where the vault lives and what protects it. Dir, KeyDir, DB
// and Wrapper are required.
type Config struct {
	Dir      string           // ciphertext files, <id>.age
	KeyDir   string           // wrapped identity and fingerprint key
	DB       *store.DB        // the state database (index tables)
	Wrapper  KeyWrapper       // normally [NewDPAPI]
	Registry *redact.Registry // masks values elsewhere; nil makes a private one
	Now      func() time.Time // nil means time.Now
}

func (c Config) check() error {
	switch {
	case c.Dir == "" || c.KeyDir == "":
		return fmt.Errorf("%w: Dir and KeyDir are required", ErrInvalid)
	case c.DB == nil:
		return fmt.Errorf("%w: DB is required", ErrInvalid)
	case c.Wrapper == nil:
		return fmt.Errorf("%w: Wrapper is required", ErrInvalid)
	}
	return nil
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// Meta is what the index records about a secret.
type Meta struct {
	ID      string // lower-case letters, digits, '-' and '_'; see [ValidID]
	Kind    string // for example "github-app-key", "google-refresh-token"
	Project string // optional
	Owner   string // optional: the adapter or op class that uses it
}

// Info is Meta plus the index fields. It holds no value.
type Info struct {
	Meta
	Fingerprint string // hex HMAC-SHA256(fp key, value), truncated
	Created     time.Time
	Rotated     time.Time // zero if never rotated
	LastUsed    time.Time // zero if never used
}

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	kindRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// Windows device names are reserved with or without an extension, so
	// "con.age" cannot be created.
	reserved = regexp.MustCompile(`^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)
)

// ValidID checks a secret id. Ids become file names, so the alphabet is
// narrow: no dots, separators, or Windows device names.
func ValidID(id string) error {
	if !idRe.MatchString(id) || reserved.MatchString(id) {
		return fmt.Errorf("%w: secret id must match %s and not be a Windows device name", ErrInvalid, idRe)
	}
	return nil
}

func (m Meta) check() error {
	if err := ValidID(m.ID); err != nil {
		return err
	}
	if !kindRe.MatchString(m.Kind) {
		return fmt.Errorf("%w: kind must match %s", ErrInvalid, kindRe)
	}
	for name, v := range map[string]string{"project": m.Project, "owner": m.Owner} {
		if len(v) > 128 || strings.ContainsFunc(v, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return fmt.Errorf("%w: %s is too long or has control characters", ErrInvalid, name)
		}
	}
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS vault_meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vault_secrets (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	project     TEXT NOT NULL,
	owner       TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	created     TEXT NOT NULL,
	rotated     TEXT,
	last_used   TEXT
) STRICT;
INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('schema_version', '` + schemaV + `');
`

func ensureSchema(ctx context.Context, db *store.DB) error {
	return db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return fmt.Errorf("vault: create index tables: %w", err)
		}
		var got string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = 'schema_version'`).Scan(&got); err != nil {
			return fmt.Errorf("vault: read schema version: %w", err)
		}
		if got != schemaV {
			return fmt.Errorf("vault: index schema version %q, this binary knows %q", got, schemaV)
		}
		return nil
	})
}

func metaGet(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("vault: read %s: %w", key, err)
	}
	return v, true, nil
}

// Init creates a new vault: a service identity wrapped by cfg.Wrapper, an
// HMAC key for fingerprints, and an offline recovery identity. Only the
// recovery identity's public half is stored.
//
// reveal receives the recovery identity (an "AGE-SECRET-KEY-1..." string)
// before anything is committed. If reveal returns an error Init discards
// everything and returns that error, so a recovery identity the operator
// never saw is never relied on. No other function returns it, and it is
// never written to disk, the database or a log.
//
// Init runs as the account that will run chapd, because the wrapper binds the
// keys to it. It refuses an existing vault ([ErrAlreadyInitialized]).
func Init(ctx context.Context, cfg Config, reveal func(recoveryIdentity string) error) (err error) {
	if err := cfg.check(); err != nil {
		return err
	}
	if reveal == nil {
		return fmt.Errorf("%w: reveal is required", ErrInvalid)
	}
	if err := ensureSchema(ctx, cfg.DB); err != nil {
		return err
	}
	idPath, fpPath := filepath.Join(cfg.KeyDir, identityFile), filepath.Join(cfg.KeyDir, fpKeyFile)
	if _, ok, err := metaGet(ctx, cfg.DB.SQL(), "service_recipient"); err != nil {
		return err
	} else if ok {
		return ErrAlreadyInitialized
	}
	for _, p := range []string{idPath, fpPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%w: %s exists without an index; move it away only if no secret was ever stored", ErrAlreadyInitialized, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault: %w", err)
		}
	}
	for _, d := range []string{cfg.Dir, cfg.KeyDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	service, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("vault: generate service identity: %w", err)
	}
	recovery, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("vault: generate recovery identity: %w", err)
	}
	fpKey := make([]byte, fpKeyLen)
	if _, err := rand.Read(fpKey); err != nil {
		return fmt.Errorf("vault: generate fingerprint key: %w", err)
	}
	defer clear(fpKey)
	serviceSecret := []byte(service.String())
	defer clear(serviceSecret)

	var written []string
	defer func() {
		if err != nil {
			for _, p := range written {
				_ = os.Remove(p)
			}
		}
	}()
	for _, w := range []struct {
		path   string
		secret []byte
	}{{idPath, serviceSecret}, {fpPath, fpKey}} {
		wrapped, werr := cfg.Wrapper.Wrap(w.secret)
		if werr != nil {
			return werr
		}
		// Prove the wrapper round-trips before the operator is asked to
		// trust it with the only copy.
		back, uerr := cfg.Wrapper.Unwrap(wrapped)
		same := uerr == nil && bytes.Equal(back, w.secret)
		clear(back)
		if uerr != nil {
			return uerr
		}
		if !same {
			return fmt.Errorf("vault: %s wrapper round trip changed the key", cfg.Wrapper.Name())
		}
		if werr := writeNew(w.path, wrapped); werr != nil {
			return werr
		}
		written = append(written, w.path)
	}

	if err := reveal(recovery.String()); err != nil {
		return err
	}

	return cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, kv := range [][2]string{
			{"service_recipient", service.Recipient().String()},
			{"recovery_recipient", recovery.Recipient().String()},
			{"key_wrapper", cfg.Wrapper.Name()},
			{"initialised", cfg.now().Format(time.RFC3339)},
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vault_meta (key, value) VALUES (?, ?)`, kv[0], kv[1]); err != nil {
				return fmt.Errorf("vault: store %s: %w", kv[0], err)
			}
		}
		return nil
	})
}

// writeNew writes data to path through a temp file and refuses to replace an
// existing file.
func writeNew(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful link
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault: close %s: %w", path, err)
	}
	if err := os.Link(name, path); err != nil {
		return fmt.Errorf("vault: create %s: %w", path, err)
	}
	return nil
}

// RunInit is the body of the "vault init" command: it runs [Init] and prints
// the recovery identity once to out, with the instructions for the offline
// copy. A failed write to out aborts the init.
func RunInit(ctx context.Context, cfg Config, out io.Writer) error {
	var recipient string
	err := Init(ctx, cfg, func(identity string) error {
		r, err := age.ParseX25519Identity(identity)
		if err != nil {
			return err
		}
		recipient = r.Recipient().String()
		_, err = fmt.Fprintf(out, `Chaperone vault initialised.

RECOVERY IDENTITY - shown once, not stored anywhere on the server:

  %s

Copy it to the offline place now (print it, or write it to a USB drive in the
safe). Anyone who holds it can decrypt every secret in the vault; if you lose
it and the server's service profile breaks, the secrets cannot be recovered.

Recovery recipient (public half, stored in the index): %s
`, identity, recipient)
		return err
	})
	return err
}

// Vault is an open vault. Methods are safe for concurrent use.
type Vault struct {
	cfg      Config
	reg      *redact.Registry
	identity *age.X25519Identity
	recips   []age.Recipient
	fpKey    []byte
	// mu keeps a Use from reading a file between a rotation's rename and
	// its index commit. It guards this process only; chapd is the one writer.
	mu sync.RWMutex
}

// Open loads the service identity (through cfg.Wrapper) and the fingerprint
// key. It fails with [ErrNotInitialized] before [Init], and when the wrapper
// is not the one the vault was created with, the identity file does not match
// the recorded recipient, or the wrapper cannot unwrap (wrong account).
func Open(ctx context.Context, cfg Config) (*Vault, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := ensureSchema(ctx, cfg.DB); err != nil {
		return nil, err
	}
	db := cfg.DB.SQL()
	svc, ok, err := metaGet(ctx, db, "service_recipient")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotInitialized
	}
	rec, _, err := metaGet(ctx, db, "recovery_recipient")
	if err != nil {
		return nil, err
	}
	wrapperName, _, err := metaGet(ctx, db, "key_wrapper")
	if err != nil {
		return nil, err
	}
	if wrapperName != cfg.Wrapper.Name() {
		return nil, fmt.Errorf("vault: created with key wrapper %q, opened with %q", wrapperName, cfg.Wrapper.Name())
	}

	idSecret, err := unwrapFile(cfg.Wrapper, filepath.Join(cfg.KeyDir, identityFile))
	if err != nil {
		return nil, err
	}
	defer clear(idSecret)
	identity, err := age.ParseX25519Identity(string(bytes.TrimSpace(idSecret)))
	if err != nil {
		return nil, errors.New("vault: the service identity file does not hold an age identity")
	}
	if identity.Recipient().String() != svc {
		return nil, fmt.Errorf("%w: service identity does not match the recipient recorded at init", ErrIntegrity)
	}
	recovery, err := age.ParseX25519Recipient(rec)
	if err != nil {
		return nil, fmt.Errorf("vault: recorded recovery recipient is invalid: %w", err)
	}
	fpKey, err := unwrapFile(cfg.Wrapper, filepath.Join(cfg.KeyDir, fpKeyFile))
	if err != nil {
		return nil, err
	}
	if len(fpKey) != fpKeyLen {
		clear(fpKey)
		return nil, fmt.Errorf("%w: fingerprint key has the wrong length", ErrIntegrity)
	}

	reg := cfg.Registry
	if reg == nil {
		reg = redact.NewRegistry()
	}
	return &Vault{
		cfg:      cfg,
		reg:      reg,
		identity: identity,
		recips:   []age.Recipient{identity.Recipient(), recovery},
		fpKey:    fpKey,
	}, nil
}

func unwrapFile(w KeyWrapper, path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	plain, err := w.Unwrap(blob)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// Close zeroes the fingerprint key. The vault is unusable afterwards.
func (v *Vault) Close() { clear(v.fpKey) }

// Registry returns the redaction registry the vault feeds.
func (v *Vault) Registry() *redact.Registry { return v.reg }

func (v *Vault) fingerprint(value []byte) string {
	m := hmac.New(sha256.New, v.fpKey)
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil)[:fpBytes])
}

func (v *Vault) path(id string) string { return filepath.Join(v.cfg.Dir, id+".age") }

// stage encrypts value to both recipients in a temp file inside the vault
// directory and returns its name. The caller renames or removes it.
func (v *Vault) stage(value []byte) (string, error) {
	f, err := os.CreateTemp(v.cfg.Dir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("vault: encrypt: %w", err)
	}
	w, err := age.Encrypt(f, v.recips...)
	if err != nil {
		return fail(err)
	}
	if _, err := w.Write(value); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("vault: %w", err)
	}
	return name, nil
}

func checkValue(value []byte) error {
	switch {
	case len(value) < redact.MinExactLen:
		return fmt.Errorf("%w: a secret shorter than %d bytes cannot be redacted safely", ErrInvalid, redact.MinExactLen)
	case len(value) > MaxSecretSize:
		return fmt.Errorf("%w: a secret is at most %d bytes", ErrInvalid, MaxSecretSize)
	}
	return nil
}

// Import stores a new secret. It fails with [ErrExists] if the id is taken;
// change a value with [Vault.Rotate]. The vault keeps no reference to value.
func (v *Vault) Import(ctx context.Context, m Meta, value []byte) (Info, error) {
	if err := m.check(); err != nil {
		return Info{}, err
	}
	if err := checkValue(value); err != nil {
		return Info{}, err
	}
	staged, err := v.stage(value)
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(staged) // no-op once renamed

	info := Info{Meta: m, Fingerprint: v.fingerprint(value), Created: v.cfg.now()}
	v.mu.Lock()
	err = v.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO vault_secrets (id, kind, project, owner, fingerprint, created) VALUES (?, ?, ?, ?, ?, ?)`,
			m.ID, m.Kind, m.Project, m.Owner, info.Fingerprint, info.Created.Format(time.RFC3339Nano))
		if err != nil {
			var n int
			if tx.QueryRowContext(ctx, `SELECT count(*) FROM vault_secrets WHERE id = ?`, m.ID).Scan(&n) == nil && n > 0 {
				return ErrExists
			}
			return fmt.Errorf("vault: index %s: %w", m.ID, err)
		}
		// A file with no index row is an orphan from an interrupted import;
		// the rename replaces it.
		if err := os.Rename(staged, v.path(m.ID)); err != nil {
			return fmt.Errorf("vault: place %s: %w", m.ID, err)
		}
		return nil
	})
	v.mu.Unlock()
	if err != nil {
		return Info{}, err
	}
	if err := v.reg.Set(m.ID, value); err != nil {
		return Info{}, err
	}
	return info, nil
}

// Rotate replaces the value of an existing secret. The old ciphertext file is
// replaced in place, so a failed index commit after the rename leaves a
// mismatch that [Vault.Use] reports as [ErrIntegrity]; repeat the rotation to
// repair it.
func (v *Vault) Rotate(ctx context.Context, id string, value []byte) (Info, error) {
	if err := ValidID(id); err != nil {
		return Info{}, err
	}
	if err := checkValue(value); err != nil {
		return Info{}, err
	}
	staged, err := v.stage(value)
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(staged)

	fp, now := v.fingerprint(value), v.cfg.now()
	v.mu.Lock()
	err = v.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE vault_secrets SET fingerprint = ?, rotated = ? WHERE id = ?`,
			fp, now.Format(time.RFC3339Nano), id)
		if err != nil {
			return fmt.Errorf("vault: index %s: %w", id, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if err := os.Rename(staged, v.path(id)); err != nil {
			return fmt.Errorf("vault: place %s: %w", id, err)
		}
		return nil
	})
	v.mu.Unlock()
	if err != nil {
		return Info{}, err
	}
	if err := v.reg.Set(id, value); err != nil {
		return Info{}, err
	}
	return v.Info(ctx, id)
}

const infoCols = `id, kind, project, owner, fingerprint, created, rotated, last_used`

type scanner interface{ Scan(...any) error }

func scanInfo(s scanner) (Info, error) {
	var i Info
	var created string
	var rotated, used sql.NullString
	if err := s.Scan(&i.ID, &i.Kind, &i.Project, &i.Owner, &i.Fingerprint, &created, &rotated, &used); err != nil {
		return Info{}, err
	}
	var err error
	if i.Created, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return Info{}, fmt.Errorf("vault: index row %s: %w", i.ID, err)
	}
	if rotated.Valid {
		if i.Rotated, err = time.Parse(time.RFC3339Nano, rotated.String); err != nil {
			return Info{}, fmt.Errorf("vault: index row %s: %w", i.ID, err)
		}
	}
	if used.Valid {
		if i.LastUsed, err = time.Parse(time.RFC3339Nano, used.String); err != nil {
			return Info{}, fmt.Errorf("vault: index row %s: %w", i.ID, err)
		}
	}
	return i, nil
}

// Info returns the metadata of one secret (never its value).
func (v *Vault) Info(ctx context.Context, id string) (Info, error) {
	if err := ValidID(id); err != nil {
		return Info{}, err
	}
	i, err := scanInfo(v.cfg.DB.SQL().QueryRowContext(ctx, `SELECT `+infoCols+` FROM vault_secrets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Info{}, ErrNotFound
	}
	return i, err
}

// List returns the metadata of every secret, ordered by id.
func (v *Vault) List(ctx context.Context) ([]Info, error) {
	rows, err := v.cfg.DB.SQL().QueryContext(ctx, `SELECT `+infoCols+` FROM vault_secrets ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("vault: list: %w", err)
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		i, err := scanInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// decrypt returns the plaintext of id in a buffer the caller must zero, after
// checking it against the indexed fingerprint. The buffer is sized from the
// ciphertext, so it is never regrown (a regrow would leave an unzeroed copy).
func (v *Vault) decrypt(ctx context.Context, id string) (buf []byte, info Info, err error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	info, err = v.Info(ctx, id)
	if err != nil {
		return nil, Info{}, err
	}
	ct, err := readLimited(v.path(id), MaxSecretSize+4096)
	if err != nil {
		return nil, Info{}, err
	}
	r, err := age.Decrypt(bytes.NewReader(ct), v.identity)
	if err != nil {
		return nil, Info{}, fmt.Errorf("vault: decrypt %s: %w", id, err)
	}
	buf = make([]byte, 0, len(ct))
	defer func() {
		if err != nil {
			clear(buf[:cap(buf)])
			buf = nil
		}
	}()
	for {
		n, rerr := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return buf, Info{}, fmt.Errorf("vault: decrypt %s: %w", id, rerr)
		}
		if len(buf) == cap(buf) {
			return buf, Info{}, fmt.Errorf("%w: %s is larger than its ciphertext", ErrIntegrity, id)
		}
	}
	if !hmac.Equal([]byte(v.fingerprint(buf)), []byte(info.Fingerprint)) {
		return buf, Info{}, fmt.Errorf("%w: %s", ErrIntegrity, id)
	}
	return buf, info, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: file for %s is missing", ErrIntegrity, filepath.Base(path))
	}
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", filepath.Base(path), err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s is larger than the vault allows", ErrIntegrity, filepath.Base(path))
	}
	return b, nil
}

// Use runs fn with the secret id and zeroes the buffer when fn returns or
// panics. fn MUST NOT keep, copy or return the slice; it belongs to an
// adapter that sends the value to its one destination (GitHub, Google, ntfy,
// the grant signer).
//
// Use records last_used before it calls fn and fails closed if it cannot. A
// secret is never used when its file no longer matches the index
// ([ErrIntegrity]). An error from fn comes back wrapped (errors.Is keeps
// working); if its text contains the secret, a masked copy that wraps nothing
// and matches [ErrSecretInError] is returned instead.
func (v *Vault) Use(ctx context.Context, id string, fn func(secret []byte) error) error {
	if fn == nil {
		return fmt.Errorf("%w: fn is required", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidID(id); err != nil {
		return err
	}
	buf, _, err := v.decrypt(ctx, id)
	if err != nil {
		return err
	}
	defer clear(buf[:cap(buf)])
	if err := v.reg.Set(id, buf); err != nil {
		return err
	}
	if err := v.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE vault_secrets SET last_used = ? WHERE id = ?`,
			v.cfg.now().Format(time.RFC3339Nano), id)
		return err
	}); err != nil {
		return fmt.Errorf("vault: record use of %s: %w", id, err)
	}

	if err := fn(buf); err != nil {
		msg, res := v.reg.Redact(err.Error())
		if res.Blocked() {
			return &maskedError{id: id, msg: msg}
		}
		return fmt.Errorf("vault: use %s: %w", id, err)
	}
	return nil
}

type maskedError struct{ id, msg string }

func (e *maskedError) Error() string        { return fmt.Sprintf("vault: use %s: %s", e.id, e.msg) }
func (e *maskedError) Is(target error) bool { return target == ErrSecretInError }

// LoadRegistry decrypts every secret once and registers it for redaction.
// Call it at start-up: after a restart the registry is empty until a secret
// is imported, rotated or used. It does not touch last_used.
func (v *Vault) LoadRegistry(ctx context.Context) error {
	infos, err := v.List(ctx)
	if err != nil {
		return err
	}
	for _, i := range infos {
		buf, _, err := v.decrypt(ctx, i.ID)
		if err != nil {
			return err
		}
		err = v.reg.Set(i.ID, buf)
		clear(buf[:cap(buf)])
		if err != nil {
			return err
		}
	}
	return nil
}
