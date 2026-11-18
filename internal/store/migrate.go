package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Errors returned by [DB.Migrate]. Each wraps a message that names the
// migration involved; test with errors.Is.
var (
	// ErrMigrationOrder: the migration list is not strictly ascending, or a
	// migration older than one already applied is still pending.
	ErrMigrationOrder = errors.New("store: migrations out of order")
	// ErrMigrationChecksum: an applied migration's name or SQL changed.
	ErrMigrationChecksum = errors.New("store: applied migration was edited")
	// ErrMigrationUnknown: the database has a migration this binary does not
	// contain (an older binary opened a newer database). Forward-only means
	// there is no downgrade.
	ErrMigrationUnknown = errors.New("store: database is newer than this binary")
)

// Migration is one forward-only schema change.
type Migration struct {
	Version int    // 1, 2, 3 ...; strictly ascending in a list
	Name    string // short snake_case label
	SQL     string // one or more statements, run in one transaction
}

func (m Migration) label() string { return fmt.Sprintf("%04d_%s", m.Version, m.Name) }

// checksum is the SHA-256 of the migration's name and SQL with CRLF folded to
// LF, so a Windows checkout and a Linux checkout agree.
func (m Migration) checksum() string {
	h := sha256.New()
	h.Write([]byte(m.Name))
	h.Write([]byte{0})
	h.Write([]byte(strings.ReplaceAll(m.SQL, "\r\n", "\n")))
	return hex.EncodeToString(h.Sum(nil))
}

//go:embed migrations/*.sql
var embedded embed.FS

// Migrations returns the migrations compiled into this binary, in version
// order. Tickets add a file `migrations/NNNN_name.sql`; they never edit an
// existing one.
func Migrations() ([]Migration, error) {
	return LoadMigrations(embedded, "migrations")
}

var fileName = regexp.MustCompile(`^([0-9]{4})_([a-z][a-z0-9_]*)\.sql$`)

// LoadMigrations reads `NNNN_name.sql` files from dir in fsys, sorted by
// version.
func LoadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var ms []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("store: migration file %q is not named NNNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read migration %s: %w", e.Name(), err)
		}
		ms = append(ms, Migration{Version: v, Name: m[2], SQL: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
	return ms, nil
}

// checkList rejects a list that is not usable at all, before the database is
// touched.
func checkList(ms []Migration) error {
	prev := 0
	for _, m := range ms {
		switch {
		case m.Version < 1:
			return fmt.Errorf("%w: %s has version %d, want 1 or more", ErrMigrationOrder, m.label(), m.Version)
		case m.Name == "" || strings.TrimSpace(m.SQL) == "":
			return fmt.Errorf("store: migration %d needs a name and SQL", m.Version)
		case m.Version <= prev:
			return fmt.Errorf("%w: %s follows version %d", ErrMigrationOrder, m.label(), prev)
		}
		prev = m.Version
	}
	return nil
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	sha256     TEXT NOT NULL,
	applied_at TEXT NOT NULL
) STRICT`

// Migrate brings the database up to the last migration in ms. It is
// forward-only and all-or-nothing: every pending migration runs in one
// BEGIN IMMEDIATE transaction, so a failure leaves the schema as it was.
//
// It refuses, before running anything, when:
//   - ms is not strictly ascending ([ErrMigrationOrder]);
//   - a migration older than the newest applied one is still pending
//     ([ErrMigrationOrder]);
//   - an applied migration's name or SQL differs from the recorded one
//     ([ErrMigrationChecksum]);
//   - the database holds a migration that ms does not contain
//     ([ErrMigrationUnknown]).
func (d *DB) Migrate(ctx context.Context, ms []Migration) error {
	if err := checkList(ms); err != nil {
		return err
	}
	return d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, createMigrationsTable); err != nil {
			return fmt.Errorf("store: create schema_migrations: %w", err)
		}

		type row struct{ name, sum string }
		applied := map[int]row{}
		rows, err := tx.QueryContext(ctx, `SELECT version, name, sha256 FROM schema_migrations`)
		if err != nil {
			return fmt.Errorf("store: read schema_migrations: %w", err)
		}
		maxApplied := 0
		for rows.Next() {
			var v int
			var r row
			if err := rows.Scan(&v, &r.name, &r.sum); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan schema_migrations: %w", err)
			}
			applied[v] = r
			maxApplied = max(maxApplied, v)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("store: read schema_migrations: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("store: read schema_migrations: %w", err)
		}

		known := make(map[int]Migration, len(ms))
		for _, m := range ms {
			known[m.Version] = m
		}
		for v, r := range applied {
			m, ok := known[v]
			switch {
			case !ok:
				return fmt.Errorf("%w: database has migration %04d_%s, this binary does not", ErrMigrationUnknown, v, r.name)
			case m.Name != r.name || m.checksum() != r.sum:
				return fmt.Errorf("%w: %s", ErrMigrationChecksum, m.label())
			}
		}

		for _, m := range ms {
			if _, done := applied[m.Version]; done {
				continue
			}
			if m.Version < maxApplied {
				return fmt.Errorf("%w: %s is pending but version %d is already applied", ErrMigrationOrder, m.label(), maxApplied)
			}
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return fmt.Errorf("store: apply %s: %w", m.label(), err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, sha256, applied_at) VALUES (?, ?, ?, ?)`,
				m.Version, m.Name, m.checksum(), time.Now().UTC().Format(time.RFC3339)); err != nil {
				return fmt.Errorf("store: record %s: %w", m.label(), err)
			}
			maxApplied = m.Version
		}
		return nil
	})
}

// SchemaVersion returns the highest applied migration, or 0 for a database
// that has never been migrated.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var exists int
	if err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	var v int
	if err := d.sql.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}
