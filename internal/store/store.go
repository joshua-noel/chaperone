// Package store opens Chaperone's one SQLite database and gives every ticket
// the same three guarantees (ADR-006):
//
//   - durability: WAL with synchronous=FULL, so a committed row survives a
//     power cut;
//   - integrity: foreign keys are on for every connection;
//   - serialised writes: [DB.Immediate] queues the writers of this process
//     first-come first-served, then takes the write lock when the transaction
//     starts (BEGIN IMMEDIATE), so a state change and its ledger event commit
//     together or not at all, never fail late with a lock upgrade error, and
//     never starve behind SQLite's polling busy handler.
//
// The driver is modernc.org/sqlite, pure Go, so every binary builds with
// CGO_ENABLED=0 (ADR-001).
package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// busyTimeoutMS is how long a connection waits for a lock held by another
// connection (another process, or a reader's checkpoint) before it returns
// SQLITE_BUSY.
const busyTimeoutMS = 5000

// writeGateWait is how long [DB.Immediate] waits for the writers ahead of it
// in this process. A transaction that calls Immediate (or Ledger.Append) from
// inside another one can never be served; this turns that mistake into an
// error instead of a hang.
var writeGateWait = 30 * time.Second

// ErrWriteGate is returned by [DB.Immediate] when the writers ahead of it did
// not finish within [writeGateWait].
var ErrWriteGate = errors.New("store: timed out waiting for the other writers in this process")

// ErrNestedWrite is returned by [DB.Immediate] (and by Ledger.Append) when it
// is called with the context of a running [DB.Immediate] function: the outer
// transaction holds the write gate, so the inner one could never start. Use the
// outer transaction's [Tx] (Ledger.AppendTx) instead.
var ErrNestedWrite = errors.New("store: write transaction started inside another write transaction")

// txHeld marks the context passed to an [DB.Immediate] function with the DB
// whose write gate that function holds.
type txHeld struct{ db *DB }

// InTransaction reports whether ctx belongs to a running [DB.Immediate]
// function of d, that is, whether a new write from it would wait on itself.
func (d *DB) InTransaction(ctx context.Context) bool {
	h, _ := ctx.Value(txHeld{d}).(*DB)
	return h == d
}

// DB is an open Chaperone database.
type DB struct {
	sql  *sql.DB
	path string
	// gate admits one writer of this process at a time. SQLite's busy handler
	// polls with growing sleeps and has no queue, so with many in-process
	// writers one of them can lose every poll for longer than busyTimeoutMS and
	// fail with SQLITE_BUSY (seen under load as a flaky ledger test). A channel
	// is used, not a mutex, so a waiting writer still honours its context.
	gate chan struct{}
}

// Open opens (creating it if needed) the SQLite file at path and checks that
// the durability and integrity settings took effect on a live connection.
// It does not migrate: call [DB.Migrate] next.
func Open(ctx context.Context, path string) (*DB, error) {
	switch {
	case path == "":
		return nil, errors.New("store: empty database path")
	case path == ":memory:" || strings.HasPrefix(path, "file:"):
		return nil, fmt.Errorf("store: %q is not a plain file path (WAL needs a file)", path)
	case strings.ContainsAny(path, "?#"):
		return nil, fmt.Errorf("store: database path %q contains '?' or '#'", path)
	}

	// Owner-only files on Unix (a no-op on Windows). Done before SQLite creates
	// anything, so the -wal and -shm files it makes inherit the mode.
	if err := prepareDBFile(path); err != nil {
		return nil, err
	}

	// busy_timeout comes first so the journal_mode switch waits for a lock
	// instead of failing. database/sql opens many connections; the DSN
	// applies every pragma to each of them.
	dsn := path + "?_pragma=busy_timeout(" + fmt.Sprint(busyTimeoutMS) + ")" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(ON)"

	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	d := &DB{sql: sdb, path: path, gate: make(chan struct{}, 1)}
	if err := d.verifyPragmas(ctx); err != nil {
		_ = sdb.Close()
		return nil, err
	}
	if err := restrictSidecars(path); err != nil {
		_ = sdb.Close()
		return nil, err
	}
	return d, nil
}

// verifyPragmas fails closed if SQLite did not honour a required setting.
func (d *DB) verifyPragmas(ctx context.Context) error {
	want := []struct {
		pragma string
		value  string
	}{
		{"journal_mode", "wal"},
		{"synchronous", "2"}, // 2 = FULL
		{"foreign_keys", "1"},
	}
	for _, w := range want {
		var got string
		if err := d.sql.QueryRowContext(ctx, "PRAGMA "+w.pragma).Scan(&got); err != nil {
			return fmt.Errorf("store: read PRAGMA %s on %s: %w", w.pragma, d.path, err)
		}
		if strings.ToLower(got) != w.value {
			return fmt.Errorf("store: PRAGMA %s is %q on %s, want %q", w.pragma, got, d.path, w.value)
		}
	}
	return nil
}

// Close closes the database. SQLite checkpoints the WAL when the last
// connection closes.
func (d *DB) Close() error { return d.sql.Close() }

// Path returns the file path the database was opened with.
func (d *DB) Path() string { return d.path }

// SQL returns the connection pool for reads. Writes MUST go through
// [DB.Immediate] so they hold the write lock from the first statement.
func (d *DB) SQL() *sql.DB { return d.sql }

// Tx is the handle passed to the function given to [DB.Immediate]. It runs
// statements on the one connection that holds the write lock.
type Tx struct{ c *sql.Conn }

// ExecContext runs a statement inside the transaction.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.c.ExecContext(ctx, query, args...)
}

// QueryContext runs a query inside the transaction.
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.c.QueryContext(ctx, query, args...)
}

// QueryRowContext runs a single-row query inside the transaction.
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.c.QueryRowContext(ctx, query, args...)
}

// Immediate runs fn inside a BEGIN IMMEDIATE transaction. It commits if fn
// returns nil and rolls back if fn returns an error or panics (the panic then
// continues). The write lock is taken before fn runs, so fn never sees a
// stale read followed by a failed upgrade.
//
// Writers of this process run one at a time in arrival order, so contention
// between them never reaches SQLite's busy handler. A writer that waits longer
// than [writeGateWait] gets [ErrWriteGate]; one whose ctx ends first gets the
// ctx error. Calling Immediate with the context fn received (or one derived
// from it) returns [ErrNestedWrite] at once.
//
// fn MUST NOT issue BEGIN, COMMIT or ROLLBACK itself, and MUST NOT call
// Immediate again (a second transaction would wait for the first).
func (d *DB) Immediate(ctx context.Context, fn func(ctx context.Context, tx *Tx) error) (err error) {
	if d.InTransaction(ctx) {
		return ErrNestedWrite
	}
	timer := time.NewTimer(writeGateWait)
	select {
	case d.gate <- struct{}{}:
		timer.Stop()
	case <-ctx.Done():
		timer.Stop()
		return fmt.Errorf("store: wait for write gate: %w", ctx.Err())
	case <-timer.C:
		return ErrWriteGate
	}
	defer func() { <-d.gate }()

	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: get connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("store: begin immediate: %w", err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		// The caller's context may be the reason we are here, so the
		// rollback must not depend on it.
		if _, rbErr := conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK"); rbErr != nil {
			// The transaction is still open on this connection. Make
			// database/sql discard the connection instead of pooling it.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("store: rollback: %w", rbErr))
		}
	}()

	if err := fn(context.WithValue(ctx, txHeld{d}, d), &Tx{c: conn}); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}
