package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestOpenPragmas(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	// Every pooled connection must carry the settings, not only the first.
	// Hold several connections at once so the pool has to open new ones.
	var conns []*sql.Conn
	for range 4 {
		c, err := d.SQL().Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	want := map[string]string{"journal_mode": "wal", "synchronous": "2", "foreign_keys": "1", "busy_timeout": "5000"}
	for i, c := range conns {
		for pragma, w := range want {
			var got string
			if err := c.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != w {
				t.Errorf("conn %d: PRAGMA %s = %q, want %q", i, pragma, got, w)
			}
		}
	}
}

func TestOpenRejectsBadPaths(t *testing.T) {
	for _, p := range []string{"", ":memory:", "file:x.db", "a?b.db", "a#b.db"} {
		if d, err := Open(context.Background(), p); err == nil {
			d.Close()
			t.Errorf("Open(%q) succeeded, want an error", p)
		}
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE parent (id INTEGER PRIMARY KEY) STRICT`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id)) STRICT`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO child (id, parent_id) VALUES (1, 99)`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("got %v, want a FOREIGN KEY constraint error", err)
	}
}

func TestImmediateCommitAndRollback(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	mustExec := func(q string) {
		t.Helper()
		err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
			_, err := tx.ExecContext(ctx, q)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		var n int
		if err := d.SQL().QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	mustExec(`CREATE TABLE t (n INTEGER) STRICT`)
	mustExec(`INSERT INTO t VALUES (1)`)

	boom := errors.New("boom")
	err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES (2)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want boom", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("rolled-back insert is visible: %d rows, want 1", n)
	}

	func() {
		defer func() {
			if r := recover(); r != "kaboom" {
				t.Fatalf("recover() = %v, want the original panic", r)
			}
		}()
		_ = d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES (3)`); err != nil {
				return err
			}
			panic("kaboom")
		})
	}()
	if n := count(); n != 1 {
		t.Fatalf("panicked insert is visible: %d rows, want 1", n)
	}
	// The pool must still work after a panic and a rollback.
	mustExec(`INSERT INTO t VALUES (4)`)
	if n := count(); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
}

func TestImmediateRollsBackOnCancelledContext(t *testing.T) {
	d := openTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE t (n INTEGER) STRICT`); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	var n int
	if err := d.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 't'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("table survived a cancelled transaction: n=%d err=%v", n, err)
	}
	// The write lock must be free again.
	if err := d.Immediate(context.Background(), func(ctx context.Context, tx *Tx) error { return nil }); err != nil {
		t.Fatalf("write lock still held: %v", err)
	}
}

// BEGIN IMMEDIATE takes the write lock at once: while one helper transaction
// is open and has written nothing, a second writer is refused.
func TestImmediateHoldsWriteLockFromTheStart(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()

	other, err := sql.Open("sqlite", d.Path()+"?_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	entered := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	c, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.ExecContext(ctx, "BEGIN IMMEDIATE")
	c.Close()
	close(release)
	wg.Wait()
	if err == nil {
		t.Fatal("second BEGIN IMMEDIATE succeeded while the helper's transaction was open")
	}
	if !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "BUSY") {
		t.Fatalf("got %v, want a busy/locked error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("refusal took %v", time.Since(start))
	}
}

func TestConcurrentWritersSerialise(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE counter (n INTEGER NOT NULL) STRICT`)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO counter VALUES (0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	const workers, each = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				// Read-then-write: only correct if the read holds the lock.
				err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
					var n int
					if err := tx.QueryRowContext(ctx, `SELECT n FROM counter`).Scan(&n); err != nil {
						return err
					}
					_, err := tx.ExecContext(ctx, `UPDATE counter SET n = ?`, n+1)
					return err
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var n int
	if err := d.SQL().QueryRow(`SELECT n FROM counter`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != workers*each {
		t.Fatalf("counter = %d, want %d: updates were lost", n, workers*each)
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE t (n INTEGER) STRICT`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO t VALUES (7)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var n int
	if err := d.SQL().QueryRow(`SELECT n FROM t`).Scan(&n); err != nil || n != 7 {
		t.Fatalf("n=%d err=%v, want 7", n, err)
	}
}

// Writers of one process queue on the gate, not in SQLite's busy handler: a
// waiter gives up when its context ends, and a transaction that starts another
// one from inside gets ErrWriteGate instead of hanging.
func TestImmediateWaitsForTheGateAndHonoursLimits(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()

	old := writeGateWait
	writeGateWait = 200 * time.Millisecond
	t.Cleanup(func() { writeGateWait = old })

	// ctx is the caller's own context, not the one the function receives, so
	// the waiters below behave like writers of other goroutines.
	err := d.Immediate(ctx, func(_ context.Context, tx *Tx) error {
		// A second writer whose context ends while it waits for the first.
		short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if err := d.Immediate(short, func(context.Context, *Tx) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waiter with an expiring context got %v, want context.DeadlineExceeded", err)
		}
		// A writer that waits longer than the gate wait gives up.
		if err := d.Immediate(ctx, func(context.Context, *Tx) error { return nil }); !errors.Is(err, ErrWriteGate) {
			t.Errorf("slow waiter got %v, want ErrWriteGate", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Neither failed waiter left the gate closed.
	if err := d.Immediate(ctx, func(context.Context, *Tx) error { return nil }); err != nil {
		t.Fatalf("gate still held: %v", err)
	}
}

// A write started from inside a running Immediate function is refused at once,
// not after the gate wait, and the outer transaction is not harmed.
func TestNestedImmediateIsRefusedAtOnce(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if d.InTransaction(ctx) {
		t.Fatal("a plain context reports a transaction")
	}
	var other *DB
	{
		var err error
		other, err = Open(ctx, filepath.Join(t.TempDir(), "other.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
	}

	start := time.Now()
	err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		if !d.InTransaction(ctx) {
			t.Error("InTransaction is false inside Immediate")
		}
		// A derived context is still marked.
		derived, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := d.Immediate(derived, func(context.Context, *Tx) error { return nil }); !errors.Is(err, ErrNestedWrite) {
			t.Errorf("nested Immediate got %v, want ErrNestedWrite", err)
		}
		// Another database has its own gate: not nested.
		if other.InTransaction(ctx) {
			t.Error("a transaction of d marks the context for another DB")
		}
		if err := other.Immediate(ctx, func(context.Context, *Tx) error { return nil }); err != nil {
			t.Errorf("Immediate on another DB from inside d's: %v", err)
		}
		_, err := tx.ExecContext(ctx, `CREATE TABLE t (n INTEGER) STRICT`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v: the nested call waited for the gate", time.Since(start))
	}
	var n int
	if err := d.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 't'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("outer transaction did not commit: n=%d err=%v", n, err)
	}
}
