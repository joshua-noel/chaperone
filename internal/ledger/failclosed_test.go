package ledger

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/store"
)

// A database that refuses writes makes every append fail, so op.request is
// refused; nothing is half written and the chain continues once writes work.
func TestReadOnlyDatabaseFailsClosed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.append(3)

	// One connection, put in read-only mode: SQLite answers every write with
	// SQLITE_READONLY, as it does for a read-only file or volume.
	e.db.SQL().SetMaxOpenConns(1)
	e.exec(`PRAGMA query_only = ON`)

	if _, err := e.l.Append(ctx, opReq(10)); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Append err = %v, want ErrUnavailable", err)
	}
	err := e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := e.l.AppendTx(ctx, tx, opReq(11))
		return err
	})
	if err == nil {
		t.Error("AppendTx succeeded on a read-only database")
	}
	if err := e.l.Preflight(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Preflight err = %v, want ErrUnavailable", err)
	}
	if _, err := e.l.Anchor(ctx, "offline-copy", "x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Anchor err = %v, want ErrUnavailable", err)
	}
	e.mustVerifyClean(false)
	if rep := e.verify(false); rep.Chains[0].Events != 3 {
		t.Fatalf("%d events, want 3", rep.Chains[0].Events)
	}

	e.exec(`PRAGMA query_only = OFF`)
	if r, err := e.l.Append(ctx, opReq(12)); err != nil || r.Seq != 3 {
		t.Fatalf("append after recovery = %+v, %v", r, err)
	}
	e.mustVerifyClean(false)
}

// The same with a read-only database file: the OS refuses the write.
func TestReadOnlyFileFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.append(3)
	e.l.Close()
	e.db.Close()
	if err := os.Chmod(e.dbPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(e.dbPath, 0o644) })
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(e.dbPath + suffix); err == nil {
			os.Chmod(e.dbPath+suffix, 0o444)
			t.Cleanup(func() { os.Chmod(e.dbPath+suffix, 0o644) })
		}
	}
	if f, err := os.OpenFile(e.dbPath, os.O_WRONLY, 0); err == nil {
		// Running as a user the permission bit does not bind (root): the
		// scenario cannot be built, so prove the path another way.
		f.Close()
		t.Log("process can write a 0444 file (privileged user); read-only is covered by TestReadOnlyDatabaseFailsClosed")
		return
	}

	ctx := context.Background()
	db, err := store.Open(ctx, e.dbPath)
	if err != nil {
		return // the store itself refused to open: failed closed before any append
	}
	defer db.Close()
	l, err := Open(ctx, db, Config{Instance: "test", Redactor: redact.NewRegistry()})
	if err != nil {
		return // Open refused: also closed
	}
	defer l.Close()
	if _, err := l.Append(ctx, opReq(1)); err == nil {
		t.Fatal("append succeeded on a read-only file")
	}
	if err := l.Preflight(ctx); err == nil {
		t.Fatal("preflight passed on a read-only file")
	}
}

func TestBrokenChainStopsAppendsUntilRestart(t *testing.T) {
	ctx := context.Background()
	tamper := map[string]func(e *env){
		"tail cut off": func(e *env) {
			e.dropGuards()
			e.exec(`DELETE FROM ledger_events WHERE seq >= 7`)
		},
		"head record removed": func(e *env) {
			e.dropGuards()
			e.exec(`DELETE FROM ledger_chains`)
		},
		"head forged": func(e *env) {
			e.dropGuards()
			// Change the last hex digit to a different one. (Appending '0' left the hash
			// unchanged whenever it already ended in '0': a 1-in-16 false pass of the tamper.)
			e.exec(`UPDATE ledger_chains SET head_hash = substr(head_hash, 1, length(head_hash) - 1) ||
				CASE substr(head_hash, -1) WHEN '0' THEN '1' ELSE '0' END`)
		},
		"all events removed": func(e *env) {
			e.dropGuards()
			e.exec(`DELETE FROM ledger_events`)
		},
	}
	for name, f := range tamper {
		t.Run(name, func(t *testing.T) {
			e := seeded(t)
			f(e)
			// A running ledger refuses at its next append ...
			_, err := e.l.Append(ctx, opReq(1))
			if !errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), StopChainBroken) {
				t.Fatalf("Append err = %v", err)
			}
			// ... and stays refused, in every API, even if the damage is undone.
			if err := e.l.Preflight(ctx); !errors.Is(err, ErrChainBroken) {
				t.Errorf("Preflight err = %v", err)
			}
			if _, err := e.l.Anchor(ctx, "offline-copy", "x"); !errors.Is(err, ErrChainBroken) {
				t.Errorf("Anchor err = %v", err)
			}
			err = e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := e.l.AppendTx(ctx, tx, opReq(2))
				return err
			})
			if !errors.Is(err, ErrChainBroken) {
				t.Errorf("AppendTx err = %v", err)
			}
			// A restart does not start on a damaged ledger either.
			if l2, err := Open(ctx, e.db, Config{Instance: "test", Redactor: e.reg}); !errors.Is(err, ErrChainBroken) {
				if l2 != nil {
					l2.Close()
				}
				t.Errorf("Open err = %v", err)
			}
		})
	}
}
