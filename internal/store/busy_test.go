package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Many writers in one process must queue, not poll: with SQLite's busy handler
// alone a writer can lose every poll for longer than busy_timeout and fail
// with SQLITE_BUSY ("database is locked"), which a ledger append under load
// then reports as ErrUnavailable.
func TestManyWritersQueueWithoutBusy(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE hits (g INTEGER NOT NULL, i INTEGER NOT NULL) STRICT`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	const writers, each, hold = 40, 10, 10 * time.Millisecond // over 5 s of work, longer than busy_timeout
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for g := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				err := d.Immediate(ctx, func(ctx context.Context, tx *Tx) error {
					time.Sleep(hold) // a commit under load
					_, err := tx.ExecContext(ctx, `INSERT INTO hits VALUES (?, ?)`, g, i)
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
		t.Error(err)
	}
	var n int
	if err := d.SQL().QueryRow(`SELECT count(*) FROM hits`).Scan(&n); err != nil || n != writers*each {
		t.Fatalf("rows = %d (%v), want %d", n, err, writers*each)
	}
}
