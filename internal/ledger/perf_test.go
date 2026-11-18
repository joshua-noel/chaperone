package ledger

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// TestTenThousandEvents runs the L1-02 workload (10,000 appends, then a full
// verify) three ways and logs the times; run with -v to read them. It asserts
// correctness, not speed: wall time depends on the disk's fsync latency and on
// what else the machine is doing, so a hard limit would flake. The target is
// 5 s; the PR records what was measured.
func TestTenThousandEvents(t *testing.T) {
	const n = 10000
	ctx := context.Background()

	run := func(name string, appendAll func(e *env)) time.Duration {
		e := newEnv(t)
		start := time.Now()
		appendAll(e)
		appended := time.Since(start)
		vstart := time.Now()
		rep := e.verify(false)
		verified := time.Since(vstart)
		if !rep.OK() || rep.Chains[0].Events != n {
			t.Fatalf("%s: %d events, %v", name, rep.Chains[0].Events, rep.Err())
		}
		t.Logf("%-34s append %8v  verify %8v  total %8v", name, appended.Round(time.Millisecond), verified.Round(time.Millisecond), (appended + verified).Round(time.Millisecond))
		return appended + verified
	}

	// 50 goroutines through Append: the writer groups them (one fsync per group).
	run("Append x50 goroutines (grouped)", func(e *env) {
		var wg sync.WaitGroup
		for g := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range n / 50 {
					if _, err := e.l.Append(ctx, opReq(g*1000+i)); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()
	})

	// One transaction per event, each fsynced: the worst case, an op at a time.
	run("Append, one caller (fsync each)", func(e *env) {
		for i := range n {
			if _, err := e.l.Append(ctx, opReq(i)); err != nil {
				t.Fatal(err)
			}
		}
	})

	// One caller transaction holding all events.
	run("AppendTx, one transaction", func(e *env) {
		err := e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			for i := range n {
				if _, err := e.l.AppendTx(ctx, tx, opReq(i)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
