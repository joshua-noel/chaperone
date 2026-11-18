package ledger

import (
	"context"

	"github.com/joshua-noel/chaperone/internal/store"
)

type request struct {
	p     *prepared
	reply chan result
}

type result struct {
	r   Receipt
	err error
}

// Append writes d in its own transaction and returns once it is committed.
// Events from many goroutines are queued to one writer goroutine that commits
// them in groups, one fsync per group, in queue order. Use [Ledger.AppendTx]
// when the event must commit with an operation's state change.
//
// Any error means the event is not in the ledger and the operation MUST be
// refused.
func (l *Ledger) Append(ctx context.Context, d Draft) (Receipt, error) {
	if err := l.brokenErr(); err != nil {
		return Receipt{}, err
	}
	if l.db.InTransaction(ctx) {
		// The writer goroutine could not start while the caller holds the write gate.
		return Receipt{}, wrapDB(store.ErrNestedWrite)
	}
	p, err := l.prepare(d)
	if err != nil {
		return Receipt{}, err
	}
	req := &request{p: p, reply: make(chan result, 1)}

	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return Receipt{}, ErrClosed
	}
	select {
	case l.reqs <- req:
		l.mu.RUnlock()
	case <-ctx.Done():
		l.mu.RUnlock()
		return Receipt{}, ctx.Err()
	}
	// Once queued the event may commit whatever the caller does, so wait for
	// the outcome instead of guessing from ctx: the caller must know.
	res := <-req.reply
	return res.r, res.err
}

// writer is the single goroutine that assigns seq and prev_hash for queued
// appends.
func (l *Ledger) writer() {
	defer l.wg.Done()
	for first := range l.reqs {
		batch := []*request{first}
	drain:
		for len(batch) < maxBatch {
			select {
			case r, ok := <-l.reqs:
				if !ok {
					break drain
				}
				batch = append(batch, r)
			default:
				break drain
			}
		}
		l.commit(batch)
	}
}

// commit writes the batch in one BEGIN IMMEDIATE transaction. A database
// failure fails every event in the batch; none is half written.
func (l *Ledger) commit(batch []*request) {
	receipts := make([]Receipt, len(batch))
	rejected := make([]error, len(batch))
	// The writer's own context: a caller that gave up must not roll back
	// events other callers are waiting on.
	ctx := context.Background()
	err := l.brokenErr()
	if err == nil {
		err = l.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			st, err := l.loadHead(ctx, tx)
			if err != nil {
				return err
			}
			stored, wrote := st.stored, false
			for i, req := range batch {
				s, err := l.stamp(req.p, st, l.cfg.Clock())
				if err != nil {
					// Only this event is refused (for example too large).
					rejected[i] = err
					continue
				}
				if st, err = l.put(ctx, tx, s); err != nil {
					return err
				}
				wrote = true
				receipts[i] = s.receipt
			}
			if !wrote {
				return nil
			}
			st.stored = stored
			return l.saveHead(ctx, tx, st)
		})
		err = wrapDB(err)
	}
	for i, req := range batch {
		switch {
		case err != nil:
			req.reply <- result{err: err}
		case rejected[i] != nil:
			req.reply <- result{err: rejected[i]}
		default:
			req.reply <- result{r: receipts[i]}
		}
	}
}
