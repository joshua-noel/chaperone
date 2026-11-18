package ledger

import (
	"context"
	"testing"

	"github.com/joshua-noel/chaperone/internal/store"
)

func BenchmarkAppendTx(b *testing.B) {
	ctx := context.Background()
	e := newEnv(b)
	b.ResetTimer()
	err := e.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		for i := 0; i < b.N; i++ {
			if _, err := e.l.AppendTx(ctx, tx, opReq(i)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkPrepare(b *testing.B) {
	e := newEnv(b)
	for i := 0; i < b.N; i++ {
		if _, err := e.l.prepare(opReq(i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStamp(b *testing.B) {
	e := newEnv(b)
	ps := make([]*prepared, b.N)
	for i := range ps {
		ps[i], _ = e.l.prepare(opReq(i))
	}
	st := chainState{seq: -1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := e.l.stamp(ps[i], st, epoch)
		if err != nil {
			b.Fatal(err)
		}
		st = chainState{seq: s.seq, hash: s.hash}
	}
}

func BenchmarkPut(b *testing.B) {
	e := newEnv(b)
	p, _ := e.l.prepare(opReq(1))
	s, _ := e.l.stamp(p, chainState{seq: -1}, epoch)
	b.ResetTimer()
	_ = e.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		for i := 0; i < b.N; i++ {
			s.seq = int64(i)
			if _, err := e.l.put(ctx, tx, s); err != nil {
				b.Fatal(err)
			}
		}
		return nil
	})
}
