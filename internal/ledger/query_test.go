package ledger

import (
	"context"
	"testing"
	"time"
)

func TestQuery(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := range 6 {
		d := opReq(i)
		if i%2 == 1 {
			d = runReq(i)
		}
		if i == 4 {
			d.Project = "other-project"
		}
		if _, err := e.l.Append(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.l.Anchor(ctx, "offline-copy", "x"); err != nil {
		t.Fatal(err)
	}
	after := int64(1)
	for name, tc := range map[string]struct {
		p    QueryParams
		want []int64
	}{
		"all":     {QueryParams{}, []int64{0, 1, 2, 3, 4, 5, 6}},
		"run":     {QueryParams{RunID: "r-abcd1"}, []int64{1, 3, 5}},
		"name":    {QueryParams{EventName: "ledger.anchor"}, []int64{6}},
		"request": {QueryParams{RequestID: "q-000003"}, []int64{3}},
		"time":    {QueryParams{From: epoch.Add(2 * time.Second), To: epoch.Add(4 * time.Second)}, []int64{2, 3}},
		"after":   {QueryParams{AfterSeq: &after, Limit: 2}, []int64{2, 3}},
	} {
		got, err := e.l.Query(ctx, tc.p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var seqs []int64
		for _, ev := range got {
			seqs = append(seqs, ev.Seq)
		}
		if len(seqs) != len(tc.want) {
			t.Errorf("%s: seqs %v, want %v", name, seqs, tc.want)
			continue
		}
		for i := range seqs {
			if seqs[i] != tc.want[i] {
				t.Errorf("%s: seqs %v, want %v", name, seqs, tc.want)
				break
			}
		}
	}
	rep, err := e.l.Verify(ctx, false)
	if err != nil || !rep.OK() {
		t.Fatalf("Verify: %v %v", err, rep.Err())
	}
}
