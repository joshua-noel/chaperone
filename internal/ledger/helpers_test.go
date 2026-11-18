package ledger

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

var epoch = time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)

// stepClock returns epoch, epoch+step, epoch+2*step ...
type stepClock struct {
	mu   sync.Mutex
	n    int64
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := epoch.Add(time.Duration(c.n) * c.step)
	c.n++
	return t
}

type env struct {
	t      testing.TB
	db     *store.DB
	l      *Ledger
	dbPath string
	export string
	reg    *redact.Registry
}

func openDB(t testing.TB, path string) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	return db
}

// newEnv opens a migrated database and a ledger with a one-second step clock.
func newEnv(t testing.TB) *env {
	t.Helper()
	return newEnvStep(t, time.Second)
}

func newEnvStep(t testing.TB, step time.Duration) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, dbPath: filepath.Join(dir, "state.db"), export: filepath.Join(dir, "export"), reg: redact.NewRegistry()}
	e.db = openDB(t, e.dbPath)
	t.Cleanup(func() { e.db.Close() })
	clk := &stepClock{step: step}
	l, err := Open(context.Background(), e.db, Config{Instance: "test", Version: "0.0.0", ExportDir: e.export, Redactor: e.reg, Clock: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.l = l
	t.Cleanup(func() { l.Close() })
	return e
}

func opReq(i int) Draft {
	return Draft{
		Name:    "op.request",
		Project: "storefront",
		Attributes: map[string]any{
			"factory.request_id":      fmt.Sprintf("q-%06d", i),
			"factory.op":              "pr.open",
			"factory.op_hash":         "sha256:" + strings.Repeat("ab", 32),
			"factory.requester.kind":  "orchestrator",
			"factory.orchestrator.id": "main",
		},
	}
}

func runReq(i int) Draft {
	d := opReq(i)
	d.RunID = "r-abcd1"
	d.Attributes["factory.requester.kind"] = "run"
	delete(d.Attributes, "factory.orchestrator.id")
	return d
}

func (e *env) append(n int) {
	e.t.Helper()
	for i := range n {
		if _, err := e.l.Append(context.Background(), opReq(i)); err != nil {
			e.t.Fatalf("append %d: %v", i, err)
		}
	}
}

func (e *env) verify(againstExport bool) Report {
	e.t.Helper()
	rep, err := Verify(context.Background(), e.db, VerifyOptions{AgainstExport: againstExport, ExportDir: e.export})
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func (e *env) mustVerifyClean(againstExport bool) {
	e.t.Helper()
	if rep := e.verify(againstExport); !rep.OK() {
		e.t.Fatalf("verify reports problems: %v", rep.Err())
	}
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.SQL().Exec(q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

// dropGuards removes every append-only trigger: what an attacker with the
// database file (or a test that needs to tamper) can do.
func (e *env) dropGuards() {
	e.t.Helper()
	for _, tr := range []string{"ledger_events_no_update", "ledger_events_no_delete", "ledger_chains_no_delete", "ledger_chains_guard"} {
		e.exec("DROP TRIGGER " + tr)
	}
}

// rewriteFrom edits event `from` with mutate and recomputes every later hash
// and link, so the stored chain is internally consistent again. It updates the
// head too: the best forgery an attacker who controls only SQLite can make.
func (e *env) rewriteFrom(from int64, mutate func(m map[string]any)) {
	e.t.Helper()
	e.dropGuards()
	rs, err := e.db.SQL().Query(`SELECT seq, event FROM ledger_events WHERE chain = ? AND seq >= ? ORDER BY seq`, e.l.Chain(), from)
	if err != nil {
		e.t.Fatal(err)
	}
	type r struct {
		seq  int64
		text string
	}
	var all []r
	for rs.Next() {
		var x r
		if err := rs.Scan(&x.seq, &x.text); err != nil {
			e.t.Fatal(err)
		}
		all = append(all, x)
	}
	rs.Close()
	prev := spec.ZeroHash
	if from > 0 {
		if err := e.db.SQL().QueryRow(`SELECT hash FROM ledger_events WHERE chain = ? AND seq = ?`, e.l.Chain(), from-1).Scan(&prev); err != nil {
			e.t.Fatal(err)
		}
	}
	var lastHash string
	var lastSeq int64
	for _, x := range all {
		tree, err := spec.ParseStrict([]byte(x.text))
		if err != nil {
			e.t.Fatal(err)
		}
		m := tree.(map[string]any)
		if x.seq == from {
			mutate(m)
		}
		m["prev_hash"] = prev
		delete(m, "hash")
		h, err := spec.EventHash(m)
		if err != nil {
			e.t.Fatal(err)
		}
		m["hash"] = h
		text, err := spec.JCS(m)
		if err != nil {
			e.t.Fatal(err)
		}
		e.exec(`UPDATE ledger_events SET event = ?, hash = ?, prev_hash = ? WHERE chain = ? AND seq = ?`, string(text), h, prev, e.l.Chain(), x.seq)
		prev, lastHash, lastSeq = h, h, x.seq
	}
	e.exec(`UPDATE ledger_chains SET head_seq = ?, head_hash = ? WHERE chain = ?`, lastSeq, lastHash, e.l.Chain())
}

func hasCode(rep Report, code string) bool {
	for _, p := range rep.Problems() {
		if p.Code == code {
			return true
		}
	}
	return false
}

func codes(rep Report) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range rep.Problems() {
		if !seen[p.Code] {
			seen[p.Code] = true
			out = append(out, p.Code)
		}
	}
	return out
}

func mustTree(t testing.TB, text string) map[string]any {
	t.Helper()
	tree, err := spec.ParseStrict([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return tree.(map[string]any)
}

func mustEventHash(t testing.TB, m map[string]any) string {
	t.Helper()
	h, err := spec.EventHash(m)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustJCS(t testing.TB, m map[string]any) string {
	t.Helper()
	b, err := spec.JCS(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
