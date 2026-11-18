package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seeded returns an env with 10 events, all exported to one JSONL segment.
func seeded(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.append(10)
	if _, err := e.l.Export(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mustVerifyClean(true)
	return e
}

func (e *env) segment() string {
	e.t.Helper()
	days, _, err := segments(filepath.Join(e.export, e.l.Chain()))
	if err != nil || len(days) != 1 {
		e.t.Fatalf("segments = %v, %v", days, err)
	}
	return filepath.Join(e.export, e.l.Chain(), days[0])
}

func (e *env) readLines() []string {
	e.t.Helper()
	b, err := os.ReadFile(e.segment())
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func (e *env) writeLines(lines []string) {
	e.t.Helper()
	out := strings.Join(lines, "")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(e.segment(), []byte(out), 0o640); err != nil {
		e.t.Fatal(err)
	}
}

// Every tamper the ticket names is detected, by the check that should catch it.
func TestTamperIsDetected(t *testing.T) {
	cases := []struct {
		name string
		// withExport: the check needs --against-export to see it.
		withExport bool
		tamper     func(e *env)
		want       []string // problem codes that must all appear
		wantMsg    string   // substring of the combined problem text
	}{
		{
			name: "flip a byte in an event",
			tamper: func(e *env) {
				e.dropGuards()
				e.exec(`UPDATE ledger_events SET event = replace(event, 'storefront', 'storefroNt') WHERE seq = 4`)
			},
			want:    []string{ProblemChain},
			wantMsg: "seq 4: hash does not match the event content",
		},
		{
			name: "flip a byte, fix the event hash only",
			tamper: func(e *env) {
				// The attacker recomputes event 4's own hash but not what follows.
				e.dropGuards()
				e.exec(`UPDATE ledger_events SET event = replace(event, 'storefront', 'storefroNt') WHERE seq = 4`)
				e.fixHashOnly(4)
			},
			want:    []string{ProblemChain},
			wantMsg: "seq 5: prev_hash does not match the previous event",
		},
		{
			name: "drop a row",
			tamper: func(e *env) {
				e.dropGuards()
				e.exec(`DELETE FROM ledger_events WHERE seq = 5`)
			},
			want:    []string{ProblemSeqGap, ProblemChain},
			wantMsg: "expected seq 5, found 6 (1 event(s) missing)",
		},
		{
			name: "reorder two rows (swap seq)",
			tamper: func(e *env) {
				e.dropGuards()
				e.exec(`UPDATE ledger_events SET seq = 100 WHERE seq = 3`)
				e.exec(`UPDATE ledger_events SET seq = 3 WHERE seq = 4`)
				e.exec(`UPDATE ledger_events SET seq = 4 WHERE seq = 100`)
			},
			want:    []string{ProblemColumnMismatch},
			wantMsg: "seq 3: indexed column(s) disagree with the event JSON: seq 4",
		},
		{
			name: "reorder two events (swap bodies)",
			tamper: func(e *env) {
				e.dropGuards()
				var a, b string
				e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = 3`).Scan(&a)
				e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = 4`).Scan(&b)
				e.exec(`UPDATE ledger_events SET event = ? WHERE seq = 3`, b)
				e.exec(`UPDATE ledger_events SET event = ? WHERE seq = 4`, a)
			},
			want:    []string{ProblemColumnMismatch},
			wantMsg: "indexed column(s) disagree",
		},
		{
			name: "truncate the tail (head record left)",
			tamper: func(e *env) {
				e.dropGuards()
				e.exec(`DELETE FROM ledger_events WHERE seq >= 7`)
			},
			want:    []string{ProblemHeadMismatch},
			wantMsg: "tail cut off: head says seq 9, last event is seq 6 (3 event(s) removed)",
		},
		{
			name:       "truncate the tail and the head record (only the export remembers)",
			withExport: true,
			tamper: func(e *env) {
				e.dropGuards()
				e.exec(`DELETE FROM ledger_events WHERE seq >= 7`)
				e.exec(`UPDATE ledger_chains SET head_seq = 6, head_hash = (SELECT hash FROM ledger_events WHERE seq = 6), exported_seq = 6, exported_hash = (SELECT hash FROM ledger_events WHERE seq = 6)`)
			},
			want:    []string{ProblemExportAhead},
			wantMsg: "export holds this event but SQLite does not",
		},
		{
			name:       "edit only the JSONL",
			withExport: true,
			tamper: func(e *env) {
				lines := e.readLines()
				lines[3] = strings.Replace(lines[3], "storefront", "storefroNt", 1)
				e.writeLines(lines)
			},
			want:    []string{ProblemExportDiffers},
			wantMsg: "export line hash INVALID, SQLite row hash valid",
		},
		{
			name:       "edit only the JSONL (last line)",
			withExport: true,
			tamper: func(e *env) {
				lines := e.readLines()
				lines[9] = strings.Replace(lines[9], "pr.open", "pr.merge", 1)
				e.writeLines(lines)
			},
			want: []string{ProblemExportDiffers},
		},
		{
			name:       "delete a line from the JSONL",
			withExport: true,
			tamper: func(e *env) {
				lines := e.readLines()
				e.writeLines(append(lines[:4:4], lines[5:]...))
			},
			want: []string{ProblemExportGap},
		},
		{
			name:       "truncate the JSONL tail",
			withExport: true,
			tamper: func(e *env) {
				e.writeLines(e.readLines()[:6])
			},
			want:    []string{ProblemExportMissing},
			wantMsg: "recorded events through seq 9 but the export holds only through seq 5",
		},
		{
			name:       "delete the JSONL segment",
			withExport: true,
			tamper: func(e *env) {
				if err := os.Remove(e.segment()); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{ProblemExportMissing},
		},
		{
			name:       "edit only SQLite, chain re-hashed from the edit",
			withExport: true,
			tamper: func(e *env) {
				e.rewriteFrom(2, func(m map[string]any) { m["project"] = "other-project" })
			},
			want:    []string{ProblemExportDiffers},
			wantMsg: "edited in only one place",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := seeded(t)
			tc.tamper(e)
			rep := e.verify(tc.withExport)
			if rep.OK() {
				t.Fatal("tamper not detected")
			}
			for _, c := range tc.want {
				if !hasCode(rep, c) {
					t.Errorf("want problem %s, got %v\n%v", c, codes(rep), rep.Err())
				}
			}
			if tc.wantMsg != "" && !strings.Contains(rep.Err().Error(), tc.wantMsg) {
				t.Errorf("no problem says %q:\n%v", tc.wantMsg, rep.Err())
			}
			if !errors.Is(rep.Err(), ErrVerifyFailed) {
				t.Errorf("Err() = %v", rep.Err())
			}
		})
	}
}

// fixHashOnly recomputes the hash of one event and nothing else.
func (e *env) fixHashOnly(seq int64) {
	e.t.Helper()
	var text string
	if err := e.db.SQL().QueryRow(`SELECT event FROM ledger_events WHERE seq = ?`, seq).Scan(&text); err != nil {
		e.t.Fatal(err)
	}
	m := mustTree(e.t, text)
	delete(m, "hash")
	h := mustEventHash(e.t, m)
	m["hash"] = h
	e.exec(`UPDATE ledger_events SET event = ?, hash = ? WHERE seq = ?`, mustJCS(e.t, m), h, seq)
}

// A forgery that is consistent inside SQLite passes the chain check and is
// caught only against the export: this is why the export exists.
func TestConsistentSQLiteRewriteNeedsTheExport(t *testing.T) {
	e := seeded(t)
	e.rewriteFrom(2, func(m map[string]any) { m["project"] = "other-project" })
	if rep := e.verify(false); !rep.OK() {
		t.Fatalf("a consistent rewrite should pass the chain check: %v", rep.Err())
	}
	if rep := e.verify(true); rep.OK() {
		t.Fatal("--against-export missed the rewrite")
	}
}

func TestVerifyWithoutTamperOnEmptyLedger(t *testing.T) {
	e := newEnv(t)
	rep := e.verify(true)
	if !rep.OK() || len(rep.Chains) != 0 {
		t.Fatalf("empty ledger: %+v", rep)
	}
	e.append(1)
	if _, err := Verify(context.Background(), e.db, VerifyOptions{AgainstExport: true}); err == nil {
		t.Error("AgainstExport without ExportDir accepted")
	}
	if rep := e.verify(true); !rep.OK() || rep.Chains[0].Unexported != 1 || rep.Chains[0].ExportedThrough != -1 {
		t.Errorf("unexported event: %+v", rep.Chains[0])
	}
}

// Rows of a second chain are checked on their own and never mix with ours.
func TestEachChainIsCheckedOnItsOwn(t *testing.T) {
	e := newEnv(t)
	other := openDB(t, filepath.Join(t.TempDir(), "other.db"))
	defer other.Close()
	l2, err := Open(context.Background(), other, Config{Instance: "second", Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if _, err := l2.Append(context.Background(), opReq(1)); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(context.Background(), other, VerifyOptions{})
	if err != nil || !rep.OK() || len(rep.Chains) != 1 || rep.Chains[0].Chain != "chaperone.second" {
		t.Fatalf("%+v %v", rep, err)
	}
}
