package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func (e *env) days() []string {
	e.t.Helper()
	days, stray, err := segments(filepath.Join(e.export, e.l.Chain()))
	if err != nil || len(stray) != 0 {
		e.t.Fatalf("segments %v stray %v err %v", days, stray, err)
	}
	return days
}

func lineCount(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func TestExportSplitsByDayAndResumes(t *testing.T) {
	e := newEnvStep(t, 8*time.Hour) // 3 events a day
	ctx := context.Background()
	e.append(7)
	res, err := e.l.Export(ctx)
	if err != nil || res.Events != 7 || res.Through != 6 {
		t.Fatalf("Export = %+v, %v", res, err)
	}
	days := e.days()
	want := []string{"2026-10-24.jsonl", "2026-10-25.jsonl", "2026-10-26.jsonl"}
	if strings.Join(days, ",") != strings.Join(want, ",") {
		t.Fatalf("segments = %v, want %v", days, want)
	}
	for i, n := range []int{2, 3, 2} { // 10:00 and 18:00 on the 24th, then 02:00 ... on the 25th
		if got := lineCount(t, filepath.Join(e.export, e.l.Chain(), days[i])); got != n {
			t.Errorf("%s has %d lines, want %d", days[i], got, n)
		}
	}
	e.mustVerifyClean(true)

	// Nothing new: nothing written. New events land after the old ones.
	if res, err := e.l.Export(ctx); err != nil || res.Events != 0 || res.Through != 6 {
		t.Fatalf("idle Export = %+v, %v", res, err)
	}
	e.append(2)
	if res, err := e.l.Export(ctx); err != nil || res.Events != 2 || res.Through != 8 {
		t.Fatalf("second Export = %+v, %v", res, err)
	}
	e.mustVerifyClean(true)
	rep := e.verify(true)
	if rep.Chains[0].ExportedThrough != 8 || rep.Chains[0].Unexported != 0 {
		t.Errorf("report = %+v", rep.Chains[0])
	}
}

func TestExportKeepsSegmentOrderWhenTheClockGoesBack(t *testing.T) {
	e := newEnv(t)
	times := []time.Time{epoch, epoch.Add(30 * time.Hour), epoch.Add(time.Hour), epoch.Add(31 * time.Hour)}
	for i, tm := range times {
		d := opReq(i)
		d.Time = tm
		if _, err := e.l.Append(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.l.Export(context.Background()); err != nil {
		t.Fatal(err)
	}
	days := e.days()
	if len(days) != 2 || lineCount(t, filepath.Join(e.export, e.l.Chain(), days[1])) != 3 {
		t.Fatalf("segments %v: the event with an earlier clock must follow its predecessor", days)
	}
	e.mustVerifyClean(true)
}

func TestExportRepairsATornLastLine(t *testing.T) {
	e := seeded(t)
	seg := e.segment()
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"chain":"chaperone.test","seq":10,"hash":"sha2`) // a crash mid-write
	f.Close()

	if rep := e.verify(true); !hasCode(rep, ProblemExportTorn) {
		t.Fatalf("torn line not reported: %v", codes(rep))
	}
	e.append(2)
	res, err := e.l.Export(context.Background())
	if err != nil || res.Events != 2 || res.Through != 11 {
		t.Fatalf("Export = %+v, %v", res, err)
	}
	e.mustVerifyClean(true)
	if got := lineCount(t, seg); got != 12 {
		t.Errorf("%d lines, want 12", got)
	}
}

// A crash after the segment was fsynced but before the export mark moved
// leaves the file ahead of the mark: the next Export carries on from the file.
func TestExportResumesWhenTheFileIsAheadOfTheMark(t *testing.T) {
	e := seeded(t)
	e.append(3)
	var extra strings.Builder
	rs, err := e.db.SQL().Query(`SELECT event FROM ledger_events WHERE seq IN (10, 11) ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var s string
		rs.Scan(&s)
		extra.WriteString(s + "\n")
	}
	rs.Close()
	f, _ := os.OpenFile(e.segment(), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(extra.String())
	f.Close()

	res, err := e.l.Export(context.Background())
	if err != nil || res.Events != 1 || res.Through != 12 {
		t.Fatalf("Export = %+v, %v", res, err)
	}
	e.mustVerifyClean(true)
}

func TestExportRefusesWhenTheExportWasTamperedWith(t *testing.T) {
	ctx := context.Background()
	t.Run("last line edited", func(t *testing.T) {
		e := seeded(t)
		lines := e.readLines()
		lines[9] = strings.Replace(lines[9], "pr.open", "pr.merge", 1)
		e.writeLines(lines)
		e.append(1)
		if _, err := e.l.Export(ctx); !errors.Is(err, ErrExportMismatch) {
			t.Fatalf("err = %v", err)
		}
		if got := lineCount(t, e.segment()); got != 10 {
			t.Errorf("a refused export wrote %d lines", got-10)
		}
	})
	t.Run("segment truncated below the mark", func(t *testing.T) {
		e := seeded(t)
		e.writeLines(e.readLines()[:5])
		e.append(1)
		if _, err := e.l.Export(ctx); !errors.Is(err, ErrExportMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("segment deleted", func(t *testing.T) {
		e := seeded(t)
		os.Remove(e.segment())
		e.append(1)
		if _, err := e.l.Export(ctx); !errors.Is(err, ErrExportMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("export ahead of SQLite", func(t *testing.T) {
		e := seeded(t)
		e.dropGuards()
		e.exec(`DELETE FROM ledger_events WHERE seq = 9`)
		e.exec(`UPDATE ledger_chains SET head_seq = 8, head_hash = (SELECT hash FROM ledger_events WHERE seq = 8)`)
		if _, err := e.l.Export(ctx); !errors.Is(err, ErrExportMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestExportNeedsADirectoryAndAnEvent(t *testing.T) {
	e := newEnv(t)
	if res, err := e.l.Export(context.Background()); err != nil || res.Events != 0 || res.Through != -1 {
		t.Fatalf("empty ledger: %+v %v", res, err)
	}
	l2, err := Open(context.Background(), e.db, Config{Instance: "test", Redactor: e.reg})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if _, err := l2.Export(context.Background()); err == nil {
		t.Error("Export without ExportDir succeeded")
	}
}

func TestRunExportExportsInTheBackground(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.l.RunExport(ctx, 10*time.Millisecond, func(err error) { t.Errorf("export: %v", err) })
	}()
	e.append(5)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rep := e.verify(true); rep.OK() && rep.Chains[0].Unexported == 0 {
			cancel()
			wg.Wait()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	t.Fatal("background export never caught up")
}
