package ledger

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/store"
)

// The crash tests run this test binary again as a child "chapd" that is killed
// without warning (TerminateProcess on Windows, SIGKILL on Linux): no deferred
// function, no Close, no WAL checkpoint.
const (
	childEnv  = "LEDGER_CRASH_CHILD"
	childDB   = "LEDGER_CRASH_DB"
	childDir  = "LEDGER_CRASH_EXPORT"
	modeAppnd = "append"
	modeTx    = "tx"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		os.Exit(runChild(mode))
	}
	os.Exit(m.Run())
}

func runChild(mode string) int {
	ctx := context.Background()
	db, err := store.Open(ctx, os.Getenv(childDB))
	if err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 2
	}
	ms, _ := store.Migrations()
	if err := db.Migrate(ctx, ms); err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 2
	}
	l, err := Open(ctx, db, Config{Instance: "crash", ExportDir: os.Getenv(childDir), Redactor: redact.NewRegistry()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 2
	}
	switch mode {
	case modeAppnd:
		go func() { // exporter, killed with everything else
			for {
				l.Export(ctx)
				time.Sleep(5 * time.Millisecond)
			}
		}()
		for g := range 4 {
			go func() {
				for i := 0; ; i++ {
					if _, err := l.Append(ctx, opReq(g*1000000+i)); err != nil {
						fmt.Fprintln(os.Stderr, "child append:", err)
						os.Exit(3)
					}
					fmt.Println("ack") // printed only after the commit returned
				}
			}()
		}
	case modeTx:
		go func() {
			err := db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
				for i := range 30 {
					if _, err := l.AppendTx(ctx, tx, opReq(i)); err != nil {
						return err
					}
				}
				fmt.Println("inside") // 30 events written, transaction still open
				waitForKill()
				return nil
			})
			fmt.Fprintln(os.Stderr, "child tx:", err)
			os.Exit(3)
		}()
	}
	waitForKill()
	return 0
}

// waitForKill parks the child until the parent kills it. It sleeps on a timer
// because with `select {}` and nothing else running, the Go runtime reports
// "all goroutines are asleep" and exits the child first, and the parent's
// kill then fails with "Access is denied" (seen under load).
func waitForKill() {
	for {
		time.Sleep(time.Hour)
	}
}

// startChild runs the child and returns the number of lines it printed until
// stop(line count, last line) says to kill it.
func killChild(t *testing.T, mode, dbPath, exportDir string, stop func(lines int, last string) bool) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+mode, childDB+"="+dbPath, childDir+"="+exportDir)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	n, last := 0, ""
	timeout := time.After(60 * time.Second)
loop:
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("child exited early after %d lines (last %q)", n, last)
			}
			n, last = n+1, l
			if stop(n, last) {
				break loop
			}
		case <-timeout:
			cmd.Process.Kill()
			t.Fatalf("child timed out after %d lines", n)
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	// Lines the child printed between the stop decision and the kill were
	// acknowledged commits too.
	for l := range lines {
		if l == "ack" {
			n++
		}
	}
	wg.Wait()
	return n
}

// openDBAfterKill opens the database the way chapd does after it was killed.
// On Windows the dead child can still hold its WAL handles for a moment after
// Wait returns (seen about once in 150 runs under load: "disk I/O error
// (1546)", SQLITE_IOERR_TRUNCATE, while the first connection recovers the WAL),
// so a transient I/O error is retried for a few seconds. Only that code is
// retried: any other error, or one that lasts, fails the test; the retries are logged.
func openDBAfterKill(t testing.TB, path string) *store.DB {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for try := 1; ; try++ {
		db, err := store.Open(ctx, path)
		if err == nil {
			ms, err := store.Migrations()
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Migrate(ctx, ms); err != nil {
				t.Fatal(err)
			}
			return db
		}
		if !strings.Contains(err.Error(), "(1546)") || time.Now().After(deadline) {
			t.Fatal(err)
		}
		t.Logf("reopen after kill, try %d: %v", try, err)
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCrashMidWriteRestartsWithNoGap(t *testing.T) {
	dir := t.TempDir()
	dbPath, exportDir := filepath.Join(dir, "state.db"), filepath.Join(dir, "export")
	ctx := context.Background()
	acked := 0

	for round := range 4 {
		acked += killChild(t, modeAppnd, dbPath, exportDir, func(n int, _ string) bool { return n >= 150+round*40 })

		// Restart: open the database as chapd would.
		db := openDBAfterKill(t, dbPath)
		l, err := Open(ctx, db, Config{Instance: "crash", ExportDir: exportDir, Redactor: redact.NewRegistry()})
		if err != nil {
			t.Fatalf("round %d: Open after crash: %v", round, err)
		}
		// The crash may have torn the export; Export repairs it, then every
		// check passes: no gap, no fork, SQLite and JSONL agree.
		if _, err := l.Export(ctx); err != nil {
			t.Fatalf("round %d: Export after crash: %v", round, err)
		}
		rep, err := Verify(ctx, db, VerifyOptions{AgainstExport: true, ExportDir: exportDir})
		if err != nil || !rep.OK() {
			t.Fatalf("round %d: verify after crash: %v %v", round, err, rep.Err())
		}
		if got := rep.Chains[0].Events; got < int64(acked) {
			t.Fatalf("round %d: %d events survived but %d were acknowledged", round, got, acked)
		}
		// New events continue the same chain.
		before := rep.Chains[0].HeadSeq
		r, err := l.Append(ctx, opReq(1))
		if err != nil || r.Seq != before+1 {
			t.Fatalf("round %d: first append after restart = %+v, %v (head was %d)", round, r, err, before)
		}
		acked = int(r.Seq) + 1 // from here on the chain length is what was committed
		l.Close()
		db.Close()
	}
}

func TestCrashInsideATransactionLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	ctx := context.Background()
	// Seed 3 committed events so the crash happens on a non-empty chain.
	db := openDB(t, dbPath)
	l, err := Open(ctx, db, Config{Instance: "crash", Redactor: redact.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := l.Append(ctx, opReq(i)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	db.Close()

	killChild(t, modeTx, dbPath, "", func(_ int, last string) bool { return last == "inside" })

	db = openDBAfterKill(t, dbPath)
	defer db.Close()
	l, err = Open(ctx, db, Config{Instance: "crash", Redactor: redact.NewRegistry()})
	if err != nil {
		t.Fatalf("Open after crash: %v", err)
	}
	defer l.Close()
	rep, err := Verify(ctx, db, VerifyOptions{})
	if err != nil || !rep.OK() {
		t.Fatalf("verify: %v %v", err, rep.Err())
	}
	if rep.Chains[0].Events != 3 {
		t.Fatalf("%d events after the crash, want the 3 committed ones", rep.Chains[0].Events)
	}
	if r, err := l.Append(ctx, opReq(9)); err != nil || r.Seq != 3 {
		t.Fatalf("append after crash = %+v, %v", r, err)
	}
}
