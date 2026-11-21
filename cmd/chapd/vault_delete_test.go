package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/store"
)

// deleteEnv is a database folder with a vault and secrets imported into it.
type deleteEnv struct {
	dir, db string
	values  map[string]string
}

// secret values for the tests, made so no scanner reads them as a real token
const (
	delValueA = "delete-test-value-aaaa-1111"
	delValueB = "delete-test-value-bbbb-2222"
)

func newDeleteEnv(t *testing.T) *deleteEnv {
	t.Helper()
	useTestWrapper(t)
	dir := t.TempDir()
	e := &deleteEnv{dir: dir, db: filepath.Join(dir, "state.db"), values: map[string]string{"mistake": delValueA, "keeper": delValueB}}
	if code, _, errs := runVault(t, "init", "-db", e.db); code != 0 {
		t.Fatalf("init: exit %d: %s", code, errs)
	}
	for name, val := range e.values {
		f := filepath.Join(dir, name+".txt")
		if err := os.WriteFile(f, []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errs := runVault(t, "import", "--name", name, "--kind", "test-kind", "--project", "demo", "--file", f, "--delete", "-db", e.db); code != 0 {
			t.Fatalf("import %s: exit %d: %s", name, code, errs)
		}
	}
	return e
}

// typed makes `chapd vault delete` see a terminal with the given input.
func typed(t *testing.T, input string) {
	t.Helper()
	oldIn, oldTerm := vaultStdin, vaultStdinTerminal
	vaultStdin, vaultStdinTerminal = strings.NewReader(input), func() bool { return true }
	t.Cleanup(func() { vaultStdin, vaultStdinTerminal = oldIn, oldTerm })
}

// piped makes `chapd vault delete` see standard input that is not a terminal.
func piped(t *testing.T) {
	t.Helper()
	oldIn, oldTerm := vaultStdin, vaultStdinTerminal
	vaultStdin, vaultStdinTerminal = strings.NewReader(""), func() bool { return false }
	t.Cleanup(func() { vaultStdin, vaultStdinTerminal = oldIn, oldTerm })
}

func (e *deleteEnv) has(t *testing.T, name string) bool {
	t.Helper()
	_, out, _ := runVault(t, "list", "-db", e.db)
	return strings.Contains(out, name+" ") || strings.Contains(out, name+"\t")
}

func (e *deleteEnv) fileOf(name string) string { return filepath.Join(e.dir, "vault", name+".age") }

func (e *deleteEnv) opEvents(t *testing.T) []string { return ledgerEventsOf(t, e.db) }

func (e *deleteEnv) verifyLedger(t *testing.T) { verifyLedgerOf(t, e.db) }

// ledgerEventsOf returns every ledger event of the database, in order, as "event_name event-json".
func ledgerEventsOf(t *testing.T, db string) []string {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rows, err := d.SQL().QueryContext(ctx, `SELECT event_name, event FROM ledger_events ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, ev string
		if err := rows.Scan(&name, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, name+" "+ev)
	}
	return out
}

func verifyLedgerOf(t *testing.T, db string) {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rep, err := ledger.Verify(ctx, d, ledger.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("the ledger does not verify: %v", rep.Err())
	}
}

func noValueIn(t *testing.T, where string, text string) {
	t.Helper()
	for _, v := range []string{delValueA, delValueB} {
		if strings.Contains(text, v) {
			t.Errorf("%s holds a secret value", where)
		}
	}
}

func TestVaultDeleteOnATerminalAsksForTheNameThenRemovesAndRecords(t *testing.T) {
	e := newDeleteEnv(t)
	typed(t, "mistake\r\n")
	code, out, errs := runVault(t, "delete", "--name", "mistake", "-db", e.db)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"mistake", "test-kind", "demo", "imported:", "Type the name to confirm", "not overwritten"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	noValueIn(t, "stdout", out)
	noValueIn(t, "stderr", errs)
	if e.has(t, "mistake") || !e.has(t, "keeper") {
		t.Error("the wrong secrets are left in the vault")
	}
	if _, err := os.Stat(e.fileOf("mistake")); !os.IsNotExist(err) {
		t.Errorf("the vault file is still there: %v", err)
	}
	if _, err := os.Stat(e.fileOf("keeper")); err != nil {
		t.Errorf("the other secret's file went: %v", err)
	}

	evs := e.opEvents(t)
	if len(evs) != 2 || !strings.HasPrefix(evs[0], "op.request ") || !strings.HasPrefix(evs[1], "op.result ") {
		t.Fatalf("the ledger has %d events, want an op.request and an op.result: %v", len(evs), evs)
	}
	for _, ev := range evs {
		for _, want := range []string{`"factory.op":"vault.delete"`, `"factory.orchestrator.id":"operator"`, `"factory.requester.kind":"orchestrator"`} {
			if strings.Contains(ev, `"factory.op"`) && !strings.Contains(ev, want) {
				t.Errorf("an event does not say %s: %s", want, ev)
			}
		}
		noValueIn(t, "a ledger event", ev)
	}
	if !strings.Contains(evs[0], "mistake") || !strings.Contains(evs[0], `"factory.reversibility":"irreversible"`) {
		t.Errorf("the request does not name the secret or say it is irreversible: %s", evs[0])
	}
	if strings.Contains(strings.Join(evs, "\n"), "op.approve") {
		t.Error("an offline command wrote an approval it cannot have")
	}
	e.verifyLedger(t)
}

func TestVaultDeleteTypedNameMustBeExact(t *testing.T) {
	for _, input := range []string{"", "\n", "mistak\n", "mistake2\n", "MISTAKE\n", " mistake\n", "mistake \n", "yes\n"} {
		e := newDeleteEnv(t)
		typed(t, input)
		code, _, errs := runVault(t, "delete", "--name", "mistake", "-db", e.db)
		if code != 1 || !strings.Contains(errs, "Nothing was deleted") {
			t.Errorf("input %q: exit %d, %q; want exit 1 and nothing deleted", input, code, errs)
		}
		if !e.has(t, "mistake") {
			t.Errorf("input %q: the secret was deleted", input)
		}
		if _, err := os.Stat(e.fileOf("mistake")); err != nil {
			t.Errorf("input %q: the file went: %v", input, err)
		}
		if n := len(e.opEvents(t)); n != 0 {
			t.Errorf("input %q: %d ledger events for a delete that did not happen", input, n)
		}
	}
}

func TestVaultDeleteWithoutATerminalNeedsYes(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	code, _, errs := runVault(t, "delete", "--name", "mistake", "-db", e.db)
	if code != 2 || !strings.Contains(errs, "--yes") {
		t.Fatalf("no --yes: exit %d, %q", code, errs)
	}
	if !e.has(t, "mistake") {
		t.Fatal("deleted without --yes")
	}
	if code, out, errs := runVault(t, "delete", "--name", "mistake", "--yes", "-db", e.db); code != 0 {
		t.Fatalf("--yes: exit %d: %s", code, errs)
	} else if strings.Contains(out, "Type the name") {
		t.Error("asked a question where nobody can answer")
	}
	if e.has(t, "mistake") {
		t.Error("--yes did not delete")
	}
	e.verifyLedger(t)
}

func TestVaultDeleteOnATerminalRefusesYes(t *testing.T) {
	e := newDeleteEnv(t)
	typed(t, "mistake\n")
	code, _, errs := runVault(t, "delete", "--name", "mistake", "--yes", "-db", e.db)
	if code != 2 || !strings.Contains(errs, "terminal") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	if !e.has(t, "mistake") {
		t.Fatal("deleted although --yes is for scripts")
	}
}

func TestVaultDeleteRefusesWhatItCannotName(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"delete", "--yes"}, 2, "--name is required"},
		{[]string{"delete", "--yes", "--name", "../keeper"}, 2, "not a secret id"},
		{[]string{"delete", "--yes", "--name", "Keeper"}, 2, "not a secret id"},
		{[]string{"delete", "--yes", "--name", "keep"}, 1, "no secret named"},
		{[]string{"delete", "--yes", "--name", "keeper*"}, 2, "not a secret id"},
		{[]string{"delete", "--yes", "--name", "keeper", "extra"}, 2, ""},
	}
	for _, c := range cases {
		code, _, errs := runVault(t, append(c.args, "-db", e.db)...)
		if code != c.code || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d, %q; want exit %d and %q", c.args, code, errs, c.code, c.want)
		}
	}
	if !e.has(t, "keeper") || !e.has(t, "mistake") {
		t.Error("a refused delete removed something")
	}
	if n := len(e.opEvents(t)); n != 0 {
		t.Errorf("%d ledger events for refused deletes", n)
	}
}

func TestVaultDeleteSaysWhenOnlyALeftoverFileExists(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	if err := os.WriteFile(e.fileOf("orphan"), []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runVault(t, "delete", "--yes", "--name", "orphan", "-db", e.db)
	if code != 1 || !strings.Contains(errs, "no secret named") || !strings.Contains(errs, "orphan.age") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	if _, err := os.Stat(e.fileOf("orphan")); err != nil {
		t.Error("a file with no index row was removed: delete only removes what the index names")
	}
}

// After a crash between the two steps the row is back and the file is gone.
// The vault refuses to use it, and the same command finishes the delete.
func TestVaultDeleteFinishesAfterACrashBetweenTheSteps(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	if err := os.Remove(e.fileOf("mistake")); err != nil { // the state the crash leaves
		t.Fatal(err)
	}
	if !e.has(t, "mistake") {
		t.Fatal("setup: the row should still be listed")
	}
	code, out, errs := runVault(t, "delete", "--yes", "--name", "mistake", "-db", e.db)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "deleted mistake") || e.has(t, "mistake") {
		t.Errorf("the delete did not finish: %q", out)
	}
	e.verifyLedger(t)
}

func TestVaultDeleteRefusesWhenTheLedgerCannotBeWritten(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	if code, _, errs := runVault(t, "delete", "--yes", "--name", "mistake", "-db", e.db); code != 0 {
		t.Fatalf("first delete: exit %d: %s", code, errs)
	}
	// Damage the chain the way a tamperer would, after taking the guard off: the head no longer names the last event.
	ctx := context.Background()
	d, err := store.Open(ctx, e.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().ExecContext(ctx, `DROP TRIGGER ledger_chains_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().ExecContext(ctx, `UPDATE ledger_chains SET head_hash = ?`, "sha256:"+strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	d.Close()

	code, _, errs := runVault(t, "delete", "--yes", "--name", "keeper", "-db", e.db)
	if code != 1 || !strings.Contains(errs, "Nothing was deleted") {
		t.Fatalf("exit %d, %q; want a refusal that deleted nothing", code, errs)
	}
	if !e.has(t, "keeper") {
		t.Error("the secret was deleted although the ledger could not record it")
	}
	if _, err := os.Stat(e.fileOf("keeper")); err != nil {
		t.Errorf("the file went: %v", err)
	}
}

func TestVaultDeleteUsageIsListedAndInstanceIsChecked(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	if _, _, errs := runVault(t, "nonsense"); !strings.Contains(errs, "chapd vault delete") {
		t.Errorf("the usage does not list delete: %q", errs)
	}
	code, _, errs := runVault(t, "delete", "--yes", "--name", "keeper", "-instance", "Not Valid", "-db", e.db)
	if code != 1 || !e.has(t, "keeper") {
		t.Errorf("a bad -instance: exit %d, %q; the secret must stay", code, errs)
	}
}

func TestVaultListMarksASecretWhoseFileIsGone(t *testing.T) {
	e := newDeleteEnv(t)
	_, before, _ := runVault(t, "list", "-db", e.db)
	if strings.Contains(before, "file missing") || strings.Contains(before, "NOTE") {
		t.Fatalf("a whole vault is marked: %s", before)
	}
	if err := os.Remove(e.fileOf("mistake")); err != nil { // the state an interrupted delete leaves
		t.Fatal(err)
	}
	code, out, errs := runVault(t, "list", "-db", e.db)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var marked, plain int
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "mistake"):
			if !strings.Contains(line, "file missing") || !strings.Contains(line, "chapd vault delete --name mistake") {
				t.Errorf("the half-deleted secret is not marked with what to run: %q", line)
			}
			marked++
		case strings.HasPrefix(line, "keeper"):
			if strings.Contains(line, "file missing") {
				t.Errorf("a whole secret is marked: %q", line)
			}
			plain++
		}
	}
	if marked != 1 || plain != 1 {
		t.Errorf("list:\n%s", out)
	}
}

func TestVaultDeleteWhoseFileIsInUseSaysNothingWasRemoved(t *testing.T) {
	e := newDeleteEnv(t)
	piped(t)
	path := e.fileOf("mistake")
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "inner"), 0o700); err != nil { // a file that cannot be removed
		t.Fatal(err)
	}
	code, _, errs := runVault(t, "delete", "--yes", "--name", "mistake", "-db", e.db)
	if code != 1 || !strings.Contains(errs, "nothing was removed") || !strings.Contains(errs, "run the same command again") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	if strings.Contains(errs, "half") {
		t.Errorf("the message calls a clean rollback half done: %q", errs)
	}
	if !e.has(t, "mistake") {
		t.Error("the row went")
	}
	if n := len(e.opEvents(t)); n != 0 {
		t.Errorf("%d ledger events for a delete that removed nothing", n)
	}
	e.verifyLedger(t)
}

func TestVaultDeleteSaysWhatHappensToTokensAlreadyMade(t *testing.T) {
	e := newDeleteEnv(t)
	typed(t, "mistake\n")
	_, out, _ := runVault(t, "delete", "--name", "mistake", "-db", e.db)
	for _, want := range []string{"stops reading this secret at once", "until it expires, at most an hour", "restart chapd"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no longer use") {
		t.Error("the output still claims chapd can no longer use the secret")
	}
}
