package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/store"
)

const deleteMarkerKey = "delete-test-marker"

// markInTx is a recorder that writes a row in the delete transaction, the way
// the ledger event is written: it must commit or roll back with the delete.
func markInTx(ctx context.Context, tx *store.Tx, _ Info) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO vault_meta (key, value) VALUES (?, 'x')`, deleteMarkerKey)
	return err
}

func hasMarker(t *testing.T, e env) bool {
	t.Helper()
	var n int
	if err := e.cfg.DB.SQL().QueryRowContext(bg, `SELECT count(*) FROM vault_meta WHERE key = ?`, deleteMarkerKey).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func fileOf(e env, id string) string { return filepath.Join(e.cfg.Dir, id+".age") }

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func TestDeleteRemovesTheFileAndTheRowAndNothingElse(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	keep, gone := []byte("keep-this-value-please"), []byte("delete-this-value-now")
	for id, val := range map[string][]byte{"keep": keep, "gone": gone} {
		if _, err := v.Import(bg, meta(id), val); err != nil {
			t.Fatal(err)
		}
	}
	if !v.Registry().Contains(gone) {
		t.Fatal("setup: the value is not registered")
	}

	info, err := v.Delete(bg, "gone", markInTx)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "gone" || info.Kind != "test" || info.Created.IsZero() {
		t.Errorf("Delete returned %+v, want the metadata of what was removed", info)
	}
	if exists(fileOf(e, "gone")) {
		t.Error("the file is still there")
	}
	if _, err := v.Info(bg, "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Info after delete: %v, want ErrNotFound", err)
	}
	if err := v.Use(bg, "gone", func([]byte) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("Use after delete: %v, want ErrNotFound", err)
	}
	if v.Registry().Contains(gone) {
		t.Error("the deleted value is still registered for redaction in this process")
	}
	if !hasMarker(t, e) {
		t.Error("the recorder's write was not committed with the delete")
	}
	if got := use(t, v, "keep"); !bytes.Equal(got, keep) {
		t.Error("another secret changed")
	}
	if infos, err := v.List(bg); err != nil || len(infos) != 1 || infos[0].ID != "keep" {
		t.Errorf("List = %+v, %v", infos, err)
	}

	// The name is free again: a mistaken import can be done over.
	if _, err := v.Import(bg, meta("gone"), []byte("a-second-value-here")); err != nil {
		t.Errorf("import after delete: %v", err)
	}
}

func TestDeleteRefusals(t *testing.T) {
	_, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("present"), []byte("present-value-123")); err != nil {
		t.Fatal(err)
	}
	called := false
	rec := func(context.Context, *store.Tx, Info) error { called = true; return nil }
	if _, err := v.Delete(bg, "absent", rec); !errors.Is(err, ErrNotFound) {
		t.Errorf("a name that does not exist: %v, want ErrNotFound", err)
	}
	for _, bad := range []string{"", "../present", "Present", "pre.sent", "con", "present/"} {
		if _, err := v.Delete(bg, bad, rec); !errors.Is(err, ErrInvalid) {
			t.Errorf("Delete(%q): %v, want ErrInvalid", bad, err)
		}
	}
	if called {
		t.Error("the recorder ran for a refused delete")
	}
	if got := use(t, v, "present"); string(got) != "present-value-123" {
		t.Error("a refused delete changed the secret")
	}
}

func TestDeleteWhoseRecordFailsDeletesNothing(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("s"), []byte("secret-value-abc")); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("ledger unavailable")
	if _, err := v.Delete(bg, "s", func(ctx context.Context, tx *store.Tx, i Info) error {
		if err := markInTx(ctx, tx, i); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("Delete: %v, want the recorder's error", err)
	}
	if !exists(fileOf(e, "s")) {
		t.Error("the file was removed although the record failed")
	}
	if hasMarker(t, e) {
		t.Error("the recorder's write survived its own failure")
	}
	if got := use(t, v, "s"); string(got) != "secret-value-abc" {
		t.Error("the secret is not whole after a failed record")
	}
}

// A crash is a process that stops at a stage and never commits. The hook returns
// an error at the stage, which rolls the transaction back the way SQLite does for
// a process that died; what is left on disk is what a crash leaves.
func TestDeleteCrashBeforeTheFileIsRemovedLeavesTheSecretWhole(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("s"), []byte("secret-value-abc")); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash")
	v.afterDeleteStep = func(stage string) error {
		if stage == "index-deleted" {
			return crash
		}
		return nil
	}
	if _, err := v.Delete(bg, "s", markInTx); !errors.Is(err, crash) {
		t.Fatalf("Delete: %v", err)
	}
	if !exists(fileOf(e, "s")) || hasMarker(t, e) {
		t.Error("the crash left a half state: file or record changed")
	}
	if got := use(t, v, "s"); string(got) != "secret-value-abc" {
		t.Error("the secret is not usable after a crash before the file was removed")
	}
}

func TestDeleteCrashAfterTheFileIsRemovedFailsClosedAndTheSameCommandFinishes(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	value := []byte("secret-value-abc")
	if _, err := v.Import(bg, meta("s"), value); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash")
	v.afterDeleteStep = func(stage string) error {
		if stage == "file-removed" {
			return crash
		}
		return nil
	}
	if _, err := v.Delete(bg, "s", markInTx); !errors.Is(err, crash) {
		t.Fatalf("Delete: %v", err)
	}
	// The state a crash here leaves: the row is back, the file is gone, nothing was recorded.
	if exists(fileOf(e, "s")) {
		t.Fatal("setup: the file should be gone at this stage")
	}
	if hasMarker(t, e) {
		t.Error("a record was committed for a delete that did not finish")
	}
	if _, err := v.Info(bg, "s"); err != nil {
		t.Fatalf("the row should be back after the rollback: %v", err)
	}

	// Fail closed: a row whose file is missing is not a secret.
	called := false
	err := v.Use(bg, "s", func([]byte) error { called = true; return nil })
	if !errors.Is(err, ErrIntegrity) || called {
		t.Errorf("Use of a row without its file: %v (closure ran: %v), want ErrIntegrity and no use", err, called)
	}
	if err := v.LoadRegistry(bg); !errors.Is(err, ErrIntegrity) {
		t.Errorf("LoadRegistry: %v, want ErrIntegrity so chapd does not start on it", err)
	}

	// The same command, run again, finishes the job even though the file is missing.
	v.afterDeleteStep = nil
	if _, err := v.Delete(bg, "s", markInTx); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	if _, err := v.Info(bg, "s"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after the second Delete: %v, want ErrNotFound", err)
	}
	if !hasMarker(t, e) {
		t.Error("the finishing delete was not recorded")
	}
	if err := v.LoadRegistry(bg); err != nil {
		t.Errorf("LoadRegistry after finishing: %v", err)
	}
}

func TestDeleteLeavesNoPlaintextAndNoTempFile(t *testing.T) {
	e, v := newEnv(t, newAESWrapper(t))
	if _, err := v.Import(bg, meta("s"), []byte("secret-value-abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Delete(bg, "s", nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(e.cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range entries {
		t.Errorf("the vault folder still holds %s", de.Name())
	}
	if strings.Contains(string(mustRead(t, filepath.Join(e.root, "state.db"))), "secret-value-abc") {
		t.Error("the value is in the database")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
