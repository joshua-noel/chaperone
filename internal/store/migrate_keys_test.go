package store

import (
	"context"
	"path/filepath"
	"testing"
)

// Migration 0010 rebuilds ops and approvals (SQLite cannot widen a CHECK). Rehearsed here on a database that
// holds rows in both tables and in the children of approvals: every row survives, no foreign key is left
// dangling, and every trigger still refuses what it refused before.
func TestMigration0010KeepsEveryRowAndEveryTrigger(t *testing.T) {
	ctx := context.Background()
	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var upTo9 []Migration
	for _, m := range all {
		if m.Version <= 9 {
			upTo9 = append(upTo9, m)
		}
	}
	db, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx, upTo9); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.SQL().ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), 'operator', '2026-10-24T00:00:00Z')`)
	for i, kind := range []string{"run", "orchestrator"} {
		id := string(rune('1' + i))
		run, orch := "NULL", "NULL"
		if kind == "run" {
			run = "'r-1'"
		} else {
			orch = "'main'"
		}
		exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
            run_id, orchestrator_id, class, reversibility, policy_version, requested_at, expires_at, updated_at, scope_json)
            VALUES ('q-00000` + id + `', 'pending_approval', 'deploy', 'p', 'wsl-host', 'pilot', '{}', 'sha256:a` + id + `', '` + kind + `', '` + kind + `:x',
            ` + run + `, ` + orch + `, 'high', 'reversible', 'v', 1, 2, 3, '{"repo":"a/b"}')`)
		exec(`INSERT INTO approvals (approval_id, request_id, requester_kind, requester_key, run_id, project, op, op_hash, class,
            policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state, created_unix, request_expires_unix,
            decided_unix, approver, nonce, challenge_sha256, record_json)
            VALUES ('a-00000` + id + `', 'q-00000` + id + `', '` + kind + `', 'x', ` + run + `, 'p', 'deploy', 'sha256:a` + id + `', 'high', 'v', '{}', '[]', '[]', 'card', 'sha256:b',
            'approved', 1, 2, 3, 'operator', 'n', 'sha256:c', '{}')`)
		exec(`INSERT INTO approval_assertions (approval_id, channel, credential_id, rp_id, origin, assertion_json, assertion_sha256, created_at)
            VALUES ('a-00000` + id + `', 'pc', x'01', 'localhost', 'http://localhost', x'7b7d', 'sha256:d', '2026-10-24T00:00:00Z')`)
	}
	exec(`INSERT INTO denials (denial_id, at, requester_key, project, surface, verb, target, cause_code) VALUES ('d-1', 1, 'run:x', 'p', 'op', 'v', 't', 'C')`)

	count := func(table string) int {
		t.Helper()
		var n int
		if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	tables := []string{"ops", "ops_transitions", "approvals", "approval_assertions", "denials", "approvers"}
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = count(tb)
	}
	if before["ops"] != 2 || before["approvals"] != 2 || before["approval_assertions"] != 2 {
		t.Fatalf("setup: %v", before)
	}

	if err := db.Migrate(ctx, all); err != nil {
		t.Fatalf("migrate to 0010 on a populated database: %v", err)
	}
	for _, tb := range tables {
		if got := count(tb); got != before[tb] {
			t.Errorf("%s: %d rows before, %d after", tb, before[tb], got)
		}
	}
	rows, err := db.SQL().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Error("a foreign key is left dangling after the rebuild")
	}
	rows.Close()
	var scope string
	if err := db.SQL().QueryRowContext(ctx, `SELECT scope_json FROM ops WHERE id = 'q-000001'`).Scan(&scope); err != nil || scope != `{"repo":"a/b"}` {
		t.Errorf("scope_json after the rebuild: %q %v", scope, err)
	}

	refused := func(why, q string) {
		t.Helper()
		if _, err := db.SQL().ExecContext(ctx, q); err == nil {
			t.Errorf("%s: accepted: %s", why, q)
		}
	}
	// The triggers ops and approvals had, one test each.
	refused("illegal op transition", `UPDATE ops SET state = 'succeeded' WHERE id = 'q-000001'`)
	refused("op identity", `UPDATE ops SET op = 'logs' WHERE id = 'q-000001'`)
	refused("op identity (key id)", `UPDATE ops SET key_id = 'k-1' WHERE id = 'q-000001'`)
	refused("op scope", `UPDATE ops SET scope_json = '{}' WHERE id = 'q-000001'`)
	refused("op delete", `DELETE FROM ops WHERE id = 'q-000001'`)
	refused("approval delete", `DELETE FROM approvals WHERE approval_id = 'a-000001'`)
	refused("approval card", `UPDATE approvals SET card_text = 'other' WHERE approval_id = 'a-000001'`)
	refused("approval state", `UPDATE approvals SET state = 'pending' WHERE approval_id = 'a-000001'`)
	refused("approval requester", `UPDATE approvals SET requester_key = 'y' WHERE approval_id = 'a-000001'`)
	// The one-live-op and one-pending-card indexes are back.
	exec(`INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
        run_id, class, reversibility, policy_version, requested_at, expires_at, updated_at)
        VALUES ('q-000009', 'requested', 'deploy', 'p', 'w', 'p', '{}', 'sha256:z', 'run', 'run:y', 'r-9', 'high', 'reversible', 'v', 1, 2, 3)`)
	refused("one live op", `INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
        run_id, class, reversibility, policy_version, requested_at, expires_at, updated_at)
        VALUES ('q-000010', 'requested', 'deploy', 'p', 'w', 'p', '{}', 'sha256:z', 'run', 'run:y', 'r-9', 'high', 'reversible', 'v', 1, 2, 3)`)

	// The new kind: a key op needs its key and its owner and nothing of a run or an orchestrator.
	key := func(extra string) string {
		return `INSERT INTO ops (id, state, op, project, target_adapter, target_ref, params_json, op_hash, requester_kind, requester_key,
        ` + extra + `class, reversibility, policy_version, requested_at, expires_at, updated_at) VALUES `
	}
	exec(key(`key_id, owner_id, `) + `('q-000020', 'requested', 'pr.view', 'p', 'github', 'a/b#1', '{}', 'sha256:k1', 'key', 'key:k-1', 'k-1', 'main', 'routine', 'reversible', 'v', 1, 2, 3)`)
	refused("key without owner", key(`key_id, `)+`('q-000021', 'requested', 'pr.view', 'p', 'github', 'a/b#1', '{}', 'sha256:k2', 'key', 'key:k-2', 'k-2', 'routine', 'reversible', 'v', 1, 2, 3)`)
	refused("key with a run id", key(`key_id, owner_id, run_id, `)+`('q-000022', 'requested', 'pr.view', 'p', 'github', 'a/b#1', '{}', 'sha256:k3', 'key', 'key:k-3', 'k-3', 'main', 'r-1', 'routine', 'reversible', 'v', 1, 2, 3)`)
	refused("run with a key id", key(`key_id, run_id, `)+`('q-000023', 'requested', 'pr.view', 'p', 'github', 'a/b#1', '{}', 'sha256:k4', 'run', 'run:r-4', 'k-4', 'r-4', 'routine', 'reversible', 'v', 1, 2, 3)`)
	refused("a fourth kind", key(`run_id, `)+`('q-000024', 'requested', 'pr.view', 'p', 'github', 'a/b#1', '{}', 'sha256:k5', 'person', 'person:x', 'r-5', 'routine', 'reversible', 'v', 1, 2, 3)`)
}
