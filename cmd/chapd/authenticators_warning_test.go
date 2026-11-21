package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/console"
)

// insertPasskey adds an approver (once) and a live credential of the given attachment to a database chapd already migrated.
func insertPasskey(t *testing.T, app *App, name, attachment string, id byte) {
	t.Helper()
	db := app.DB.SQL()
	if _, err := db.Exec(`INSERT OR IGNORE INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), ?, '2026-11-19T00:00:00Z')`, name); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO credentials (approver_id, credential_id, rp_id, origin, public_key, attestation_type, attestation_format,
		aaguid, transports, attachment, sign_count, user_verified, backup_eligible, backup_state, label, created_at)
		VALUES (1, ?, 'localhost', 'http://localhost:55398', x'00', 'none', 'none', x'', '[]', ?, 0, 1, 0, 0, 'k', '2026-11-19T00:00:00Z')`,
		[]byte{id, id, id, id}, attachment); err != nil {
		t.Fatal(err)
	}
}

// chapd says at start when the authenticators setting refuses enrolled passkeys: a warning when some still work, an
// error with the way out when none does (a full lockout). It starts in both cases, and says nothing when the setting
// is "any" or nothing is refused.
func TestStartWarnsWhenTheSettingRefusesPasskeys(t *testing.T) {
	dir := t.TempDir()
	db, keys := filepath.Join(dir, "state.db"), writeKeys(t, dir)
	build := func(a console.Authenticators) (*App, *syncBuf) {
		t.Helper()
		log := &syncBuf{}
		app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keys, Instance: "test", Authenticators: a,
			Log: slog.New(slog.NewTextHandler(log, nil))})
		if err != nil {
			t.Fatal(err) // a lockout must not stop chapd from building
		}
		return app, log
	}
	app, log := build("")
	if strings.Contains(log.String(), "refused by the authenticators setting") {
		t.Fatalf("a warning with no passkeys:\n%s", log)
	}
	insertPasskey(t, app, "operator", "cross-platform", 1)
	app.Close()

	// Full lockout: the only passkey is a security key.
	app, log = build(console.AuthenticatorsPlatform)
	out := log.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "nobody can sign in or approve") || !strings.Contains(out, "-approver-authenticators any") {
		t.Fatalf("no error for a full lockout:\n%s", out)
	}
	insertPasskey(t, app, "operator", "platform", 2)
	app.Close()

	// Partial: one built-in passkey still works.
	app, log = build(console.AuthenticatorsPlatform)
	out = log.String()
	if !strings.Contains(out, "level=WARN") || strings.Contains(out, "level=ERROR") || !strings.Contains(out, "did not report its kind") ||
		!strings.Contains(out, "refused=1") || !strings.Contains(out, "usable=1") {
		t.Fatalf("partial case:\n%s", out)
	}
	app.Close()

	// Wide setting: nothing is refused.
	app, log = build(console.AuthenticatorsAny)
	if strings.Contains(log.String(), "refused by the authenticators setting") {
		t.Fatalf("a warning under any:\n%s", log)
	}
	app.Close()
}
