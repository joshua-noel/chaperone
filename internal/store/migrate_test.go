package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

var threeMigrations = []Migration{
	{Version: 1, Name: "create_a", SQL: `CREATE TABLE a (id INTEGER PRIMARY KEY) STRICT;`},
	{Version: 2, Name: "create_b", SQL: "CREATE TABLE b (id INTEGER PRIMARY KEY) STRICT;\nCREATE INDEX b_id ON b (id);"},
	{Version: 3, Name: "create_c", SQL: `CREATE TABLE c (id INTEGER PRIMARY KEY) STRICT;`},
}

func tableExists(t *testing.T, d *DB, name string) bool {
	t.Helper()
	var n int
	if err := d.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func schemaVersion(t *testing.T, d *DB) int {
	t.Helper()
	v, err := d.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMigrateAppliesInOrderAndIsIdempotent(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if v := schemaVersion(t, d); v != 0 {
		t.Fatalf("fresh database at version %d, want 0", v)
	}
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"a", "b", "c"} {
		if !tableExists(t, d, tbl) {
			t.Errorf("table %s missing", tbl)
		}
	}
	if v := schemaVersion(t, d); v != 3 {
		t.Fatalf("version %d, want 3", v)
	}
	// A second run changes nothing and does not fail.
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var rows int
	if err := d.SQL().QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("schema_migrations has %d rows (err %v), want 3", rows, err)
	}
}

func TestMigrateAddsLaterMigrations(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, threeMigrations[:2]); err != nil {
		t.Fatal(err)
	}
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, d); v != 3 {
		t.Fatalf("version %d, want 3", v)
	}
}

// The acceptance case: version 2 is applied, then a list that gains a
// version 1 migration it never ran is refused.
func TestMigrateRefusesOutOfOrderPendingMigration(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, []Migration{threeMigrations[1], threeMigrations[2]}); err != nil {
		t.Fatal(err)
	}
	err := d.Migrate(ctx, threeMigrations) // 1 is new but 3 is already applied
	if !errors.Is(err, ErrMigrationOrder) {
		t.Fatalf("got %v, want ErrMigrationOrder", err)
	}
	if tableExists(t, d, "a") {
		t.Fatal("the out-of-order migration ran anyway")
	}
	if v := schemaVersion(t, d); v != 3 {
		t.Fatalf("version %d after refusal, want 3", v)
	}
}

func TestMigrateRefusesUnorderedOrDuplicateList(t *testing.T) {
	cases := map[string][]Migration{
		"descending": {threeMigrations[1], threeMigrations[0]},
		"duplicate":  {threeMigrations[0], threeMigrations[0]},
		"zero":       {{Version: 0, Name: "zero", SQL: "SELECT 1"}},
		"negative":   {{Version: -1, Name: "neg", SQL: "SELECT 1"}},
	}
	for name, ms := range cases {
		t.Run(name, func(t *testing.T) {
			d := openTemp(t)
			if err := d.Migrate(context.Background(), ms); !errors.Is(err, ErrMigrationOrder) {
				t.Fatalf("got %v, want ErrMigrationOrder", err)
			}
			if tableExists(t, d, "schema_migrations") {
				t.Fatal("database was touched before the list was validated")
			}
		})
	}
}

func TestMigrateRefusesEmptyNameOrSQL(t *testing.T) {
	for name, m := range map[string]Migration{
		"no name": {Version: 1, SQL: "SELECT 1"},
		"no sql":  {Version: 1, Name: "x", SQL: " \n"},
	} {
		t.Run(name, func(t *testing.T) {
			d := openTemp(t)
			if err := d.Migrate(context.Background(), []Migration{m}); err == nil {
				t.Fatal("got nil, want an error")
			}
		})
	}
}

func TestMigrateRefusesEditedMigration(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
	edited := append([]Migration(nil), threeMigrations...)
	edited[1].SQL += "\nCREATE TABLE sneaky (id INTEGER PRIMARY KEY) STRICT;"
	if err := d.Migrate(ctx, edited); !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf("edited SQL: got %v, want ErrMigrationChecksum", err)
	}
	renamed := append([]Migration(nil), threeMigrations...)
	renamed[0].Name = "renamed"
	if err := d.Migrate(ctx, renamed); !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf("renamed: got %v, want ErrMigrationChecksum", err)
	}
	if tableExists(t, d, "sneaky") {
		t.Fatal("edited migration ran")
	}
}

func TestMigrateChecksumIgnoresLineEndings(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
	crlf := append([]Migration(nil), threeMigrations...)
	crlf[1].SQL = strings.ReplaceAll(crlf[1].SQL, "\n", "\r\n")
	if err := d.Migrate(ctx, crlf); err != nil {
		t.Fatalf("CRLF checkout of an applied migration was refused: %v", err)
	}
}

func TestMigrateRefusesDowngrade(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
	if err := d.Migrate(ctx, threeMigrations[:2]); !errors.Is(err, ErrMigrationUnknown) {
		t.Fatalf("got %v, want ErrMigrationUnknown", err)
	}
}

func TestMigrateIsAllOrNothing(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	if err := d.Migrate(ctx, threeMigrations[:1]); err != nil {
		t.Fatal(err)
	}
	bad := []Migration{
		threeMigrations[0],
		threeMigrations[1],
		{Version: 3, Name: "broken", SQL: "CREATE TABLE ok (id INTEGER) STRICT;\nTHIS IS NOT SQL;"},
	}
	err := d.Migrate(ctx, bad)
	if err == nil || !strings.Contains(err.Error(), "0003_broken") {
		t.Fatalf("got %v, want an error naming 0003_broken", err)
	}
	for _, tbl := range []string{"b", "ok"} {
		if tableExists(t, d, tbl) {
			t.Errorf("table %s survived a failed run", tbl)
		}
	}
	if v := schemaVersion(t, d); v != 1 {
		t.Fatalf("version %d after failed run, want 1", v)
	}
	// And the fixed list then applies cleanly.
	if err := d.Migrate(ctx, threeMigrations); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMigrations(t *testing.T) {
	fsys := fstest.MapFS{
		"m/0002_second.sql": {Data: []byte("SELECT 2;")},
		"m/0001_first.sql":  {Data: []byte("SELECT 1;")},
	}
	ms, err := LoadMigrations(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Version != 1 || ms[0].Name != "first" || ms[1].Version != 2 || ms[1].SQL != "SELECT 2;" {
		t.Fatalf("got %+v", ms)
	}
	for _, bad := range []string{"m/1_short.sql", "m/0001_Upper.sql", "m/0001-dash.sql", "m/notes.txt"} {
		_, err := LoadMigrations(fstest.MapFS{bad: {Data: []byte("x")}}, "m")
		if err == nil {
			t.Errorf("LoadMigrations accepted %q", bad)
		}
	}
}

func TestEmbeddedMigrationsApplyAndAreOrdered(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].Version != 1 {
		t.Fatalf("embedded migrations %+v: want at least version 1", ms)
	}
	for i, m := range ms {
		if m.Version != i+1 {
			t.Errorf("embedded migration %s sits at position %d: versions must be contiguous from 1", m.label(), i+1)
		}
	}
	d, err := Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Migrate(context.Background(), ms); err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, d); v != ms[len(ms)-1].Version {
		t.Fatalf("version %d, want %d", v, ms[len(ms)-1].Version)
	}
}
