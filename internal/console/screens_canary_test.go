package console

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// forms lists the ways a value may be written down by accident: as is, base64
// (standard, URL, raw), hex, and URL-escaped (ADR-003 item 8).
func forms(v string) []string {
	b := []byte(v)
	return []string{
		v,
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(v),
	}
}

// fileBytes reads every file under dir (the vault's ciphertext is read too,
// where nothing should read as the plaintext either).
func fileBytes(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				t.Fatal(rerr)
			}
			sb.Write(b)
		}
		return nil
	})
	return sb.String()
}

// TestNoScreenRendersASecret is the canary test of L1-20 (ADR-003 item 8): a
// value that was imported, one that is waiting for its approval, one that was
// written then rotated, and a live orchestrator token. Every screen, every
// action response, the ledger, its export, the log and the database file are
// searched for each of them in every form a leak could take.
func TestNoScreenRendersASecret(t *testing.T) {
	sr := newScrRig(t)
	b, auth := sr.signedIn()
	ctx := context.Background()

	const (
		stored  = "canary-STORED-5c1e90b7aa31f4d2-do-not-show"
		held    = "canary-HELD-77ab03e1c9d25b68-do-not-show"
		rotated = "canary-ROTATED-e41d8a6f02b79c35-do-not-show"
		old     = "canary-OLD-0b9f3d7a6e1c8254-do-not-show"
		pemLike = "-----BEGIN PRIVATE KEY-----\ncanary-PEM-3fa91c07d5e2b846\n-----END PRIVATE KEY-----"
	)
	orchToken := sr.issueOrch("main")
	canaries := []string{stored, held, rotated, old, pemLike, orchToken, strings.TrimPrefix(orchToken, runtoken.OrchPrefix)}

	// A value put in the vault directly, and one the operator imports through the console.
	if _, err := sr.vault.Import(ctx, vault.Meta{ID: "direct-one", Kind: "test"}, []byte(stored)); err != nil {
		t.Fatal(err)
	}
	id := sr.requestSecret(b, importForm("console-one", old))
	sr.approveCard(b, auth, id) // the approval stores the value by itself
	if sr.state(id) != approvals.StateConsumed {
		t.Fatalf("import: state %s", sr.state(id))
	}
	// ... which is rotated through the console too, and one more that is only waiting.
	id = sr.requestSecret(b, url.Values{"action": {"rotate"}, "id": {"console-one"}, "value": {rotated}})
	sr.approveCard(b, auth, id)
	if sr.state(id) != approvals.StateConsumed {
		t.Fatalf("rotate: state %s", sr.state(id))
	}
	sr.requestSecret(b, importForm("waiting-one", held))
	sr.requestSecret(b, importForm("pem-one", pemLike)) // two cards at once is the cap

	// Something that tries to put a secret in the ledger (a denial text built from an agent's input).
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "deploy leaked "+stored+" and "+rotated)
	sr.seedRun("r-aaaa1", "acme-shop")

	// Every screen, and the fragments the actions answer with.
	var seen []string
	for _, p := range []string{"/", "/catalog", "/ledger", "/ledger?event=denial", "/ledger?op=secrets.write", "/ledger?event=op.result",
		"/runs", "/secrets", "/approvals", "/ledger?run=r-aaaa1"} {
		seen = append(seen, p+"\n"+get(t, b, p))
	}
	for _, p := range []string{"/ledger/verify", "/stop-all", "/secrets/a-nothere/commit", "/secrets/a-nothere/cancel", "/runs/r-aaaa1/revoke", "/orchestrators/main/revoke"} {
		rec := hxPost(b, p, url.Values{})
		seen = append(seen, p+"\n"+rec.Body.String())
	}
	for _, f := range []url.Values{
		importForm("bad id!", held), importForm("direct-one", held), // refused with the value in the form
		{"action": {"rotate"}, "id": {"nope"}, "value": {held}},
	} {
		seen = append(seen, "request refused\n"+hxPost(b, "/secrets/request", f).Body.String())
	}

	// The record, the export, the log and the database file.
	evs, err := sr.led.Query(ctx, ledger.QueryParams{Limit: ledger.MaxQueryLimit})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(evs)
	if _, err := sr.led.Export(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sr.db.SQL().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	var dbPath string
	var seq int
	var name string
	if err := sr.db.SQL().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &dbPath); err != nil {
		t.Fatal(err)
	}
	seen = append(seen, "ledger events\n"+string(raw), "export\n"+fileBytes(t, sr.export), "log\n"+sr.logs.String(),
		"database\n"+fileBytes(t, filepath.Dir(dbPath)))

	// The sources of the canaries must not appear in these where only a leak could put them.
	for _, c := range canaries {
		for _, form := range forms(c) {
			for _, where := range seen {
				if strings.Contains(where, form) {
					head, _, _ := strings.Cut(where, "\n")
					t.Errorf("%q leaked (as %.40q...) in %s", c[:min(len(c), 24)], form, head)
				}
			}
		}
	}
	// Control: the screens did render, and the vault does hold what was written.
	if !strings.Contains(strings.Join(seen, ""), "console-one") || sr.secretValue("console-one") != rotated {
		t.Fatal("the canary test did not exercise the screens")
	}
	if res := sr.secretValue("direct-one"); res != stored {
		t.Fatalf("direct-one holds %q", res)
	}
}

// TestScreenResponsesCarryTheGuardHeaders: every screen is no-store, framed
// by nobody and allowed to run script only from this origin.
func TestScreenResponsesCarryTheGuardHeaders(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	for _, p := range []string{"/", "/catalog", "/ledger", "/runs", "/secrets"} {
		rec := b.do("GET", p, nil, nil)
		h := rec.Header()
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'self'") ||
			!strings.HasPrefix(h.Get("Content-Type"), "text/html") {
			t.Errorf("GET %s headers: %v", p, h)
		}
	}
}
