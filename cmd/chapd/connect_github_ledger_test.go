package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/store"
)

// connectEvents are the ledger events of a finished connection, checked as a pair by the operator.
func connectEvents(t *testing.T, e *ghEnv) (request, result string) {
	t.Helper()
	evs := ledgerEventsOf(t, e.db)
	if len(evs) != 2 || !strings.HasPrefix(evs[0], "op.request ") || !strings.HasPrefix(evs[1], "op.result ") {
		t.Fatalf("the ledger has %d events, want an op.request and an op.result: %v", len(evs), evs)
	}
	for _, ev := range evs {
		for _, want := range []string{`"factory.requester.kind":"orchestrator"`, `"factory.orchestrator.id":"operator"`} {
			if !strings.Contains(ev, want) {
				t.Errorf("an event lacks %s: %s", want, ev)
			}
		}
	}
	if strings.Contains(strings.Join(evs, "\n"), "op.approve") {
		t.Error("an offline command wrote an approval it cannot have")
	}
	verifyLedgerOf(t, e.db)
	return evs[0], evs[1]
}

func TestConnectGitHubIsRecordedInTheLedger(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-org", "my-org", "-with", "issues,deploy")
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatal(r.both())
	}
	app := e.fake.Apps()[0]
	req, res := connectEvents(t, e)

	for _, want := range []string{
		`"factory.op":"github.app.connect"`, `"factory.reversibility":"compensable"`,
		app.Slug(), "my-org", "organization", "id " + strconv.FormatInt(int64(app.ID()), 10),
		"contents write", "pull_requests write", "metadata read", "issues write", "deployments write",
		"extra groups: deploy, issues", "github-app-key",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("the request lacks %q: %s", want, req)
		}
	}
	if !strings.Contains(res, `"factory.outcome":"succeeded"`) {
		t.Errorf("the result is not a success: %s", res)
	}
	// The pair is one request: the same id and the same hash.
	if id := between(req, `"factory.request_id":"`); id == "" || id != between(res, `"factory.request_id":"`) {
		t.Errorf("request and result do not share a request id: %s / %s", req, res)
	}
	if h := between(req, `"factory.op_hash":"`); h == "" || h != between(res, `"factory.op_hash":"`) {
		t.Errorf("request and result do not share an op_hash")
	}

	// Never a secret: not the private key, not the client secret, not the webhook secret, not the code.
	secrets := secretsOf(app)
	for _, ev := range ledgerEventsOf(t, e.db) {
		assertNoSecrets(t, "a ledger event", ev, secrets)
		if strings.Contains(ev, e.fake.ManifestRequests()[0].Code) {
			t.Error("the temporary code is in the ledger")
		}
	}
	assertNoSecrets(t, "the output", r.both(), secrets)
	if !strings.Contains(r.out.String(), "recorded in the ledger") {
		t.Errorf("the command does not say it recorded the connection:\n%s", r.out.String())
	}
}

func TestConnectGitHubInAUserAccountSaysUser(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "example-user")
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatal(r.both())
	}
	req, _ := connectEvents(t, e)
	if !strings.Contains(req, "the user example-user") || !strings.Contains(req, "extra groups: none") {
		t.Errorf("the request does not say whose App it is: %s", req)
	}
}

// A refusal stores nothing, so it records nothing: the ledger says a connection happened only when one did.
func TestConnectGitHubRefusalsWriteNoLedgerEvent(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "example-user")
	u := r.startURL(t)
	b := newBrowser(t)
	action, manifest := b.openStart(u)
	state := mustQuery(t, action, "state")
	e.fake.SetWebUser("mallory")
	loc := b.postManifest(action, manifest)
	cb := strings.Split(u, "/start/")[0] + "/callback?code=" + mustQuery(t, loc, "code") + "&state=" + state
	if st, _, _ := b.get(cb, browserCallback); st != 200 {
		t.Fatalf("callback %d", st)
	}
	if code := r.wait(t); code != 1 {
		t.Fatalf("exit %d:\n%s", code, r.both())
	}
	if evs := ledgerEventsOf(t, e.db); len(evs) != 0 {
		t.Errorf("%d ledger events for an App that was refused: %v", len(evs), evs)
	}
}

// A ledger that cannot be written is found before GitHub is asked for anything.
func TestConnectGitHubRefusesToStartWhenTheLedgerCannotBeWritten(t *testing.T) {
	e := newGHEnv(t)
	r := e.connect("-user", "example-user")
	if st, _ := newBrowser(t).operator(r.startURL(t)); st != 200 || r.wait(t) != 0 {
		t.Fatal(r.both())
	}
	// Remove the key and record so a second setup would otherwise be allowed, and damage the chain.
	ctx := context.Background()
	d, err := store.Open(ctx, e.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TRIGGER ledger_chains_guard`,
		`UPDATE ledger_chains SET head_hash = 'sha256:` + strings.Repeat("0", 64) + `'`,
		`DELETE FROM vault_secrets WHERE id = 'github-app-key'`,
	} {
		if _, err := d.SQL().ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	d.Close()
	if err := os.Remove(githubAppPath(e.db)); err != nil {
		t.Fatal(err)
	}
	made := len(e.fake.Apps())
	code, out, errs := e.runConnect("-user", "example-user", "-timeout", "5s")
	if code != 1 || !strings.Contains(errs, "Nothing was started") {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if strings.Contains(out, "/start/") || len(e.fake.Apps()) != made || len(e.fake.ManifestRequests()) != 1 {
		t.Error("the command started the flow with a ledger it could not write")
	}
}

// between returns the text after prefix up to the next double quote.
func between(s, prefix string) string {
	_, after, ok := strings.Cut(s, prefix)
	if !ok {
		return ""
	}
	v, _, _ := strings.Cut(after, "\"")
	return v
}
