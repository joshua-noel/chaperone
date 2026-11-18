package ops

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/redact"
)

// An adapter's error text can quote a credential it was given (a tool that
// echoes its arguments, an HTTP client that prints a URL). chapd logs that text;
// the log must hold it masked.
func TestAdapterErrorIsMaskedInTheLog(t *testing.T) {
	const secret = "cnry-7d67d4cc000091f619c05d1d-not-a-pattern"
	reg := redact.NewRegistry()
	if err := reg.Set("canary", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	g := newRig(t, rigOpts{enable: []string{"health"}})
	var logs bytes.Buffer
	g.svc.redactor = reg
	g.svc.log = slog.New(slog.NewTextHandler(&logs, nil))
	g.ad.execute = func(context.Context, *Request) (Outcome, error) {
		return Outcome{}, errors.New("upstream said: bad credential " + secret)
	}
	st, body, _ := g.call("POST", "/v0/ops", runTok, health())
	if st != 202 && st != 200 {
		t.Fatalf("status %d: %v", st, body)
	}
	if body["state"] != "unconfirmed" {
		t.Fatalf("state = %v", body["state"])
	}
	if !strings.Contains(logs.String(), "adapter result unknown") {
		t.Fatalf("the failure was not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("the adapter's error reached the log unmasked:\n%s", logs.String())
	}
}
