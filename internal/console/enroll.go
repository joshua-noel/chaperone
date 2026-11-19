package console

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/loopback"
	"github.com/joshua-noel/chaperone/internal/store"
)

// DefaultAddr is the console's loopback listen address (ADR-004, house rules).
const DefaultAddr = "127.0.0.1:55398"

// EnrollOptions configures [RunEnroll], the body of `chapd enroll`.
type EnrollOptions struct {
	DBPath string        // state.db; created and migrated if missing
	Addr   string        // listen address; default [DefaultAddr]
	Origin Origin        // default [LocalOrigin]; its host:port must be what Addr serves
	TTL    time.Duration // how long each step may take; default 10 minutes
	Name   string        // approver name for the first enrolment; default "operator"
	// Authenticators is which kinds of authenticator may be enrolled; default [AuthenticatorsPlatform].
	Authenticators Authenticators
	// CheckOnly skips enrolment and waits for one sign-in (an approver must
	// already exist). Use it to repeat the assertion half of the H3 check.
	CheckOnly bool
	Out       io.Writer
}

// RunEnroll is `chapd enroll` (human-gated step H3). It
//
//  1. opens and migrates the database,
//  2. refuses if an approver already exists (unless CheckOnly),
//  3. prints a one-time address for the browser,
//  4. serves the console on Addr until the Windows Hello registration lands,
//  5. then waits for one sign-in and prints the verified flags.
//
// Each step ends the command with an error after TTL or when ctx is done.
// Nothing is written to Out that works as a credential after the command ends.
func RunEnroll(ctx context.Context, o EnrollOptions) error {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Addr == "" {
		o.Addr = DefaultAddr
	}
	if o.Origin.URL == "" {
		o.Origin = LocalOrigin
	}
	if o.TTL == 0 {
		o.TTL = 10 * time.Minute
	}
	if o.Name == "" {
		o.Name = "operator"
	}

	db, err := store.Open(ctx, o.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ms, err := store.Migrations()
	if err != nil {
		return err
	}
	if err := db.Migrate(ctx, ms); err != nil {
		return err
	}

	events := make(chan Event, 8)
	con, err := New(Config{
		DB:             db,
		Authenticators: o.Authenticators,
		Origins:        []Origin{o.Origin},
		OnEvent: func(e Event) {
			select {
			case events <- e:
			default: // nobody is waiting; the console must not block
			}
		},
	})
	if err != nil {
		return err
	}

	n, err := con.approverCount(ctx)
	if err != nil {
		return err
	}
	switch {
	case o.CheckOnly && n == 0:
		return errors.New("chapd enroll --check: no approver is enrolled yet; run chapd enroll first")
	case !o.CheckOnly && n > 0:
		return errors.New("chapd enroll: an approver is already enrolled. " +
			"Run `chapd enroll --check` to test sign-in. Adding another device is the approvers.enroll operation, not this command")
	}

	var token string
	if !o.CheckOnly {
		if token, err = IssueEnrollment(ctx, db, nil, o.TTL, time.Now()); err != nil {
			return err
		}
	}
	// Both loopback addresses: the browser is sent to localhost, which may mean ::1, and
	// whoever listens there would read the one-time address (internal/loopback).
	lns, err := loopback.Bind(o.Addr, net.Listen, " (is chapd already running? stop it first)")
	if err != nil {
		return fmt.Errorf("chapd enroll: %w", err)
	}
	defer loopback.CloseAll(lns)

	srv := &http.Server{
		Handler:           con.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	for _, ln := range lns {
		go func() { _ = srv.Serve(ln) }()
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if !o.CheckOnly {
		fmt.Fprintf(o.Out, "Passkey enrolment (step H3)\n\n"+
			"1. Open this address in a browser on the server (it works once, for %s):\n\n   %s/enroll#%s\n\n"+
			"2. Click \"Create passkey\" and approve with your PIN, fingerprint or face.\n\n",
			o.TTL, o.Origin.URL, token)
		if o.Authenticators == AuthenticatorsAny {
			fmt.Fprint(o.Out, "   A hardware security key or a phone is allowed too: choose it in the browser's prompt.\n\n")
		}
		if _, err := waitFor(ctx, events, EventEnrolled, o.TTL, o.Out); err != nil {
			return err
		}
	}
	fmt.Fprintf(o.Out, "\nNow test the assertion. Open %s/login, click \"Sign in with a passkey\" and approve.\n\n", o.Origin.URL)
	if _, err := waitFor(ctx, events, EventLogin, o.TTL, o.Out); err != nil {
		return err
	}
	fmt.Fprintln(o.Out, "\nDone. Paste the lines starting with OK into the L1-06 PR as the H3 evidence.")
	return nil
}

// waitFor prints each event until one named want arrives.
func waitFor(ctx context.Context, events <-chan Event, want string, ttl time.Duration, out io.Writer) (Event, error) {
	timer := time.NewTimer(ttl)
	defer timer.Stop()
	for {
		select {
		case e := <-events:
			switch e.Name {
			case want:
				fmt.Fprintf(out, "OK %s credential_id=%s rp_id=%s origin=%s uv=%t sign_count=%d approver_id=%d attachment=%s transports=%s backup_eligible=%t\n",
					e.Name, b64.EncodeToString(e.CredentialID), e.RPID, e.Origin, e.UserVerified, e.SignCount, e.ApproverID, cmp.Or(e.Attachment, "unreported"), cmp.Or(strings.Join(e.Transports, ","), "none"), e.BackupEligible)
				return e, nil
			case EventRefused:
				fmt.Fprintf(out, "REFUSED reason=%s detail=%q\n", e.Reason, e.Detail)
			}
		case <-timer.C:
			return Event{}, fmt.Errorf("chapd enroll: timed out after %s waiting for %s", ttl, want)
		case <-ctx.Done():
			return Event{}, ctx.Err()
		}
	}
}
