package approvals

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// Number matching for the phone passkey (ticket L1-22, ADR-004 section 5).
//
// The server card shows one two-digit number. The phone page shows the same card
// text, rendered by the server, and three numbers: the server's and two decoys. The
// approver taps the one he sees on the server. A right tap lets the phone ask for a
// challenge (one assertion then approves, any approve-tier op, decision #15); a
// wrong tap denies the card at once and starts the sticky-deny cooldown. There
// is no second try, so the number cannot be found by guessing: a blind tap on a
// phone page is right one time in three and wrong two times in three, and a
// wrong tap costs the attacker the card for 60 minutes.
//
// The numbers are made once per card and kept, so reloading the phone page
// shows the same three in the same order (two renders could otherwise be
// compared to find the common number).

// PhoneEnabled reports whether the phone channel is on.
func (e *Engine) PhoneEnabled() bool { return len(e.cfg.PhoneOrigins) > 0 }

// channelOf says which device a decision begun at origin is: the phone for a
// configured phone origin, otherwise the server.
func (e *Engine) channelOf(origin string) string {
	if slices.Contains(e.cfg.PhoneOrigins, origin) {
		return "phone"
	}
	return "pc"
}

// IsPhoneOrigin reports whether origin is one of the phone's.
func (e *Engine) IsPhoneOrigin(origin string) bool { return e.channelOf(origin) == "phone" }

// phoneNumbers is one card's stored numbers.
type phoneNumbers struct {
	code    string
	choices [3]string
}

// randTwoDigits returns a uniform number from 10 to 99 as text.
func randTwoDigits() string {
	for {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("approvals: crypto/rand failed: " + err.Error()) // no safe fallback exists
		}
		// 90 values; reject the tail of the byte range so none is likelier.
		if b[0] < 180 {
			return fmt.Sprintf("%d", 10+int(b[0])%90)
		}
	}
}

// newPhoneNumbers draws a code, two different decoys, and a uniform order.
func newPhoneNumbers() phoneNumbers {
	p := phoneNumbers{code: randTwoDigits()}
	all := []string{p.code}
	for len(all) < 3 {
		if n := randTwoDigits(); !slices.Contains(all, n) {
			all = append(all, n)
		}
	}
	// Fisher-Yates with unbiased draws: j is uniform in [0, i].
	for i := len(all) - 1; i > 0; i-- {
		var j int
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic("approvals: crypto/rand failed: " + err.Error())
			}
			if int(b[0]) < 256-256%(i+1) {
				j = int(b[0]) % (i + 1)
				break
			}
		}
		all[i], all[j] = all[j], all[i]
	}
	copy(p.choices[:], all)
	return p
}

// phoneNumbersTx returns the numbers of a pending card, making them the first time.
func (e *Engine) phoneNumbersTx(ctx context.Context, tx *store.Tx, approvalID string, now time.Time) (phoneNumbers, error) {
	var p phoneNumbers
	var choices string
	err := tx.QueryRowContext(ctx, `SELECT code, choices FROM approval_phone_numbers WHERE approval_id = ?`, approvalID).Scan(&p.code, &choices)
	switch {
	case err == nil:
		parts := strings.Split(choices, ",")
		if len(parts) != 3 {
			return p, fmt.Errorf("approvals: %s: stored phone numbers are malformed", approvalID)
		}
		copy(p.choices[:], parts)
		return p, nil
	case !errors.Is(err, sql.ErrNoRows):
		return p, err
	}
	p = newPhoneNumbers()
	_, err = tx.ExecContext(ctx, `INSERT INTO approval_phone_numbers (approval_id, code, choices, created_unix) VALUES (?, ?, ?, ?)`,
		approvalID, p.code, strings.Join(p.choices[:], ","), now.Unix())
	return p, err
}

// phoneNumbersFor loads or makes the numbers of a card that is still pending.
func (e *Engine) phoneNumbersFor(ctx context.Context, approvalID string) (phoneNumbers, error) {
	var p phoneNumbers
	var refusal *Refusal
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		now := e.now()
		if _, err := e.sweepTx(ctx, tx); err != nil {
			return err
		}
		a, err := getApproval(ctx, tx, approvalID)
		if err != nil {
			return err
		}
		switch {
		case a == nil:
			refusal = refuse(CodeNoSuchApproval, "there is no such approval")
			return nil
		case a.State != StatePending:
			refusal = decidable(a)
			return nil
		}
		p, err = e.phoneNumbersTx(ctx, tx, a.ID, now)
		return err
	})
	if err != nil {
		return p, err
	}
	if refusal != nil {
		return p, refusal
	}
	return p, nil
}

// PCNumber is the two-digit number the server card shows for a pending card. Show
// it on the server console only, never on the phone page.
func (e *Engine) PCNumber(ctx context.Context, approvalID string) (string, error) {
	if !e.PhoneEnabled() {
		return "", refuse(CodePolicyRefused, "the phone channel is not enabled")
	}
	p, err := e.phoneNumbersFor(ctx, approvalID)
	return p.code, err
}

// PhoneChoices are the three numbers the phone page shows for a pending card,
// in the order to show them. The same three, in the same order, every time.
func (e *Engine) PhoneChoices(ctx context.Context, approvalID string) ([3]string, error) {
	if !e.PhoneEnabled() {
		return [3]string{}, refuse(CodePolicyRefused, "the phone channel is not enabled")
	}
	p, err := e.phoneNumbersFor(ctx, approvalID)
	return p.choices, err
}

// PhoneMatchInput is a tap on one of the three numbers.
type PhoneMatchInput struct {
	ApprovalID string
	Actor      Actor
	// Origin is the console origin the tap arrived at; it must be a phone origin.
	Origin string
	// Binding ties the match to the browser that made it (a hash of its csrf cookie).
	Binding []byte
	Choice  string
}

// PhoneMatchResult is what a tap did.
type PhoneMatchResult struct {
	// Matched is true when the number was right: the phone may now begin a decision.
	Matched bool
	// Denied is the card, denied, when the number was wrong.
	Denied *Approval
}

// PhoneMatch checks the number the approver tapped on the phone. A wrong
// number, or one that is not among the three shown, denies the card (reason
// "wrong number on the phone") in the same transaction, so the same op hash is
// refused for the sticky-deny window and the ledger records the denial. A right
// number stores a one-use permission for this approver and this browser that
// [Engine.BeginDecision] takes at the phone origin.
func (e *Engine) PhoneMatch(ctx context.Context, in PhoneMatchInput) (PhoneMatchResult, error) {
	if err := e.checkActor(ctx, in.Actor, in.ApprovalID); err != nil {
		return PhoneMatchResult{}, err
	}
	if e.channelOf(in.Origin) != "phone" {
		return PhoneMatchResult{}, &Refusal{Code: CodeAssertion, Why: "channel_not_enabled", ApprovalID: in.ApprovalID}
	}
	var res PhoneMatchResult
	var refusal *Refusal
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		now := e.now()
		if _, err := e.sweepTx(ctx, tx); err != nil {
			return err
		}
		a, err := getApproval(ctx, tx, in.ApprovalID)
		if err != nil {
			return err
		}
		if a == nil {
			refusal = refuse(CodeNoSuchApproval, "there is no such approval")
			return nil
		}
		if refusal = decidable(a); refusal != nil {
			return nil
		}
		if refusal = verifyCard(a); refusal != nil {
			return nil
		}
		p, err := e.phoneNumbersTx(ctx, tx, a.ID, now)
		if err != nil {
			return err
		}
		if len(in.Choice) != 2 || subtle.ConstantTimeCompare([]byte(in.Choice), []byte(p.code)) != 1 {
			res.Denied, refusal, err = e.denyTx(ctx, tx, a.ID, in.Actor.ApproverID,
				"number matching failed: the number chosen on the phone was not the one on the server card")
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM approval_phone_matches WHERE valid_until_unix < ?`, now.Unix()); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO approval_phone_matches (approval_id, approver_row, binding_sha256, valid_until_unix) VALUES (?, ?, ?, ?)
			 ON CONFLICT (approval_id, approver_row, binding_sha256) DO UPDATE SET valid_until_unix = excluded.valid_until_unix`,
			a.ID, in.Actor.ApproverRow, nonNil(in.Binding), now.Add(e.chap.ChallengeTTL).Unix())
		res.Matched = err == nil
		return err
	})
	if err != nil {
		return PhoneMatchResult{}, err
	}
	if refusal != nil {
		return PhoneMatchResult{}, refusal
	}
	return res, nil
}

// takeMatch deletes and checks the permission a right number left. Without it
// the phone decision is refused. It runs inside BeginDecision's transaction.
func (e *Engine) takeMatch(ctx context.Context, tx *store.Tx, approvalID string, approverRow int64, binding []byte, now time.Time) (*Refusal, error) {
	var until int64
	err := tx.QueryRowContext(ctx,
		`DELETE FROM approval_phone_matches WHERE approval_id = ? AND approver_row = ? AND binding_sha256 = ?
		 RETURNING valid_until_unix`, approvalID, approverRow, nonNil(binding)).Scan(&until)
	switch {
	case errors.Is(err, sql.ErrNoRows) || (err == nil && until < now.Unix()):
		return &Refusal{Code: CodeNumberRequired, ApprovalID: approvalID,
			Why: "choose the number shown on the server card first"}, nil
	case err != nil:
		return nil, err
	}
	return nil, nil
}
