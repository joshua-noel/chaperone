package approvals

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

var b64 = base64.RawURLEncoding

// maxChallenges bounds the decision challenges in flight, so a flood of begin
// calls cannot grow the table (the console is reachable by any local process).
const maxChallenges = 64

// Challenge is one decision challenge in flight.
type Challenge struct {
	// ID is the random handle the browser sends back with its response.
	ID         []byte
	ApprovalID string
	// Raw is the 32-byte WebAuthn challenge: the SHA-256 that
	// spec.ApprovalChallenge returns, as bytes.
	Raw           []byte
	Hash          string // "sha256:<hex>" form of Raw
	DisplaySHA256 string
	Nonce         string
	// Expires is the approval's expires_at that the challenge binds.
	Expires time.Time
	// ValidUntil is the last instant the challenge may be answered.
	ValidUntil  time.Time
	ApproverRow int64
	Approver    string
	Origin      string
	binding     []byte
}

// BeginInput starts a decision.
type BeginInput struct {
	ApprovalID string
	Actor      Actor
	// Origin is the console origin URL the operator is on.
	Origin string
	// Binding ties the challenge to one browser (a hash of its csrf cookie).
	Binding []byte
}

// breach refuses a token that tried to decide an approval, and asks for the stop.
func (e *Engine) breach(ctx context.Context, actor Actor, approvalID string) error {
	r := &Refusal{Code: CodeBreach, Stop: StopBreach, ApprovalID: approvalID,
		Why: "a token cannot decide an approval, its own or anyone's"}
	if e.cfg.Stop != nil {
		s := Stop{Code: StopBreach, Why: r.Why}
		switch actor.Kind {
		case ActorRun:
			s.RequesterKind, s.RequesterKey, s.RunID = "run", actor.RunID, actor.RunID
		case ActorOrchestrator:
			s.RequesterKind, s.RequesterKey = "orchestrator", actor.ID
		}
		if err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			return e.cfg.Stop(ctx, tx, s)
		}); err != nil {
			return err
		}
	}
	return r
}

func (e *Engine) checkActor(ctx context.Context, actor Actor, approvalID string) error {
	if actor.Kind != ActorApprover {
		return e.breach(ctx, actor, approvalID)
	}
	if actor.ApproverRow <= 0 || actor.ApproverID == "" {
		return errors.New("approvals: an approver Actor needs ApproverRow and ApproverID")
	}
	return nil
}

// decidable maps the state of a card to the refusal a decision on it gets, or nil when it is pending.
func decidable(a *Approval) *Refusal {
	var r *Refusal
	switch a.State {
	case StatePending:
		return nil
	case StateApproved, StateConsumed:
		r = refuse(CodeConsumed, "this approval has already been decided and used")
	case StateDenied:
		r = refuse(CodeDenied, "this request was denied")
	case StateCancelled:
		r = refuse(CodeDenied, "this request was cancelled")
	default:
		r = refuse(CodeExpired, "this request expired before it was decided")
	}
	r.ApprovalID = a.ID
	return r
}

// verifyCard re-derives, from the stored request, what the card must say, and
// refuses when the stored op hash or the stored text no longer match it.
func verifyCard(a *Approval) *Refusal {
	if h, err := spec.OpHash(a.Request); err != nil || h != a.OpHash {
		return &Refusal{Code: CodeHashMismatch, ApprovalID: a.ID, Why: "the stored request does not hash to the op hash that was approved"}
	}
	text, err := renderCard(a)
	if err != nil || text != a.CardText || DisplayHash(a.CardText) != a.DisplaySHA256 {
		return &Refusal{Code: CodeDisplayMismatch, ApprovalID: a.ID, Why: "the card text does not match the request it was made from"}
	}
	return nil
}

// record builds the spec approval document up to (not including) its
// confirmations. The challenge covers exactly: approval_id, request_id, run_id,
// op_hash, decision, approver id, nonce, expires_at, policy_version and
// display_sha256.
func record(a *Approval, decision, approverID, nonce string, expires time.Time) spec.Approval {
	return spec.Approval{
		SpecVersion: spec.SpecVersion, Type: "op.approval", ApprovalID: a.ID, RequestID: a.RequestID, RunID: a.RunID,
		OpHash: a.OpHash, Decision: decision, PolicyVersion: a.PolicyVersion, Checks: nonNilChecks(a.Checks),
		Shown:         spec.Shown{DisplaySHA256: a.DisplaySHA256, Channels: []string{"pc"}},
		Confirmations: []spec.Confirmation{}, Approver: spec.Approver{ID: approverID}, Nonce: nonce, SingleUse: true,
		ExpiresAt: ts(expires),
	}
}

func challengeBytes(hash string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(hash, "sha256:"))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("approvals: challenge %q is not a SHA-256", hash)
	}
	return raw, nil
}

func newNonce() string {
	b := make([]byte, 24) // 192 bits; spec: ^[A-Za-z0-9_-]{22,64}$ (128+ bits)
	if _, err := rand.Read(b); err != nil {
		panic("approvals: crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
	return b64.EncodeToString(b)
}

// BeginDecision makes the challenge an approver's authenticator signs to approve
// one card. It writes nothing the card depends on; an unanswered challenge just
// ages out. Several may be in flight for a card; each has its own nonce.
func (e *Engine) BeginDecision(ctx context.Context, in BeginInput) (*Challenge, error) {
	if err := e.checkActor(ctx, in.Actor, in.ApprovalID); err != nil {
		return nil, err
	}
	var ch *Challenge
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM approval_challenges WHERE valid_until_unix < ?`, now.Unix()); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_challenges`).Scan(&n); err != nil {
			return err
		}
		if n >= maxChallenges {
			refusal = refuse(CodePolicyRefused, "too many decisions are in progress")
			return nil
		}
		if e.channelOf(in.Origin) == "phone" {
			// Number matching (ADR-004 section 5): the phone may only ask for a
			// challenge after its approver chose the number on the server card.
			if refusal, err = e.takeMatch(ctx, tx, a.ID, in.Actor.ApproverRow, in.Binding, now); err != nil || refusal != nil {
				return err
			}
		}
		nonce := newNonce()
		expires := now.Add(e.chap.ChallengeTTL + e.chap.ApprovalTTL).Truncate(time.Second)
		rec := record(a, "approved", in.Actor.ApproverID, nonce, expires)
		hash, err := spec.ApprovalChallenge(rec)
		if err != nil {
			return fmt.Errorf("approvals: challenge for %s: %w", a.ID, err)
		}
		raw, err := challengeBytes(hash)
		if err != nil {
			return err
		}
		ch = &Challenge{ID: make([]byte, 16), ApprovalID: a.ID, Raw: raw, Hash: hash, DisplaySHA256: a.DisplaySHA256,
			Nonce: nonce, Expires: expires, ValidUntil: now.Add(e.chap.ChallengeTTL), ApproverRow: in.Actor.ApproverRow,
			Approver: in.Actor.ApproverID, Origin: in.Origin, binding: in.Binding}
		if _, err := rand.Read(ch.ID); err != nil {
			panic("approvals: crypto/rand failed: " + err.Error())
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO approval_challenges (id, approval_id, decision, approver, approver_row, origin, binding_sha256, nonce,
				challenge_sha256, approval_expires_unix, valid_until_unix)
			 VALUES (?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, ?)`,
			ch.ID, a.ID, ch.Approver, ch.ApproverRow, ch.Origin, nonNil(ch.binding), ch.Nonce, ch.Hash, expires.Unix(),
			ch.ValidUntil.Unix())
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return nil, refusal
	}
	return ch, nil
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// takeChallenge deletes and returns a challenge in one statement. Whatever
// happens next, it is gone: a response can be tried once.
func (e *Engine) takeChallenge(ctx context.Context, id []byte) (*Challenge, error) {
	var (
		ch                 Challenge
		expires, validUtil int64
	)
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.QueryRowContext(ctx,
			`DELETE FROM approval_challenges WHERE id = ?
			 RETURNING id, approval_id, approver, approver_row, origin, binding_sha256, nonce, challenge_sha256,
			           approval_expires_unix, valid_until_unix`, id).
			Scan(&ch.ID, &ch.ApprovalID, &ch.Approver, &ch.ApproverRow, &ch.Origin, &ch.binding, &ch.Nonce, &ch.Hash,
				&expires, &validUtil)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ch.Expires, ch.ValidUntil = time.Unix(expires, 0).UTC(), time.Unix(validUtil, 0).UTC()
	if ch.Raw, err = challengeBytes(ch.Hash); err != nil {
		return nil, err
	}
	return &ch, nil
}

// ApproveInput finishes an approval: the browser's answer to a challenge.
type ApproveInput struct {
	ApprovalID  string
	ChallengeID []byte
	Actor       Actor
	Origin      string
	Binding     []byte
	// Response is the PublicKeyCredential JSON exactly as the browser sent it.
	Response []byte
}

// Approve verifies a fresh WebAuthn assertion over the challenge and, if every
// check passes, records the approval: pending→approved by compare-and-set,
// the operation-approval document, the assertion and the op.approve ledger
// event, all in one transaction. An expected "no" is returned as a *[Refusal].
//
// The console session is never enough: the decision rests on the assertion, which
// only the authenticator's user verification can produce.
func (e *Engine) Approve(ctx context.Context, in ApproveInput) (*Approval, error) {
	if err := e.checkActor(ctx, in.Actor, in.ApprovalID); err != nil {
		return nil, err
	}
	if e.cfg.Verifier == nil {
		return nil, errors.New("approvals: Config.Verifier is required to approve")
	}
	ch, err := e.takeChallenge(ctx, in.ChallengeID)
	if err != nil {
		return nil, err
	}
	now := e.now()
	switch {
	case ch == nil || now.After(ch.ValidUntil) || ch.Origin != in.Origin ||
		subtle.ConstantTimeCompare(ch.binding, nonNil(in.Binding)) != 1:
		return nil, refuse(CodeChallenge, "the challenge is unknown, expired, already used, or belongs to another browser")
	case ch.ApprovalID != in.ApprovalID || ch.ApproverRow != in.Actor.ApproverRow || ch.Approver != in.Actor.ApproverID:
		return nil, &Refusal{Code: CodeWrongRequest, ApprovalID: in.ApprovalID,
			Why: "the challenge was made for another approval or another approver"}
	}

	ev, err := e.cfg.Verifier.VerifyAssertion(ctx, AssertionInput{
		Origin: in.Origin, ApproverRow: ch.ApproverRow, Challenge: ch.Raw, Response: in.Response})
	if err != nil {
		var ae *AssertionError
		if errors.As(err, &ae) {
			return nil, &Refusal{Code: CodeAssertion, Why: ae.Reason, ApprovalID: in.ApprovalID}
		}
		return nil, err
	}
	if !e.channelAllowed(ev.Channel) {
		return nil, &Refusal{Code: CodeAssertion, Why: "channel_not_enabled", ApprovalID: in.ApprovalID}
	}
	if ev.Channel != e.channelOf(ch.Origin) {
		// The verifier and the engine disagree about which device this was; no
		// phone assertion may pass for a server one or the other way round.
		return nil, &Refusal{Code: CodeAssertion, Why: "channel_mismatch", ApprovalID: in.ApprovalID}
	}
	assertionHash := spec.SHA256Tagged(in.Response)

	var done *Approval
	var refusal *Refusal
	err = e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
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
		if v := e.currentPolicy(); v != "" && v != a.PolicyVersion {
			refusal = &Refusal{Code: CodePolicyRefused, ApprovalID: a.ID, Why: "the policy changed after the card was made; ask again"}
			return nil
		}
		rec := record(a, "approved", ch.Approver, ch.Nonce, ch.Expires)
		hash, err := spec.ApprovalChallenge(rec)
		if err != nil {
			return err
		}
		if hash != ch.Hash {
			refusal = &Refusal{Code: CodeIntegrity, ApprovalID: a.ID, Why: "the challenge no longer matches the approval"}
			return nil
		}
		rec.ChallengeSHA256 = hash
		rec.DecidedAt = ts(now)
		rec.Shown.Channels = []string{ev.Channel}
		rec.Confirmations = []spec.Confirmation{{Channel: ev.Channel, CredentialID: credentialLabel(ev.CredentialID),
			AssertionSHA256: assertionHash, At: ts(now)}}
		recJSON, err := encodeRecord(rec)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE approvals SET state = 'approved', decided_unix = ?, approver = ?, nonce = ?, challenge_sha256 = ?,
				approval_expires_unix = ?, record_json = ?
			 WHERE approval_id = ? AND state = 'pending' AND request_expires_unix >= ?`,
			now.Unix(), ch.Approver, ch.Nonce, hash, ch.Expires.Unix(), recJSON, a.ID, now.Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			refusal = refuse(CodeConsumed, "this approval has already been decided and used")
			refusal.ApprovalID = a.ID
			return nil
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO approval_assertions (approval_id, channel, credential_id, rp_id, origin, assertion_json, assertion_sha256, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, ev.Channel, nonNil(ev.CredentialID), ev.RPID, ev.Origin, in.Response, assertionHash, ts(now)); err != nil {
			return err
		}
		if done, err = getApproval(ctx, tx, a.ID); err != nil {
			return err
		}
		body := fmt.Sprintf("approved by %s on %s; assertion_sha256=%s; display_sha256=%s; challenge_sha256=%s",
			ch.Approver, ev.Channel, assertionHash, a.DisplaySHA256, hash)
		if ev.Attachment != "" {
			body += fmt.Sprintf("; authenticator=%s; transports=%s; backup_eligible=%t",
				ev.Attachment, cmp.Or(strings.Join(ev.Transports, ","), "none"), ev.BackupEligible)
		}
		if ev.Channel == "phone" {
			body += "; number_matching=ok"
		}
		if err := e.ledgerDecision(ctx, tx, done, "approved", ev.Channel, body); err != nil {
			return err
		}
		return e.decided(ctx, tx, done, OutcomeApproved, "")
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return nil, refusal
	}
	fx := Effects{e: e}
	if done.Class == ClassCritical {
		fx.alerts = append(fx.alerts, e.alert(AlertApproved, done))
	}
	fx.Run(ctx)
	if e.cfg.AfterApproved != nil {
		e.cfg.AfterApproved(ctx, done)
	}
	return done, nil
}

func (e *Engine) currentPolicy() string {
	if e.cfg.PolicyVersion == nil {
		return ""
	}
	return e.cfg.PolicyVersion()
}

// credentialLabel is the spec credential_id: base64url of the authenticator's
// id, or of its SHA-256 when the id is longer than the spec allows.
func credentialLabel(id []byte) string {
	if s := b64.EncodeToString(id); len(s) >= 8 && len(s) <= 128 {
		return s
	}
	sum := sha256.Sum256(id)
	return b64.EncodeToString(sum[:])
}

// encodeRecord validates an approval document against the spec schema and returns
// its canonical (JCS) text.
func encodeRecord(rec spec.Approval) (string, error) {
	tree, err := spec.Tree(rec)
	if err != nil {
		return "", fmt.Errorf("approvals: approval record: %w", err)
	}
	if err := spec.Validate(spec.SchemaApproval, tree); err != nil {
		return "", fmt.Errorf("approvals: approval record does not match the spec schema: %w", err)
	}
	b, err := spec.JCS(tree)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ledgerDecision appends the op.approve event of a decision.
func (e *Engine) ledgerDecision(ctx context.Context, tx *store.Tx, a *Approval, decision, channel, body string) error {
	attrs := map[string]any{
		"factory.approval.id":    a.ID,
		"factory.request_id":     a.RequestID,
		"factory.op_hash":        a.OpHash,
		"factory.decision":       decision,
		"factory.approver.id":    a.Approver,
		"factory.policy_version": a.PolicyVersion,
		"factory.requester.kind": a.RequesterKind,
	}
	if a.RequesterKind == "orchestrator" {
		attrs["factory.orchestrator.id"] = a.RequesterKey
	}
	if channel != "" {
		attrs["factory.confirm.channels"] = []any{channel}
	}
	sev := ""
	if a.Class == ClassCritical {
		sev = "WARN"
	}
	return e.cfg.Ledger.AppendTx(ctx, tx, LedgerEvent{Name: "op.approve", RunID: a.RunID, Project: a.Project,
		Severity: sev, Attributes: attrs, Body: body})
}

func (e *Engine) decided(ctx context.Context, tx *store.Tx, a *Approval, o Outcome, reason string) error {
	if e.cfg.OnDecided == nil {
		return nil
	}
	return e.cfg.OnDecided(ctx, tx, Decision{Approval: *a, Outcome: o, Reason: reason})
}

// DenyInput denies a card.
type DenyInput struct {
	ApprovalID string
	Actor      Actor
	Reason     string
}

// Deny records the operator's "no" with a reason. It needs no assertion: it only
// removes authority, and the console session is enough. The same op hash is then
// refused for the sticky-deny window.
func (e *Engine) Deny(ctx context.Context, in DenyInput) (*Approval, error) {
	if err := e.checkActor(ctx, in.Actor, in.ApprovalID); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 500 {
		return nil, refuse(CodeParamsInvalid, "a denial needs a reason of 1 to 500 characters")
	}
	var done *Approval
	var refusal *Refusal
	err := e.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) (err error) {
		done, refusal, err = e.denyTx(ctx, tx, in.ApprovalID, in.Actor.ApproverID, reason)
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return nil, refusal
	}
	return done, nil
}

// denyTx is the pending→denied compare-and-set, the op.approve event and the
// OnDecided hook, inside the caller's transaction. A refusal is returned with a
// nil error: the caller commits (the sweep may have written) and then returns it.
func (e *Engine) denyTx(ctx context.Context, tx *store.Tx, approvalID, approverID, reason string) (*Approval, *Refusal, error) {
	now := e.now()
	if _, err := e.sweepTx(ctx, tx); err != nil {
		return nil, nil, err
	}
	a, err := getApproval(ctx, tx, approvalID)
	if err != nil {
		return nil, nil, err
	}
	if a == nil {
		return nil, refuse(CodeNoSuchApproval, "there is no such approval"), nil
	}
	if r := decidable(a); r != nil {
		return nil, r, nil
	}
	// A denial can never be consumed, so its expires_at is its own instant.
	rec := record(a, "denied", approverID, newNonce(), now)
	rec.Reason, rec.DecidedAt = reason, ts(now)
	hash, err := spec.ApprovalChallenge(rec)
	if err != nil {
		return nil, nil, err
	}
	rec.ChallengeSHA256 = hash
	recJSON, err := encodeRecord(rec)
	if err != nil {
		return nil, nil, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET state = 'denied', decided_unix = ?, approver = ?, reason = ?, nonce = ?, challenge_sha256 = ?,
			approval_expires_unix = ?, record_json = ?
		 WHERE approval_id = ? AND state = 'pending'`,
		now.Unix(), approverID, reason, rec.Nonce, hash, now.Unix(), recJSON, a.ID)
	if err != nil {
		return nil, nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		r := refuse(CodeConsumed, "this approval has already been decided")
		r.ApprovalID = a.ID
		return nil, r, nil
	}
	done, err := getApproval(ctx, tx, a.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := e.ledgerDecision(ctx, tx, done, "denied", "", "denied by "+approverID+": "+reason); err != nil {
		return nil, nil, err
	}
	return done, nil, e.decided(ctx, tx, done, OutcomeDenied, reason)
}
