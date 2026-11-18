package approvals

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

const approvalColumns = `approval_id, request_id, requester_kind, requester_key, coalesce(run_id, ''), project, op, op_hash,
	class, policy_version, request_json, checks_json, evidence_json, card_text, display_sha256, state,
	created_unix, request_expires_unix, coalesce(decided_unix, 0), coalesce(approver, ''), coalesce(reason, ''),
	coalesce(approval_expires_unix, 0), coalesce(consumed_unix, 0), coalesce(record_json, '')`

type scanner interface{ Scan(...any) error }

func scanApproval(s scanner) (*Approval, error) {
	var (
		a                                           Approval
		class, state                                string
		reqJSON, checksJSON, evJSON, recJSON        string
		created, reqExp, decided, expires, consumed int64
	)
	if err := s.Scan(&a.ID, &a.RequestID, &a.RequesterKind, &a.RequesterKey, &a.RunID, &a.Project, &a.Op, &a.OpHash,
		&class, &a.PolicyVersion, &reqJSON, &checksJSON, &evJSON, &a.CardText, &a.DisplaySHA256, &state,
		&created, &reqExp, &decided, &a.Approver, &a.Reason, &expires, &consumed, &recJSON); err != nil {
		return nil, err
	}
	a.Class, a.State = Class(class), State(state)
	a.Created = time.Unix(created, 0).UTC()
	a.RequestExpires = time.Unix(reqExp, 0).UTC()
	if decided != 0 {
		a.Decided = time.Unix(decided, 0).UTC()
	}
	if expires != 0 {
		a.Expires = time.Unix(expires, 0).UTC()
	}
	if consumed != 0 {
		a.Consumed = time.Unix(consumed, 0).UTC()
	}
	// The stored documents were written by this package; a failure to read
	// them back means the row was edited, which is a fault, not a refusal.
	if err := json.Unmarshal([]byte(reqJSON), &a.Request); err != nil {
		return nil, fmt.Errorf("approvals: %s request_json: %w", a.ID, err)
	}
	if err := json.Unmarshal([]byte(checksJSON), &a.Checks); err != nil {
		return nil, fmt.Errorf("approvals: %s checks_json: %w", a.ID, err)
	}
	if err := json.Unmarshal([]byte(evJSON), &a.Evidence); err != nil {
		return nil, fmt.Errorf("approvals: %s evidence_json: %w", a.ID, err)
	}
	if recJSON != "" {
		a.Record = new(spec.Approval)
		if err := json.Unmarshal([]byte(recJSON), a.Record); err != nil {
			return nil, fmt.Errorf("approvals: %s record_json: %w", a.ID, err)
		}
	}
	return &a, nil
}

// queryer is a *sql.DB or a *store.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func getApproval(ctx context.Context, q queryer, id string) (*Approval, error) {
	a, err := scanApproval(q.QueryRowContext(ctx, `SELECT `+approvalColumns+` FROM approvals WHERE approval_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

func listApprovals(ctx context.Context, q queryer, where string, args ...any) ([]*Approval, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+approvalColumns+` FROM approvals `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func countWhere(ctx context.Context, q queryer, where string, args ...any) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM approvals WHERE `+where, args...).Scan(&n)
	return n, err
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// newApprovalID returns "a-" and 12 random characters of [0-9a-z] (spec: a-[0-9a-z]{6,32}).
func newApprovalID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("approvals: crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
	for i := range b {
		b[i] = idAlphabet[int(b[i])%len(idAlphabet)]
	}
	return "a-" + string(b)
}
