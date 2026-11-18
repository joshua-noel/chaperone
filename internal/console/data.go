package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/joshua-noel/chaperone/internal/store"
)

// errors the HTTP layer maps to refusal reasons.
var (
	errNoCeremony        = errors.New("console: no such ceremony (unknown, expired or already used)")
	errEnrollToken       = errors.New("console: enrolment token unknown, used or expired")
	errApproverExists    = errors.New("console: an approver is already enrolled")
	errNoApprover        = errors.New("console: no such approver")
	errTooManyCeremonies = errors.New("console: too many ceremonies in flight")
)

// maxCeremonies bounds the unfinished Begin calls: anything that can reach the
// loopback port can start a login ceremony, so the table must not grow without limit.
const maxCeremonies = 64

const timeFormat = time.RFC3339

func sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("console: crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
	return b
}

// approver is one row of approvers.
type approver struct {
	ID       int64
	Handle   []byte
	Name     string
	Disabled bool
}

// credential is one row of credentials, with the library's view of it.
type credential struct {
	ID         int64
	ApproverID int64
	RPID       string
	Origin     string
	Label      string
	Created    string
	LastUsed   string
	Revoked    bool
	WA         webauthn.Credential
}

// waUser adapts an approver and some of its credentials to webauthn.User.
type waUser struct {
	handle []byte
	name   string
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ceremony is one row of console_ceremonies.
type ceremony struct {
	ID               []byte
	Kind             string
	Origin           string
	CSRFSum          []byte
	Session          webauthn.SessionData
	ApproverID       sql.NullInt64
	NewUserHandle    []byte
	ApproverName     string
	CredentialLabel  string
	EnrollmentSHA256 []byte
}

const credColumns = `c.id, c.approver_id, c.credential_id, c.rp_id, c.origin, c.public_key, c.attestation_type,
	c.attestation_format, c.aaguid, c.transports, c.attachment, c.sign_count, c.backup_eligible, c.backup_state,
	c.label, c.created_at, coalesce(c.last_used_at, ''), c.revoked_at IS NOT NULL`

type scanner interface{ Scan(...any) error }

func scanCredential(s scanner) (*credential, error) {
	var (
		c                       credential
		credID, key, aaguid     []byte
		attType, attFmt, trans  string
		attachment              string
		signCount               uint32
		backupElig, backupState bool
	)
	if err := s.Scan(&c.ID, &c.ApproverID, &credID, &c.RPID, &c.Origin, &key, &attType, &attFmt, &aaguid, &trans,
		&attachment, &signCount, &backupElig, &backupState, &c.Label, &c.Created, &c.LastUsed, &c.Revoked); err != nil {
		return nil, err
	}
	var transports []protocol.AuthenticatorTransport
	if err := json.Unmarshal([]byte(trans), &transports); err != nil {
		return nil, fmt.Errorf("console: credential %d transports: %w", c.ID, err)
	}
	c.WA = webauthn.Credential{
		ID:                credID,
		PublicKey:         key,
		AttestationType:   attType,
		AttestationFormat: attFmt,
		Transport:         transports,
		// user_verified is 1 by CHECK; user presence is required by every ceremony.
		Flags: webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: backupElig, BackupState: backupState},
		Authenticator: webauthn.Authenticator{
			AAGUID:     aaguid,
			SignCount:  signCount,
			Attachment: protocol.AuthenticatorAttachment(attachment),
		},
	}
	return &c, nil
}

// approverCount returns the number of approvers (enabled or not).
func (c *Console) approverCount(ctx context.Context) (int, error) {
	var n int
	err := c.db.SQL().QueryRowContext(ctx, `SELECT count(*) FROM approvers`).Scan(&n)
	return n, err
}

func (c *Console) approverByID(ctx context.Context, id int64) (*approver, error) {
	var a approver
	var disabled sql.NullString
	err := c.db.SQL().QueryRowContext(ctx,
		`SELECT id, user_handle, name, disabled_at FROM approvers WHERE id = ?`, id).
		Scan(&a.ID, &a.Handle, &a.Name, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoApprover
	}
	a.Disabled = disabled.Valid
	return &a, err
}

// credentialByRawID finds a credential by the authenticator's credential id.
func (c *Console) credentialByRawID(ctx context.Context, rawID []byte) (*credential, error) {
	cr, err := scanCredential(c.db.SQL().QueryRowContext(ctx,
		`SELECT `+credColumns+` FROM credentials c WHERE c.credential_id = ?`, rawID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, protocol.ErrBadRequest.WithDetails("unknown credential")
	}
	return cr, err
}

// credentialsOf lists an approver's live credentials, oldest first.
func (c *Console) credentialsOf(ctx context.Context, approverID int64) ([]*credential, error) {
	rows, err := c.db.SQL().QueryContext(ctx,
		`SELECT `+credColumns+` FROM credentials c WHERE c.approver_id = ? AND c.revoked_at IS NULL ORDER BY c.id`, approverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*credential
	for rows.Next() {
		cr, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

// putCeremony stores a ceremony. The row id is returned to the browser.
func (c *Console) putCeremony(ctx context.Context, cm *ceremony) error {
	js, err := json.Marshal(cm.Session)
	if err != nil {
		return err
	}
	expires := c.now().Add(c.ceremonyTTL).Unix()
	return c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		// Housekeeping: expired ceremonies are dead weight.
		if _, err := tx.ExecContext(ctx, `DELETE FROM console_ceremonies WHERE expires_unix < ?`, c.now().Unix()); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM console_ceremonies`).Scan(&pending); err != nil {
			return err
		}
		if pending >= maxCeremonies {
			return errTooManyCeremonies
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO console_ceremonies (id, kind, origin, csrf_sha256, session_json, approver_id, new_user_handle,
				approver_name, credential_label, enrollment_sha256, expires_unix)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			cm.ID, cm.Kind, cm.Origin, cm.CSRFSum, string(js), cm.ApproverID, cm.NewUserHandle,
			cm.ApproverName, cm.CredentialLabel, cm.EnrollmentSHA256, expires)
		return err
	})
}

// takeCeremony deletes and returns a ceremony in one statement. Whatever
// happens next (a bad signature, a wrong origin, a dropped connection), the
// ceremony is gone: a response can be tried once.
func (c *Console) takeCeremony(ctx context.Context, id []byte) (*ceremony, error) {
	var (
		cm      ceremony
		js      string
		name    sql.NullString
		label   sql.NullString
		expires int64
	)
	err := c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.QueryRowContext(ctx,
			`DELETE FROM console_ceremonies WHERE id = ?
			 RETURNING id, kind, origin, csrf_sha256, session_json, approver_id, new_user_handle, approver_name,
			           credential_label, enrollment_sha256, expires_unix`, id).
			Scan(&cm.ID, &cm.Kind, &cm.Origin, &cm.CSRFSum, &js, &cm.ApproverID, &cm.NewUserHandle, &name, &label,
				&cm.EnrollmentSHA256, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoCeremony
	}
	if err != nil {
		return nil, err
	}
	if expires < c.now().Unix() {
		return nil, errNoCeremony
	}
	cm.ApproverName, cm.CredentialLabel = name.String, label.String
	if err := json.Unmarshal([]byte(js), &cm.Session); err != nil {
		return nil, fmt.Errorf("console: ceremony %x: %w", id, err)
	}
	return &cm, nil
}

// checkEnrollment reports whether a token is usable right now, without using it.
func (c *Console) checkEnrollment(ctx context.Context, tokenSum []byte) (approverID sql.NullInt64, err error) {
	var used sql.NullString
	var expires int64
	err = c.db.SQL().QueryRowContext(ctx,
		`SELECT approver_id, used_at, expires_unix FROM console_enrollments WHERE token_sha256 = ?`, tokenSum).
		Scan(&approverID, &used, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (used.Valid || expires < c.now().Unix())) {
		return approverID, errEnrollToken
	}
	if err != nil {
		return approverID, err
	}
	if !approverID.Valid {
		n, err := c.approverCount(ctx)
		if err != nil {
			return approverID, err
		}
		if n > 0 {
			return approverID, errApproverExists
		}
	}
	return approverID, nil
}

// saveEnrollment makes the new credential (and, for a first enrolment, the
// approver) and uses the token, all in one transaction. A token is valid for
// exactly one commit.
func (c *Console) saveEnrollment(ctx context.Context, cm *ceremony, o Origin, cred *webauthn.Credential) (approverID int64, err error) {
	now := c.now()
	err = c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE console_enrollments SET used_at = ? WHERE token_sha256 = ? AND used_at IS NULL AND expires_unix >= ?`,
			now.UTC().Format(timeFormat), cm.EnrollmentSHA256, now.Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errEnrollToken
		}
		if cm.ApproverID.Valid {
			var disabled sql.NullString
			err := tx.QueryRowContext(ctx, `SELECT disabled_at FROM approvers WHERE id = ?`, cm.ApproverID.Int64).Scan(&disabled)
			if errors.Is(err, sql.ErrNoRows) || disabled.Valid {
				return errNoApprover
			}
			if err != nil {
				return err
			}
			approverID = cm.ApproverID.Int64
		} else {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approvers`).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return errApproverExists
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO approvers (user_handle, name, created_at) VALUES (?, ?, ?)`,
				cm.NewUserHandle, cm.ApproverName, now.UTC().Format(timeFormat))
			if err != nil {
				return err
			}
			if approverID, err = res.LastInsertId(); err != nil {
				return err
			}
		}
		transports, err := json.Marshal(cred.Transport)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credentials (approver_id, credential_id, rp_id, origin, public_key, attestation_type,
				attestation_format, aaguid, transports, attachment, sign_count, user_verified, backup_eligible,
				backup_state, label, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
			approverID, cred.ID, o.RPID, o.URL, cred.PublicKey, cred.AttestationType, cred.AttestationFormat,
			nonNil(cred.Authenticator.AAGUID), string(transports), string(cred.Authenticator.Attachment),
			cred.Authenticator.SignCount, cred.Flags.BackupEligible, cred.Flags.BackupState,
			cm.CredentialLabel, now.UTC().Format(timeFormat))
		return err
	})
	return approverID, err
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// session is one console session.
type session struct {
	TokenSum   []byte
	ApproverID int64
	Credential int64
	Origin     string
	LastSeen   int64
}

// newSession stores a session for a verified assertion and returns the
// cookie value.
func (c *Console) newSession(ctx context.Context, approverID, credentialRow int64, origin string) (string, error) {
	token := b64.EncodeToString(randBytes(32))
	now := c.now()
	err := c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM console_sessions WHERE expires_unix < ?`, now.Unix()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO console_sessions (token_sha256, approver_id, credential, origin, created_at, last_seen_unix, expires_unix)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sum([]byte(token)), approverID, credentialRow, origin, now.UTC().Format(timeFormat), now.Unix(),
			now.Add(c.sessionIdle).Unix())
		return err
	})
	return token, err
}

// lookupSession returns the live session for a cookie value, or nil. With slide it
// slides the idle expiry (not beyond the absolute maximum) at most once a minute.
// A request that reached the guard only through the frame-navigation exception
// passes slide=false: a page of another origin must not keep the session alive.
func (c *Console) lookupSession(ctx context.Context, token string, slide bool) (*session, *approver, error) {
	if token == "" {
		return nil, nil, nil
	}
	var s session
	var created string
	var expires int64
	var disabled sql.NullString
	var a approver
	ts := sum([]byte(token))
	err := c.db.SQL().QueryRowContext(ctx,
		`SELECT s.approver_id, s.credential, s.origin, s.created_at, s.last_seen_unix, s.expires_unix,
		        a.id, a.user_handle, a.name, a.disabled_at
		 FROM console_sessions s JOIN approvers a ON a.id = s.approver_id
		 WHERE s.token_sha256 = ? AND s.revoked_at IS NULL`, ts).
		Scan(&s.ApproverID, &s.Credential, &s.Origin, &created, &s.LastSeen, &expires,
			&a.ID, &a.Handle, &a.Name, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	now := c.now()
	born, err := time.Parse(timeFormat, created)
	if err != nil {
		return nil, nil, fmt.Errorf("console: session created_at: %w", err)
	}
	if disabled.Valid || expires < now.Unix() || now.After(born.Add(c.sessionMax)) {
		return nil, nil, nil
	}
	s.TokenSum = ts
	if slide && now.Unix()-s.LastSeen >= 60 {
		newExp := min(now.Add(c.sessionIdle).Unix(), born.Add(c.sessionMax).Unix())
		if err := c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE console_sessions SET last_seen_unix = ?, expires_unix = ? WHERE token_sha256 = ?`,
				now.Unix(), newExp, ts)
			return err
		}); err != nil {
			return nil, nil, err
		}
	}
	return &s, &a, nil
}

func (c *Console) endSession(ctx context.Context, tokenSum []byte) error {
	return c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE console_sessions SET revoked_at = ? WHERE token_sha256 = ? AND revoked_at IS NULL`,
			c.now().UTC().Format(timeFormat), tokenSum)
		return err
	})
}

// recordLogin writes back the counter and flags after a verified assertion.
func (c *Console) recordLogin(ctx context.Context, cr *credential, updated *webauthn.Credential) error {
	return c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE credentials SET sign_count = ?, backup_state = ?, last_used_at = ? WHERE id = ?`,
			updated.Authenticator.SignCount, updated.Flags.BackupState, c.now().UTC().Format(timeFormat), cr.ID)
		return err
	})
}
