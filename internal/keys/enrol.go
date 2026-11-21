package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Agent enrolment (ADR-008): a device-code flow in the shape of RFC 8628, because a command line
// cannot do WebAuthn. The agent starts it and gets two codes: a short one it prints for its owner to read, and a
// long one only it holds. The owner enters the short code at the console, sees "enrol agent X, no access", and
// signs the card with Hello. The agent, polling with the long code, then receives a request-only key once.
// Neither code is stored: only its SHA-256.

const (
	enrolPending   = "pending"
	enrolIssued    = "issued"
	enrolClaimed   = "claimed"
	enrolExpired   = "expired"
	enrolCancelled = "cancelled"
)

// EnrolLife is how long an enrolment waits for its owner (the spec's 10 minutes).
const EnrolLife = 10 * time.Minute

// MaxPendingEnrolments caps the enrolments waiting at once: the start route needs no credential, so it must not
// be a way to fill the table.
const MaxPendingEnrolments = 5

// userCodeAlphabet leaves out what is easy to misread (0, 1, I, O).
const userCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

type enrolRow struct {
	ID, Project, Label, UserHash, DeviceHash, State string
	Created, Expires                                int64
	Owner, IssueOp, KeyID                           string
}

const enrolColumns = `id, project, label, user_code_sha256, device_sha256, state, created_at, expires_at,
    COALESCE(owner_id,''), COALESCE(issue_op_id,''), COALESCE(key_id,'')`

func scanEnrol(r rowScanner) (*enrolRow, error) {
	var e enrolRow
	if err := r.Scan(&e.ID, &e.Project, &e.Label, &e.UserHash, &e.DeviceHash, &e.State, &e.Created, &e.Expires, &e.Owner, &e.IssueOp, &e.KeyID); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) enrolRow(ctx context.Context, q dbx, id string) (*enrolRow, error) {
	if !enrolIDRE.MatchString(id) {
		return nil, ErrNotFound
	}
	e, err := scanEnrol(q.QueryRowContext(ctx, `SELECT `+enrolColumns+` FROM key_enrolments WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func userCodeHash(normalized string) string {
	sum := sha256.Sum256([]byte("enrol-user:" + normalized))
	return hex.EncodeToString(sum[:])
}

func deviceHash(code string) string {
	sum := sha256.Sum256([]byte("enrol-device:" + code))
	return hex.EncodeToString(sum[:])
}

// normalizeUserCode accepts the code as printed ("ABCD-EFGH") or typed carelessly (lower case, spaces).
func normalizeUserCode(s string) (string, bool) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != 8 {
		return "", false
	}
	for _, r := range s {
		if !strings.ContainsRune(userCodeAlphabet, r) {
			return "", false
		}
	}
	return s, true
}

func newUserCode() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("keys: random: %w", err)
	}
	b := make([]byte, 8)
	for i := range b {
		b[i] = userCodeAlphabet[int(raw[i])%len(userCodeAlphabet)] // 256 is a multiple of 32: no bias
	}
	return string(b), nil
}

// EnrolStart is what the agent gets: the id to poll, the code to read out and the code to keep.
type EnrolStart struct {
	ID         string
	UserCode   string // "ABCD-EFGH"
	DeviceCode string // 43 characters of base64url
	ExpiresAt  time.Time
}

// EnrolRefusal is an enrolment the rules turn down (a caller's mistake, not a fault).
type EnrolRefusal struct {
	Why    string
	Status int
}

func (e *EnrolRefusal) Error() string { return e.Why }

// StartEnrolment opens an enrolment for an agent called label in project. It needs no credential, so it is
// bounded: the project must be one where agents may ask for keys, at most MaxPendingEnrolments wait at once, and
// one label waits once.
func (s *Store) StartEnrolment(ctx context.Context, project, label string) (EnrolStart, error) {
	if !projectRE.MatchString(project) {
		return EnrolStart{}, &EnrolRefusal{Why: "project must be a project name", Status: 400}
	}
	if !labelRE.MatchString(label) {
		return EnrolStart{}, &EnrolRefusal{Why: fmt.Sprintf("label must be a lower-case name of at most %d characters: letters, digits, '.', '_' and '-'", MaxLabel), Status: 400}
	}
	if s.cfg.EnrolProject != nil && !s.cfg.EnrolProject(project) {
		return EnrolStart{}, &EnrolRefusal{Why: "agents cannot ask for keys in project " + project + ": the policy does not turn keys.request on for it", Status: 403}
	}
	var out EnrolStart
	now := s.now()
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := s.expireTx(ctx, tx, now); err != nil {
			return err
		}
		var pending, same int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(project = ? AND label = ?), 0) FROM key_enrolments WHERE state = 'pending'`, project, label).Scan(&pending, &same); err != nil {
			return err
		}
		if same > 0 {
			return &EnrolRefusal{Why: "an enrolment for " + label + " already waits for its owner; read them the code it printed, or wait for it to expire", Status: 409}
		}
		if pending >= MaxPendingEnrolments {
			return &EnrolRefusal{Why: "too many enrolments are waiting; try again in a few minutes", Status: 429}
		}
		id, err := randomHex("en-", 8)
		if err != nil {
			return err
		}
		user, err := newUserCode()
		if err != nil {
			return err
		}
		var dev [32]byte
		if _, err := rand.Read(dev[:]); err != nil {
			return fmt.Errorf("keys: random: %w", err)
		}
		device := base64.RawURLEncoding.EncodeToString(dev[:])
		expires := now.Add(EnrolLife)
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_enrolments (id, project, label, user_code_sha256, device_sha256, state, created_at, expires_at)
            VALUES (?,?,?,?,?,'pending',?,?)`, id, project, label, userCodeHash(user), deviceHash(device), now.Unix(), expires.Unix()); err != nil {
			return fmt.Errorf("keys: write the enrolment: %w", err)
		}
		out = EnrolStart{ID: id, UserCode: user[:4] + "-" + user[4:], DeviceCode: device, ExpiresAt: expires}
		return nil
	})
	var ref *EnrolRefusal
	if errors.As(err, &ref) && (ref.Status == 409 || ref.Status == 429) {
		s.noteRefusedStart(ctx, project, label, ref)
	}
	return out, err
}

// EnrolView is a waiting enrolment as the console shows it to the owner.
type EnrolView struct {
	ID, Project, Label string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// refusedStartEvery is the least time between two written-down refusals of the same label in the same project, and
// refusedStartMax the most refusals written down in that time for all labels together. A process that keeps asking
// must not fill the log and the ledger, only show up in them; and one label's refusals must not hide another's
// (a process that squats on the label of the real agent must not use up the real agent's refusal), so the limit is
// per label, with a global cap so that a process that tries many labels cannot flood (a clash on a label that holds a slot is outside the cap).
const (
	refusedStartEvery = time.Minute
	refusedStartMax   = 10
)

// allowNote says whether a refusal of project/label is written down now, and records that it was. A clash (the label
// already holds a slot, 409) is outside the global cap: only a label that holds one of the few slots can clash, so at
// most MaxPendingEnrolments of them a minute are written down, and the refusal of the real agent's label is never
// hidden by an attacker who tries many labels (those are the cap's 429s, which the global cap does limit).
func (s *Store) allowNote(project, label string, clash bool) bool {
	now := s.now()
	key := project + "/" + label
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refused == nil || len(s.refused) > 1024 { // bounded: labels are many, a minute is short
		s.refused = map[string]time.Time{}
	}
	if at, ok := s.refused[key]; ok && now.Sub(at) < refusedStartEvery {
		return false
	}
	if !clash {
		if now.Sub(s.noteFrom) >= refusedStartEvery {
			s.noteFrom, s.noteN = now, 0
		}
		if s.noteN >= refusedStartMax {
			return false
		}
		s.noteN++
	}
	s.refused[key] = now
	return true
}

// noteRefusedStart makes a refused start (the cap, or a label that already waits) visible: one WARN in the log
// and one event in the ledger, at most once a minute for each label (and ten a minute in all). A start needs no
// credential, so a local process can keep the slots or a label filled; this does not stop it, it lets the operator
// see it.
func (s *Store) noteRefusedStart(ctx context.Context, project, label string, ref *EnrolRefusal) {
	if !s.allowNote(project, label, ref.Status == 409) {
		return
	}
	log := s.cfg.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("an agent enrolment was refused: the slots are full or the label already waits", "project", project, "label", label, "why", ref.Why)
	err := s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return s.appendNote(ctx, tx, note{
			Op: "keys.enrol", Project: project, Requester: "enrol.start", Ref: "enrol:" + label, Severity: "WARN",
			Params: map[string]any{"project": project, "label": label, "status": ref.Status},
			Body:   "agent enrolment refused for " + label + ": " + ref.Why, Cause: "ENROLMENT_REFUSED",
		})
	})
	if err != nil {
		log.Error("could not write the refused enrolment to the ledger", "err", err)
	}
}

// WaitingEnrolments lists the enrolments that wait for their owner now, oldest first.
func (s *Store) WaitingEnrolments(ctx context.Context) ([]EnrolView, error) {
	rows, err := s.cfg.DB.SQL().QueryContext(ctx, `SELECT `+enrolColumns+` FROM key_enrolments WHERE state = 'pending' AND expires_at > ? ORDER BY created_at, id`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrolView
	for rows.Next() {
		e, err := scanEnrol(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, EnrolView{ID: e.ID, Project: e.Project, Label: e.Label, CreatedAt: unixTime(e.Created), ExpiresAt: unixTime(e.Expires)})
	}
	return out, rows.Err()
}

// CancelEnrolment ends a waiting enrolment on behalf of by (the approver, "person:<id>") and writes who did it to
// the ledger, in the same transaction: its agent's next poll is told it expired. A card that was already started
// for it must be denied on the approvals page first (cardWaiting says so, in the Decider).
func (s *Store) CancelEnrolment(ctx context.Context, id, by string) error {
	if !enrolIDRE.MatchString(id) {
		return ErrNotFound
	}
	return s.cfg.DB.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		e, err := s.enrolRow(ctx, tx, id)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE key_enrolments SET state = 'cancelled' WHERE id = ? AND state = 'pending'`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return s.appendNote(ctx, tx, note{
			Op: "keys.enrol.cancel", Project: e.Project, Requester: claimerID(by), Ref: "enrol:" + id,
			Params: map[string]any{"id": id, "label": e.Label},
			Body:   "agent enrolment " + id + " for " + e.Label + " was cancelled by " + clipText(by, 80),
		})
	})
}

// EnrolmentByCode finds the waiting enrolment a short code names. An unknown, expired or answered code is
// ErrNotFound: the console counts those.
func (s *Store) EnrolmentByCode(ctx context.Context, userCode string) (EnrolView, error) {
	norm, ok := normalizeUserCode(userCode)
	if !ok {
		return EnrolView{}, ErrNotFound
	}
	e, err := scanEnrol(s.cfg.DB.SQL().QueryRowContext(ctx, `SELECT `+enrolColumns+` FROM key_enrolments WHERE user_code_sha256 = ?`, userCodeHash(norm)))
	if errors.Is(err, sql.ErrNoRows) {
		return EnrolView{}, ErrNotFound
	}
	if err != nil {
		return EnrolView{}, err
	}
	if e.State != enrolPending || !s.now().Before(unixTime(e.Expires)) {
		return EnrolView{}, ErrNotFound
	}
	return EnrolView{ID: e.ID, Project: e.Project, Label: e.Label, CreatedAt: unixTime(e.Created), ExpiresAt: unixTime(e.Expires)}, nil
}

// BindEnrolIssue remembers the card the owner started for an enrolment.
func (s *Store) BindEnrolIssue(ctx context.Context, id, opID string) error {
	_, err := s.cfg.DB.SQL().ExecContext(ctx, `UPDATE key_enrolments SET issue_op_id = ? WHERE id = ? AND state = 'pending'`, opID, id)
	return err
}

// EnrolPoll is the answer to the agent's poll: its state, and once, the request-only key.
type EnrolPoll struct {
	State string // pending, claimed, expired
	Token string // only with "claimed", only once
	Key   ops.KeyInfo
}

// PollEnrolment answers the agent that holds deviceCode. While the owner has not signed it says pending; when
// the card is signed the same call hands the agent its request-only key, once, and marks the enrolment claimed
// in the claim's own transaction. A wrong device code is ErrNotFound, never a hint that the enrolment exists.
func (s *Store) PollEnrolment(ctx context.Context, id, deviceCode string) (EnrolPoll, error) {
	e, err := s.enrolRow(ctx, s.cfg.DB.SQL(), id)
	if err != nil {
		return EnrolPoll{}, err
	}
	if subtle.ConstantTimeCompare([]byte(e.DeviceHash), []byte(deviceHash(deviceCode))) != 1 {
		return EnrolPoll{}, ErrNotFound
	}
	now := s.now()
	switch e.State {
	case enrolPending:
		if now.Before(unixTime(e.Expires)) {
			return EnrolPoll{State: enrolPending}, nil
		}
		if _, err := s.cfg.DB.SQL().ExecContext(ctx, `UPDATE key_enrolments SET state = 'expired' WHERE id = ? AND state = 'pending'`, id); err != nil {
			return EnrolPoll{}, err
		}
		return EnrolPoll{State: enrolExpired}, nil
	case enrolExpired, enrolCancelled:
		return EnrolPoll{State: enrolExpired}, nil
	case enrolClaimed:
		return EnrolPoll{}, ErrAlreadyClaimed
	}
	token, info, err := s.claim(ctx, e.KeyID, "enrol:"+id, func(ctx context.Context, tx *store.Tx, _ ops.KeyInfo) error {
		res, err := tx.ExecContext(ctx, `UPDATE key_enrolments SET state = 'claimed' WHERE id = ? AND state = 'issued'`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrAlreadyClaimed
		}
		return nil
	})
	if errors.Is(err, ErrClaimExpired) || errors.Is(err, ErrRevoked) {
		return EnrolPoll{State: enrolExpired}, nil
	}
	if err != nil {
		return EnrolPoll{}, err
	}
	return EnrolPoll{State: enrolClaimed, Token: token, Key: info}, nil
}
