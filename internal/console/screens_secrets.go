package console

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

// Secrets: the vault's metadata, and import and rotation (ADR-003 item 5).
//
// Import and rotation are the critical-class op secrets.write. The operator is
// the requester (orchestrator id "operator"), and the approval is the same
// one every critical op gets: a card bound to the op hash, decided with a
// fresh Windows Hello assertion (ADR-004), never by this session alone. The
// steps:
//
//  1. POST /secrets/request: the form carries the value. The value is held in
//     memory only; the request that goes to the approvals engine carries a
//     keyed commitment to it (HMAC-SHA256 under a random key that also stays in
//     memory), so the approved op hash covers exactly those bytes and nothing
//     on disk or in the ledger can be used to guess them.
//  2. The operator approves the card (this page or /approvals). The approval
//     stores the value in the same request (approvalFinish, autoCommitSecret):
//     the approval is consumed (once), then the vault stores the value, then
//     the ledger records op.result. If chapd restarts or the card times out
//     before the approval, the value is gone and the operator submits it again.
//  3. Only if that store fails after the approval and the value is still held:
//     POST /secrets/{id}/commit ("Try again" on this page) finishes it with the
//     same approval, which stays unused until then.
//
// No response, page, log line or ledger event contains the value.

// heldSecret is a value waiting for its approval.
type heldSecret struct {
	req    spec.Request
	meta   vault.Meta
	action string
	value  []byte
	key    [32]byte
	until  time.Time
}

func (h *heldSecret) wipe() {
	clear(h.value)
	clear(h.key[:])
	h.value = nil
}

// commitment is the keyed digest of the value that the request's params carry.
func (h *heldSecret) commitment() string {
	m := hmac.New(sha256.New, h.key[:])
	m.Write([]byte("chap-secret-commitment-v1\x00"))
	m.Write(h.value)
	return hex.EncodeToString(m.Sum(nil)[:16])
}

const (
	maxHeldSecrets = 5
	// heldGrace is how long past the card's last decision time a value stays
	// in memory (time for the approval to be used).
	heldGrace = 10 * time.Minute
)

var errTooManyHeld = errors.New("too many secret writes are waiting")

type pendingSecrets struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]*heldSecret
}

func newPendingSecrets(now func() time.Time) *pendingSecrets {
	return &pendingSecrets{now: now, m: map[string]*heldSecret{}}
}

// purgeLocked wipes the values whose time is up.
func (p *pendingSecrets) purgeLocked() {
	now := p.now()
	for id, h := range p.m {
		if now.After(h.until) {
			h.wipe()
			delete(p.m, id)
		}
	}
}

func (p *pendingSecrets) put(id string, h *heldSecret) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeLocked()
	if len(p.m) >= maxHeldSecrets {
		return errTooManyHeld
	}
	p.m[id] = h
	return nil
}

// take removes and returns the held value; the caller wipes it.
func (p *pendingSecrets) take(id string) *heldSecret {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeLocked()
	h := p.m[id]
	delete(p.m, id)
	return h
}

func (p *pendingSecrets) has(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeLocked()
	_, ok := p.m[id]
	return ok
}

// ---- the page ----

type secretRow struct {
	ID, Kind, Project, Owner, Fingerprint, Created, Rotated, LastUsed string
}

type secretReq struct {
	ApprovalID, SecretID, Action, State, Expires string
	Pending, Approved, Held                      bool
	Card                                         cardView
}

type secretsView struct {
	shell
	Enabled  bool
	Secrets  []secretRow
	Requests []secretReq
	MaxKiB   int
}

func secretRowOf(i vault.Info) secretRow {
	return secretRow{ID: i.ID, Kind: i.Kind, Project: i.Project, Owner: i.Owner, Fingerprint: i.Fingerprint,
		Created: stamp(i.Created), Rotated: stamp(i.Rotated), LastUsed: stamp(i.LastUsed)}
}

// operatorSecretWrite reports whether a is a secrets.write the console asked for.
func operatorSecretWrite(a *approvals.Approval) bool {
	return a != nil && a.Op == "secrets.write" && a.RequesterKind == "orchestrator" && a.RequesterKey == operatorID
}

// secretsPage is GET /secrets.
func (s *screens) secretsPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	v := secretsView{shell: s.shell(st, "Secrets"), Enabled: s.cfg.Vault != nil, MaxKiB: vault.MaxSecretSize >> 10}
	if s.cfg.Vault != nil {
		infos, err := s.cfg.Vault.List(ctx)
		if err != nil {
			s.fail(w, "list secrets", err)
			return
		}
		for _, i := range infos {
			v.Secrets = append(v.Secrets, secretRowOf(i))
		}
		for _, state := range []approvals.State{approvals.StatePending, approvals.StateApproved} {
			list, err := s.c.appr.ListFor(ctx, "orchestrator", operatorID, state, 20)
			if err != nil {
				s.fail(w, "list secret approvals", err)
				return
			}
			for _, a := range list {
				if !operatorSecretWrite(a) {
					continue
				}
				req := secretReq{
					ApprovalID: a.ID, SecretID: a.Request.Target.Ref, Action: paramString(a.Request.Params, "action"),
					State: string(a.State), Pending: a.State == approvals.StatePending, Approved: a.State == approvals.StateApproved,
					Held: s.pend.has(a.ID),
				}
				if req.Pending {
					req.Expires = stamp(a.RequestExpires)
					req.Card = cardViewOf(a, s.c.now())
					req.Card.Open = !st.restricted
					req.Card.Restricted, req.Card.Legacy = st.restricted, st.legacy
				} else {
					req.Expires = stamp(a.Expires)
				}
				v.Requests = append(v.Requests, req)
			}
		}
	}
	s.page(w, http.StatusOK, "secrets", v)
}

func paramString(params map[string]any, key string) string {
	if s, ok := params[key].(string); ok {
		return s
	}
	return ""
}

// ---- request ----

var (
	secretKindPat    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`) // vault.Meta's kind rule
	projectSlugPat   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)      // the spec's project_id
	specTimeLayout   = "2006-01-02T15:04:05Z"
	maxSecretFormLen = 1 << 20 // the value is at most vault.MaxSecretSize; form encoding can triple it
)

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
}

func randLower(n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("console: crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (s *screens) needVault(w http.ResponseWriter) bool {
	if s.cfg.Vault == nil {
		s.sayAt(w, http.StatusNotFound, "#secrets-status", "No vault", "chapd runs without a vault, so there is nothing to write secrets to.")
		return false
	}
	return true
}

// secretRequest is POST /secrets/request.
func (s *screens) secretRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok || !s.needVault(w) {
		return
	}
	const target = "#secret-form-status"
	bad := func(status int, text string) { s.sayAt(w, status, target, "Not requested", text) }

	r.Body = http.MaxBytesReader(w, r.Body, int64(maxSecretFormLen))
	if err := r.ParseForm(); err != nil {
		bad(http.StatusRequestEntityTooLarge, "The form could not be read, or the value is too large.")
		return
	}
	form := r.PostForm
	action := form.Get("action")
	id := strings.TrimSpace(form.Get("id"))
	if action != "import" && action != "rotate" {
		bad(http.StatusBadRequest, "Choose import or rotate.")
		return
	}
	if err := vault.ValidID(id); err != nil {
		bad(http.StatusBadRequest, "The secret id must be lower-case letters, digits, '-' and '_' (at most 63), and not a Windows device name.")
		return
	}
	value := []byte(strings.TrimSpace(strings.ReplaceAll(form.Get("value"), "\r\n", "\n")))
	defer clear(value)
	if len(value) == 0 {
		bad(http.StatusBadRequest, "The value is empty.")
		return
	}
	if len(value) < redact.MinExactLen {
		bad(http.StatusBadRequest, fmt.Sprintf("The value is shorter than %d bytes. The vault refuses it because it could not be hidden reliably elsewhere.", redact.MinExactLen))
		return
	}
	if len(value) > vault.MaxSecretSize {
		bad(http.StatusRequestEntityTooLarge, "The value is larger than the vault accepts.")
		return
	}

	existing, err := s.cfg.Vault.List(r.Context())
	if err != nil {
		s.fail(w, "list secrets", err)
		return
	}
	var current *vault.Info
	for i := range existing {
		if existing[i].ID == id {
			current = &existing[i]
		}
	}
	var meta vault.Meta
	var check spec.ApprovalCheck
	switch {
	case action == "import" && current != nil:
		bad(http.StatusConflict, "A secret with this id exists. Use rotate to change its value.")
		return
	case action == "rotate" && current == nil:
		bad(http.StatusNotFound, "No secret has this id. Use import to add it.")
		return
	case action == "rotate":
		meta = current.Meta
		check = spec.ApprovalCheck{Name: "vault.target", Passed: true, Detail: "replaces the value of an existing secret (kind " + meta.Kind + ", fingerprint " + current.Fingerprint + ")"}
	default:
		meta = vault.Meta{ID: id, Kind: strings.TrimSpace(form.Get("kind")), Project: strings.TrimSpace(form.Get("project")), Owner: strings.TrimSpace(form.Get("owner"))}
		if !secretKindPat.MatchString(meta.Kind) {
			bad(http.StatusBadRequest, "The kind must be lower-case letters, digits, '.', '_' and '-' (for example github-app-key).")
			return
		}
		if len(meta.Project) > 128 || len(meta.Owner) > 128 || hasControl(meta.Project) || hasControl(meta.Owner) {
			bad(http.StatusBadRequest, "The project and owner must be short plain text.")
			return
		}
		check = spec.ApprovalCheck{Name: "vault.target", Passed: true, Detail: "adds a new secret of kind " + meta.Kind + "; no secret has this id"}
	}

	held := &heldSecret{meta: meta, action: action, value: append([]byte(nil), value...)}
	copy(held.key[:], randBytes(32))
	now := s.c.now()
	project := "chaperone"
	if projectSlugPat.MatchString(meta.Project) {
		project = meta.Project
	}
	req := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: "q-" + randLower(10),
		Requester: spec.Requester{Kind: "orchestrator", ID: operatorID},
		Project:   project, Op: "secrets.write", Target: spec.Target{Adapter: "vault", Ref: id},
		Params: map[string]any{
			"action": action, "kind": meta.Kind, "project": meta.Project, "owner": meta.Owner,
			"value_commitment": held.commitment(),
		},
		Reason:      "Operator console: " + action + " secret " + id,
		RequestedAt: now.UTC().Truncate(time.Second).Format(specTimeLayout),
		ExpiresAt:   now.Add(s.c.appr.RequestTTL("secrets.write")).UTC().Truncate(time.Second).Format(specTimeLayout),
	}
	if req.OpHash, err = spec.OpHash(req); err != nil {
		held.wipe()
		s.fail(w, "hash secret request", err)
		return
	}
	held.req = req
	held.until = now.Add(s.c.appr.RequestTTL("secrets.write") + heldGrace)

	var res approvals.Result
	err = s.c.appr.Atomic(r.Context(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = s.c.appr.RequestTx(ctx, tx, approvals.RequestInput{
			Request: req, PolicyVersion: s.cfg.Policy.Baseline().BaselineVersion(), Checks: []spec.ApprovalCheck{check}})
		if err != nil {
			return approvals.Effects{}, err
		}
		if res.Refusal != nil || !res.Created {
			return approvals.Effects{}, nil // commit: a stop hook may have written to the transaction
		}
		return res.Effects, s.cfg.Record.AppendTx(ctx, tx, secretRequestEvent(req, project, action))
	})
	switch {
	case err != nil:
		held.wipe()
		s.fail(w, "request secret write", err)
		return
	case res.Refusal != nil:
		held.wipe()
		bad(refusalStatus(res.Refusal.Code), res.Refusal.Code+": "+res.Refusal.Why)
		return
	case !res.Created:
		held.wipe()
		bad(http.StatusConflict, "An identical request is already waiting.")
		return
	}
	if err := s.pend.put(res.Approval.ID, held); err != nil {
		held.wipe()
		s.cancelApproval(r.Context(), res.Approval.RequestID, "the console could not hold the value")
		bad(http.StatusTooManyRequests, "Too many secret writes are waiting. Decide or cancel one first.")
		return
	}
	s.c.log.Warn("secret write requested", "op", "secrets.write", "action", action, "secret", id, "approval", res.Approval.ID)
	w.Header().Set("HX-Refresh", "true")
	s.say(w, http.StatusAccepted, "Approval requested", "Read the card below and approve it with Windows Hello. The value is held in memory until then.")
}

func secretRequestEvent(req spec.Request, project, action string) approvals.LedgerEvent {
	return approvals.LedgerEvent{
		Name: "op.request", Project: project, Severity: "WARN",
		Attributes: map[string]any{
			"factory.request_id": req.RequestID, "factory.op": req.Op, "factory.op_hash": req.OpHash,
			"factory.reversibility": "compensable", "factory.requester.kind": "orchestrator", "factory.orchestrator.id": operatorID,
		},
		Body: operatorID + " asked to " + action + " secret " + req.Target.Ref + " (value not recorded)",
	}
}

func (s *screens) cancelApproval(ctx context.Context, requestID, why string) {
	err := s.c.appr.Atomic(ctx, func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		_, err := s.c.appr.CancelTx(ctx, tx, approvals.CancelInput{RequestID: requestID, Reason: why})
		return approvals.Effects{}, err
	})
	if err != nil {
		s.c.log.Error("cancel secret approval", "request", requestID, "err", err)
	}
}

// ---- commit and cancel ----

// ownApproval loads an approval named in the path and checks it is a secret
// write the console asked for.
func (s *screens) ownApproval(w http.ResponseWriter, r *http.Request) (*approvals.Approval, bool) {
	id := r.PathValue("id")
	a, err := s.c.appr.Get(r.Context(), id)
	if err != nil {
		s.fail(w, "get approval", err)
		return nil, false
	}
	if !operatorSecretWrite(a) {
		s.sayAt(w, http.StatusNotFound, "#secrets-status", "No such request", "There is no secret write with this id.")
		return nil, false
	}
	return a, true
}

// commitResult is what storing an approved secret came to: the message the page shows, its HTTP status, and whether
// the value is in the vault now. Err is set when chapd failed in a way the page does not explain (the caller logs it).
type commitResult struct {
	Status        int
	Title, Detail string
	Stored        bool
	Err           error
	// Held is true when Err is set and the value is still held in memory, so a retry can finish. It is false when the value
	// could not be put back (too many held values): then it is gone.
	Held bool
}

// secretCommit is POST /secrets/{id}/commit: spend the approval and store the value. The approval itself stores the
// value as soon as it is decided (autoCommitSecret); this route stays for the value that is still held after a failed
// first try, so a retry needs no second approval.
func (s *screens) secretCommit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok || !s.needVault(w) {
		return
	}
	a, ok := s.ownApproval(w, r)
	if !ok {
		return
	}
	res := s.commitSecret(r.Context(), a)
	switch {
	case res.Err != nil:
		s.fail(w, "consume secret approval", res.Err)
	case res.Stored:
		w.Header().Set("HX-Refresh", "true")
		s.say(w, res.Status, res.Title, res.Detail)
	default:
		s.sayAt(w, res.Status, "#secrets-status", res.Title, res.Detail)
	}
}

// autoCommitSecret stores the value of a secret write the moment its approval is granted: the approval already says
// yes to exactly this write (the card names the secret and the value commitment is in the op hash), so a second
// button and a confirm dialog asked the operator the same question twice. ADR-003 is unchanged: the value was held in
// memory, nowhere else, and is written once. It returns nil when a is not a console secret write, or no vault is on.
func (s *screens) autoCommitSecret(ctx context.Context, a *approvals.Approval) *commitResult {
	if s == nil || s.cfg.Vault == nil || !operatorSecretWrite(a) {
		return nil
	}
	res := s.commitSecret(ctx, a)
	return &res
}

// discardHeld wipes the value held for a, a console secret write that was just denied: a denied card cannot be
// approved later, so nothing may keep the value until its time is up. It does nothing for any other card.
func (s *screens) discardHeld(a *approvals.Approval) {
	if s == nil || !operatorSecretWrite(a) {
		return
	}
	if h := s.pend.take(a.ID); h != nil {
		h.wipe()
	}
}

func (s *screens) commitSecret(ctx context.Context, a *approvals.Approval) commitResult {
	if a.State != approvals.StateApproved {
		return commitResult{Status: http.StatusConflict, Title: "Not approved", Detail: "This request is " + string(a.State) + ". Only an approved request can be completed."}
	}
	h := s.pend.take(a.ID)
	if h == nil {
		return commitResult{Status: http.StatusGone, Title: "The value is no longer held",
			Detail: "chapd restarted or the request timed out, so the value is gone. Cancel this request and submit the secret again."}
	}
	kept := false // true once the value is back in the held set for a retry
	defer func() {
		if !kept {
			h.wipe()
		}
	}()
	if !hmac.Equal([]byte(h.commitment()), []byte(paramString(a.Request.Params, "value_commitment"))) {
		s.c.log.Error("secret write: held value does not match the approved commitment", "approval", a.ID)
		return commitResult{Status: http.StatusConflict, Title: "Nothing was written", Detail: "The held value is not the one that was approved. Cancel this request and submit the secret again."}
	}

	err := s.c.appr.Atomic(ctx, func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		return s.c.appr.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: a.ID, Request: h.req})
	})
	var ref *approvals.Refusal
	switch {
	case errors.As(err, &ref):
		s.c.log.Warn("secret write refused", "approval", a.ID, "code", ref.Code)
		return commitResult{Status: refusalStatus(ref.Code), Title: "Nothing was written", Detail: ref.Code + ": " + ref.Why}
	case err != nil:
		// The approval is still unused: keep the value so a retry can finish.
		kept = s.pend.put(a.ID, h) == nil
		return commitResult{Err: err, Held: kept}
	}

	var info vault.Info
	switch h.action {
	case "import":
		info, err = s.cfg.Vault.Import(ctx, h.meta, h.value)
	default:
		info, err = s.cfg.Vault.Rotate(ctx, h.meta.ID, h.value)
	}
	outcome, cause := "succeeded", ""
	if err != nil {
		s.c.log.Error("secret write failed", "approval", a.ID, "secret", h.meta.ID, "err", err)
		outcome, cause = "failed", "VAULT_WRITE_FAILED"
	}
	rerr := s.c.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, ev := range secretResultEvents(a, h, outcome, cause) {
			if err := s.cfg.Record.AppendTx(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	if rerr != nil {
		s.c.log.Error("secret write: the result could not be ledgered", "approval", a.ID, "err", rerr)
	}
	switch {
	case err != nil:
		return commitResult{Status: http.StatusInternalServerError, Title: "The vault did not store the secret",
			Detail: "The approval is used up. " + vaultReason(err) + " Submit the secret again."}
	case rerr != nil:
		return commitResult{Status: http.StatusInternalServerError, Title: "Stored, but not ledgered",
			Detail: "The secret " + info.ID + " is in the vault, but the ledger could not record it. Check the ledger before doing anything else."}
	}
	s.c.log.Warn("secret written", "op", "secrets.write", "action", h.action, "secret", info.ID, "fingerprint", info.Fingerprint)
	return commitResult{Status: http.StatusOK, Title: "Secret stored", Detail: info.ID + " is in the vault (fingerprint " + info.Fingerprint + ").", Stored: true}
}

func vaultReason(err error) string {
	switch {
	case errors.Is(err, vault.ErrExists):
		return "A secret with this id exists now."
	case errors.Is(err, vault.ErrNotFound):
		return "No secret has this id."
	case errors.Is(err, vault.ErrInvalid):
		return "The vault found the id, kind or value invalid."
	}
	return "The vault reported an error (see the log)."
}

// secretResultEvents are the two events of one secret write under one
// execution_id (spec v0.1.1, "Secret writes"): vault.write names the secret
// and what the vault did, op.result is the operation's outcome. Neither holds
// the value, a hash of it or a fingerprint.
func secretResultEvents(a *approvals.Approval, h *heldSecret, outcome, cause string) []approvals.LedgerEvent {
	xid := "x-" + randLower(10)
	write := map[string]any{
		"factory.request_id": a.RequestID, "factory.op_hash": a.OpHash, "factory.execution_id": xid, "factory.outcome": outcome,
		"factory.secret.id": h.meta.ID, "factory.secret.action": h.action, "factory.secret.kind": h.meta.Kind,
		"factory.requester.kind": "orchestrator", "factory.orchestrator.id": operatorID,
	}
	result := map[string]any{
		"factory.request_id": a.RequestID, "factory.op_hash": a.OpHash, "factory.execution_id": xid,
		"factory.outcome": outcome, "factory.policy_version": a.PolicyVersion,
		"factory.requester.kind": "orchestrator", "factory.orchestrator.id": operatorID,
	}
	sev, body := "WARN", operatorID+" "+h.action+" secret "+h.meta.ID+": "+outcome
	if cause != "" {
		write["factory.cause_code"], result["factory.cause_code"] = cause, cause
		sev = "ERROR"
	}
	return []approvals.LedgerEvent{
		{Name: "vault.write", Project: a.Project, Severity: sev, Attributes: write, Body: body},
		{Name: "op.result", Project: a.Project, Severity: sev, Attributes: result, Body: body},
	}
}

// secretCancel is POST /secrets/{id}/cancel: drop the value and close the approval.
func (s *screens) secretCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok || !s.needVault(w) {
		return
	}
	a, ok := s.ownApproval(w, r)
	if !ok {
		return
	}
	if a.State != approvals.StatePending && a.State != approvals.StateApproved {
		s.sayAt(w, http.StatusConflict, "#secrets-status", "Nothing to cancel", "This request is "+string(a.State)+".")
		return
	}
	if h := s.pend.take(a.ID); h != nil {
		h.wipe()
	}
	s.cancelApproval(r.Context(), a.RequestID, "cancelled by the operator")
	w.Header().Set("HX-Refresh", "true")
	s.say(w, http.StatusOK, "Cancelled", "The request is cancelled and the value is discarded.")
}
