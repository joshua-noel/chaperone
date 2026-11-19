package console

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/web"
)

// The Approvals screen (ticket L1-12, ADR-004 sections 1 and 3): the card as the
// server rendered it, "Approve with your passkey" and "Deny with a reason".
//
// The console session only lets the operator look. Approving needs a fresh
// WebAuthn assertion with user verification over the approval challenge, made
// for this card, this decision and this approver; a token of any kind that
// reaches these routes is a POLICY_BREACH.

//go:embed approvals.html
var approvalsHTML string

//go:embed approvals.js
var approvalsJS []byte

//go:embed approvals.css
var approvalsCSS []byte

// ApprovalsOptions configures [Console.UseApprovals].
type ApprovalsOptions struct {
	// ResolveToken names the holder of a bearer token presented to an approvals
	// route, so the breach can be attributed to its run. Optional: without it
	// the token is classified by its prefix (chap_orch_ is the orchestrator,
	// anything else a run) and the run is not named. A token is never accepted
	// as an approver whatever this returns.
	ResolveToken func(ctx context.Context, bearer string) (approvals.Actor, bool)
	// Recheck takes a read-only look at the request behind a pending approval and says whether it would be refused now.
	// It must write nothing. Optional: without it no card is flagged. An error means "could not tell": the page says
	// the card was not checked.
	Recheck func(ctx context.Context, requestID string) (StaleCheck, error)
}

// StaleCheck is the answer of a Recheck.
type StaleCheck struct {
	// Stale is true when the request would be refused now; Why says so in one sentence for the operator.
	Stale bool
	Why   string
	// NewCard is true when approving this card cannot help (the merge is bound to what the card showed, and that
	// changed): the page then says to ask again for a new card instead of "you can still decide".
	NewCard bool
}

// UseApprovals attaches the approvals engine and turns on the /approvals
// routes. Call it before [Console.Handler]. The engine's Verifier must be this
// console ([Console.VerifyAssertion]).
func (c *Console) UseApprovals(e *approvals.Engine, opts ApprovalsOptions) error {
	if e == nil {
		return errors.New("console: UseApprovals needs an engine")
	}
	t, err := newTemplate().ParseFS(web.Templates(), "layout.html", "fragments.html")
	if err != nil {
		return fmt.Errorf("console: approvals layout: %w", err)
	}
	if t, err = t.Parse(approvalsHTML); err != nil {
		return fmt.Errorf("console: approvals page: %w", err)
	}
	c.appr, c.apprOpts, c.apprPage = e, opts, t
	return nil
}

var _ approvals.Verifier = (*Console)(nil)

func (c *Console) approvalRoutes(mux *http.ServeMux) {
	if c.appr == nil {
		return
	}
	mux.HandleFunc("GET /approvals", c.approvalsPage)
	mux.HandleFunc("GET /approvals/approvals.js", c.approvalsScript)
	mux.HandleFunc("GET /approvals/approvals.css", c.approvalsStyle)
	mux.HandleFunc("POST /approvals/{id}/begin", c.approvalBegin)
	mux.HandleFunc("POST /approvals/{id}/finish", c.approvalFinish)
	mux.HandleFunc("POST /approvals/{id}/deny", c.approvalDeny)
	mux.HandleFunc("GET /approvals/{id}/outcome", c.approvalOutcome)
}

// ---- the screen ----

type cardView struct {
	ID, Op, Project, Requester, Class, Expires, Text, DisplaySHA string
	// PhoneCode is the two-digit number the phone page asks for; empty when the
	// phone is off. It is shown beside the card text, never inside it.
	PhoneCode string
	Critical  bool
	// Sections is the card text split at its headings; Split is false for a
	// card the page cannot split (an older card version), which is shown whole.
	// The parts add up to Text exactly.
	Sections []approvals.CardSection
	Split    bool
	// Who and What are read from the top of the card text, so the one-line list
	// shows words the approver signs. Risk is low, medium, high or critical.
	Who, What, Risk string
	// Age and ExpiresIn are chrome computed when the page is drawn; they are not part of the card.
	Age, ExpiresIn string
	// Open shows the card unfolded under its line.
	Open bool
	// Stale is why this merge would be refused if it ran now (a read-only look, stale.go); empty when it would not, or
	// when no look could be made. Page chrome outside the card text: not signed, and it does not block Approve.
	Stale string
	// Unchecked says why no look at a merge card could be made (too slow, too many looks running, the check failed); empty
	// when there was one. The card is then neither flagged nor known to be fine. Text only, like Stale.
	Unchecked string
	// NewCard: only a new card can help (see StaleCheck); the note says so.
	NewCard bool
	// Restricted draws the card with no working Approve or Deny (see Console.restricted). Legacy: the browser sent no
	// Sec-Fetch-Site, so the page cannot offer a way out.
	Restricted, Legacy bool
}

// RiskTone is the badge colour for the risk word. The word stays on the badge, so colour is never the only signal.
func (v cardView) RiskTone() string {
	switch v.Risk {
	case "low":
		return "success"
	case "medium":
		return "warning"
	}
	return "danger"
}

type recentView struct {
	ID, Op, Project, State, When string
	Who, What, Age               string
	// Outcome is what became of an approved request (see outcome.go); empty when nothing was approved.
	Outcome, OutcomeText string
	Critical             bool
}

type approvalsView struct {
	Title, CSRF, Origin, Approver string
	Cards                         []cardView
	Framed                        bool // see Console.framed: no header, no nav
	// Restricted: the page was loaded in a way that must not hand over a live Approve (see Console.restricted). Legacy: the
	// browser sent no Sec-Fetch-Site, so the note cannot offer a way out.
	Restricted, Legacy bool
	Recent             []recentView
	// PhoneOn turns on the "Add a phone" panel; Enrolments are approved
	// approvers.enroll cards waiting to be spent for their address.
	PhoneOn    bool
	PhoneURL   string
	Enrolments []recentView
}

func requesterLabel(a *approvals.Approval) string {
	if a.RequesterKind == "orchestrator" {
		return "orchestrator " + a.RequesterKey
	}
	return "run " + a.RunID
}

// ago says how long ago t was, in words a person reads at a glance.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

// until says how long is left before t.
func until(now, t time.Time) string {
	d := t.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Minute:
		return "under a minute left"
	case d < time.Hour:
		return fmt.Sprintf("%d min left", int(d.Minutes()))
	}
	return fmt.Sprintf("%d h left", int(d.Hours()))
}

// askOf reads who and what from a card's text; a card the page cannot read
// falls back to the requester and the op name.
func askOf(a *approvals.Approval) (who, what string, secs []approvals.CardSection, split bool) {
	secs, split = approvals.ParseCard(a.CardText)
	if split {
		if w, t, ok := approvals.CardAsk(secs); ok {
			return w, t, secs, true
		}
	}
	return requesterLabel(a), a.Op + " (an older card: this line is not read from its text)", nil, false
}

func (c *Console) approvalsPage(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	if st.user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if c.appr.IsPhoneOrigin(st.rp.URL) {
		// The server page shows the number the phone must match; the phone page is the phone's.
		http.Redirect(w, r, "/phone", http.StatusSeeOther)
		return
	}
	pending, err := c.appr.Pending(r.Context())
	if err != nil {
		c.log.Error("list approvals", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	recent, err := c.appr.Recent(r.Context(), 15)
	if err != nil {
		c.log.Error("list recent approvals", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The phone panel (ask to add a phone, show the enrolment address) is never drawn in a frame: enrolment is not framable.
	v := approvalsView{Title: "Approvals", CSRF: c.csrfToken(st), Origin: st.rp.URL, Approver: st.user.Name, Framed: st.framed,
		PhoneOn: c.phone != nil && !c.framable(r) && !st.restricted, Restricted: st.restricted, Legacy: st.legacy}
	if c.phone != nil {
		v.PhoneURL = c.phone.origin.URL
	}
	now := c.now()
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].RequestExpires.Before(pending[j].RequestExpires) })
	stale := c.staleFlags(r.Context(), pending)
	for _, a := range pending {
		cv := cardViewOf(a, now)
		cv.Stale, cv.Unchecked, cv.NewCard = stale[a.ID].Why, stale[a.ID].Unknown, stale[a.ID].NewCard
		if c.appr.PhoneEnabled() {
			code, err := c.appr.PCNumber(r.Context(), a.ID)
			var ref *approvals.Refusal
			switch {
			case errors.As(err, &ref):
				continue // decided or expired since the list was read
			case err != nil:
				c.log.Error("phone number", "approval", a.ID, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			cv.PhoneCode = code
		}
		v.Cards = append(v.Cards, cv)
	}
	if len(v.Cards) == 1 {
		v.Cards[0].Open = !st.restricted // one request: no need to click to read it, unless the page is restricted
	}
	for i := range v.Cards {
		v.Cards[i].Restricted, v.Cards[i].Legacy = st.restricted, st.legacy
	}
	var approved []string
	for _, a := range recent {
		if a.State == approvals.StateApproved || a.State == approvals.StateConsumed {
			approved = append(approved, a.ID)
		}
	}
	outcomes, err := c.opOutcomes(r.Context(), approved)
	if err != nil {
		c.log.Error("list outcomes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, a := range recent {
		if a.State == approvals.StatePending {
			continue
		}
		when := a.Created
		if !a.Decided.IsZero() {
			when = a.Decided
		}
		who, what, _, _ := askOf(a)
		rv := recentView{ID: a.ID, Op: a.Op, Project: a.Project, State: string(a.State), Who: who, What: what, Age: ago(now, when),
			When: when.UTC().Format(time.RFC3339), Critical: a.Critical()}
		if o, ok := outcomes[a.ID]; ok {
			rv.Outcome, rv.OutcomeText = o.describe()
		}
		v.Recent = append(v.Recent, rv)
		if c.phone != nil && a.State == approvals.StateApproved && c.operatorEnrollment(a) && a.Approver == approverSpecID(st.user) {
			v.Enrolments = append(v.Enrolments, rv)
		}
	}
	var buf bytes.Buffer
	if err := c.apprPage.ExecuteTemplate(&buf, "layout", v); err != nil {
		c.log.Error("render approvals", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (c *Console) approvalsScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(approvalsJS)
}

func (c *Console) approvalsStyle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(approvalsCSS)
}

// ---- who is asking ----

var specIDChars = regexp.MustCompile(`[^a-z0-9._-]+`)
var specID = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)

// approverSpecID is the spec approver id (^[a-z][a-z0-9._-]{0,62}$) of an
// approver: the lower-cased name with other characters turned into "-", or
// approver-<row> when nothing usable is left.
func approverSpecID(a *approver) string {
	id := specIDChars.ReplaceAllString(strings.ToLower(strings.TrimSpace(a.Name)), "-")
	id = strings.Trim(id, "-._")
	if len(id) > 63 {
		id = id[:63]
	}
	if !specID.MatchString(id) {
		return fmt.Sprintf("approver-%d", a.ID)
	}
	return id
}

// approvalActor says who is calling an approvals route. A request that carries
// an Authorization header is a token's, never an approver's, whatever session
// cookie rides along: a run or the orchestrator reaching for the operator's
// console gets POLICY_BREACH from the engine.
func (c *Console) approvalActor(r *http.Request) (approvals.Actor, bool) {
	bearer := ""
	for _, h := range []string{"Authorization", "Proxy-Authorization"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			bearer = v
			break
		}
	}
	if bearer != "" {
		_, tok, _ := strings.Cut(bearer, " ")
		tok = strings.TrimSpace(tok)
		if c.apprOpts.ResolveToken != nil {
			if a, ok := c.apprOpts.ResolveToken(r.Context(), tok); ok && a.Kind != approvals.ActorApprover {
				return a, true
			}
		}
		if strings.HasPrefix(tok, "chap_orch_") {
			return approvals.Actor{Kind: approvals.ActorOrchestrator}, true
		}
		return approvals.Actor{Kind: approvals.ActorRun}, true
	}
	st := stateOf(r)
	if st.user == nil {
		return approvals.Actor{}, false
	}
	return approvals.Actor{Kind: approvals.ActorApprover, ApproverRow: st.user.ID, ApproverID: approverSpecID(st.user)}, true
}

// refusalStatus maps an engine refusal to an HTTP status.
func refusalStatus(code string) int {
	switch code {
	case approvals.CodeBreach, approvals.CodeAssertion, approvals.CodeNumberRequired:
		return http.StatusForbidden
	case approvals.CodeConsumed, approvals.CodeHashMismatch, approvals.CodeDenied, approvals.CodePolicyRefused:
		return http.StatusConflict
	case approvals.CodeExpired:
		return http.StatusGone
	case approvals.CodeNoSuchApproval:
		return http.StatusNotFound
	case approvals.CodeIntegrity, approvals.CodeDisplayMismatch:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// approvalFailed answers an engine error: a refusal with its code, anything else as a fault.
func (c *Console) approvalFailed(w http.ResponseWriter, r *http.Request, err error) {
	var ref *approvals.Refusal
	if !errors.As(err, &ref) {
		c.log.Error("approvals", "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	c.log.Warn("approval refused", "path", r.URL.Path, "code", ref.Code, "why", ref.Why)
	if ref.Code == approvals.CodeAssertion {
		c.emit(Event{Name: EventRefused, Reason: ReasonAssertion, Ceremony: "approve", Detail: ref.Why, RPID: stateOf(r).rp.RPID, Origin: stateOf(r).rp.URL})
	}
	writeJSON(w, refusalStatus(ref.Code), map[string]string{"error": ref.Code, "why": ref.Why})
}

// ---- decisions ----

func (c *Console) approvalBegin(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	actor, ok := c.approvalActor(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	}
	id := r.PathValue("id")
	var user *waUser
	if actor.Kind == approvals.ActorApprover {
		creds, err := c.credentialsAt(r.Context(), actor.ApproverRow, st.rp)
		if err != nil {
			c.log.Error("list credentials", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if len(creds) == 0 {
			writeError(w, http.StatusConflict, "no_credential")
			return
		}
		user = &waUser{handle: st.user.Handle, name: st.user.Name}
		for _, cr := range creds {
			user.creds = append(user.creds, cr.WA)
		}
	}
	ch, err := c.appr.BeginDecision(r.Context(), approvals.BeginInput{
		ApprovalID: id, Actor: actor, Origin: st.rp.URL, Binding: sum([]byte(st.csrfCookie))})
	if err != nil {
		c.approvalFailed(w, r, err)
		return
	}
	// The challenge is the engine's, not the library's random one: it covers the card, the decision and the approver.
	assertion, _, err := st.rp.wa.BeginLogin(user, webauthn.WithChallenge(ch.Raw),
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		c.log.Error("begin approval assertion", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if ms := ch.ValidUntil.Sub(c.now()).Milliseconds(); ms > 0 {
		assertion.Response.Timeout = int(ms)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id":   b64.EncodeToString(ch.ID),
		"display_sha256": ch.DisplaySHA256,
		"options":        assertion,
	})
}

func (c *Console) approvalFinish(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	actor, ok := c.approvalActor(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	}
	chID, err := b64.DecodeString(r.Header.Get(challengeHeader))
	if err != nil || len(chID) != 16 {
		writeError(w, http.StatusBadRequest, approvals.CodeChallenge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, ReasonMalformed)
		return
	}
	a, err := c.appr.Approve(r.Context(), approvals.ApproveInput{
		ApprovalID: r.PathValue("id"), ChallengeID: chID, Actor: actor, Origin: st.rp.URL,
		Binding: sum([]byte(st.csrfCookie)), Response: body})
	if err != nil {
		c.approvalFailed(w, r, err)
		return
	}
	resp := map[string]any{"ok": true, "state": a.State, "expires_at": a.Record.ExpiresAt}
	// A console secret write is stored by this same request: the approval is the only question the operator is asked.
	if res := c.scr.autoCommitSecret(context.WithoutCancel(r.Context()), a); res != nil {
		resp["secret"] = map[string]any{"stored": res.Stored, "title": res.Title, "detail": res.Detail}
		if res.Err != nil {
			c.log.Error("secret write after approval", "approval", a.ID, "err", res.Err)
			detail := "The value is still held: open Secrets and press Try again."
			if !res.Held {
				detail = "The value is gone (chapd could not keep it): cancel this request and submit the secret again."
			}
			resp["secret"] = map[string]any{"stored": false, "title": "chapd could not use the approval", "detail": detail}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Console) approvalDeny(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.approvalActor(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ReasonMalformed)
		return
	}
	a, err := c.appr.Deny(r.Context(), approvals.DenyInput{ApprovalID: r.PathValue("id"), Actor: actor, Reason: req.Reason})
	if err != nil {
		c.approvalFailed(w, r, err)
		return
	}
	// A denied secret write can never be stored: wipe its held value now, not when its time is up.
	c.scr.discardHeld(a)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": a.State})
}

const challengeHeader = "X-Challenge-ID"

// ---- assertion verification (approvals.Verifier) ----

// credentialsAt lists an approver's live credentials made at rp's origin.
func (c *Console) credentialsAt(ctx context.Context, approverID int64, rp *relyingParty) ([]*credential, error) {
	all, err := c.credentialsOf(ctx, approverID)
	if err != nil {
		return nil, err
	}
	var out []*credential
	for _, cr := range all {
		if cr.RPID == rp.RPID && cr.Origin == rp.URL {
			out = append(out, cr)
		}
	}
	return out, nil
}

func (c *Console) relyingPartyAt(url string) *relyingParty {
	for _, rp := range c.rps {
		if rp.URL == url {
			return rp
		}
	}
	return nil
}

func assertionRefused(reason string, err error) error {
	return &approvals.AssertionError{Reason: reason, Err: err}
}

// VerifyAssertion checks a fresh WebAuthn assertion over challenge for an
// approver, as the approvals engine's [approvals.Verifier]. It is the login
// check with the library's random challenge replaced by the approval's: same
// origin and RP ID binding, user verification and presence checked here as well
// as by the library, a credential that belongs to this approver at this origin
// only, a regressed signature counter refused. It never looks at the session.
func (c *Console) VerifyAssertion(ctx context.Context, in approvals.AssertionInput) (approvals.AssertionEvidence, error) {
	rp := c.relyingPartyAt(in.Origin)
	if rp == nil {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonOrigin, errors.New("no relying party at "+in.Origin))
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(in.Response)
	if err != nil {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonMalformed, err)
	}
	flags := parsed.Response.AuthenticatorData.Flags
	if !flags.UserVerified() {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonUV, errors.New("UV flag not set in assertion"))
	}
	if !flags.UserPresent() {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonUP, errors.New("UP flag not set in assertion"))
	}
	ap, err := c.approverByID(ctx, in.ApproverRow)
	if err != nil || ap.Disabled {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonCredential, errors.New("approver unknown or disabled"))
	}
	creds, err := c.credentialsAt(ctx, in.ApproverRow, rp)
	if err != nil {
		return approvals.AssertionEvidence{}, err
	}
	var found *credential
	user := &waUser{handle: ap.Handle, name: ap.Name}
	session := webauthn.SessionData{
		Challenge:        b64.EncodeToString(in.Challenge),
		RelyingPartyID:   rp.RPID,
		UserID:           ap.Handle,
		UserVerification: protocol.VerificationRequired,
	}
	for _, cr := range creds {
		user.creds = append(user.creds, cr.WA)
		session.AllowedCredentialIDs = append(session.AllowedCredentialIDs, cr.WA.ID)
		if bytes.Equal(cr.WA.ID, parsed.RawID) {
			found = cr
		}
	}
	if found == nil {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonCredential, errors.New("credential is not this approver's at this origin"))
	}
	// The setting may have been narrowed since this credential was made (see loginFinish).
	if !c.attachmentAllowed(found.WA.Authenticator.Attachment) {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonAttachment, errors.New("credential's authenticator kind is not allowed by the authenticators setting"))
	}
	wa := rp.wa
	if cd := parsed.Response.CollectedClientData; cd.CrossOrigin {
		// Made in a frame. Accepted only when this console lists frame ancestors and the authenticator-signed topOrigin
		// is one of them (the library checks the list in explicit mode; an absent topOrigin is refused here, so "no
		// top origin" can never pass for "any"). Everything else about the assertion is checked as for a page of our own.
		if rp.waFramed == nil || cd.TopOrigin == "" {
			return approvals.AssertionEvidence{}, assertionRefused(ReasonOrigin, errors.New("cross-origin assertion without an allowed top origin"))
		}
		wa = rp.waFramed
	}
	updated, err := wa.ValidateLogin(user, session, parsed)
	if err != nil {
		return approvals.AssertionEvidence{}, assertionRefused(reasonOf(err), err)
	}
	if updated.Authenticator.CloneWarning {
		return approvals.AssertionEvidence{}, assertionRefused(ReasonClone, errors.New("signature counter did not advance"))
	}
	if err := c.recordLogin(ctx, found, updated); err != nil {
		return approvals.AssertionEvidence{}, err
	}
	channel := "phone"
	if rp.RPID == LocalOrigin.RPID {
		channel = "pc"
	}
	f := authnFacts(Event{}, updated)
	return approvals.AssertionEvidence{Channel: channel, CredentialID: found.WA.ID, RPID: rp.RPID, Origin: rp.URL,
		Attachment: cmp.Or(f.Attachment, "unreported"), Transports: f.Transports, BackupEligible: f.BackupEligible}, nil
}
