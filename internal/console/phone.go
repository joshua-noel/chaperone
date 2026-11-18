package console

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/qr"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/web"
)

// The phone (ticket L1-22, ADR-004 section 5 and amendment 6): the console is also
// reached at https://<server>.<tailnet>.ts.net through Tailscale Serve. That is a
// second relying party. The phone registers its own passkey there, and for an
// approve-tier card it may approve alone:
//
//  1. The server card shows a two-digit number ([Engine.PCNumber]).
//  2. The phone page shows the same card text (this server rendered it) and
//     three numbers; the approver taps the one on the server. A wrong tap denies the
//     card and starts the sticky-deny cooldown ([approvals.Engine.PhoneMatch]).
//  3. A right tap lets the phone ask for a challenge. One passkey assertion over
//     it approves. The routes for that are the server's (/approvals/{id}/begin and
//     /finish); the engine refuses a phone begin without the matched number.
//
// Enrolling the phone is the critical-class op approvers.enroll, approved with
// Windows Hello on the server: the server page then spends the approval and shows the
// one-time address of the phone's /enroll page as text and as a QR code.

//go:embed phone.html
var phoneHTML string

// PhoneConfig configures [Console.UsePhone].
type PhoneConfig struct {
	// Record appends the op.request and op.result events of the enrolment the
	// operator asks for from the server console, inside the caller's transaction.
	// Required.
	Record approvals.Ledger
	// PolicyVersion returns the policy version in force (a card records it).
	// Required.
	PolicyVersion func() string
	// EnrollTTL is how long the phone has to open the enrolment address.
	// Default 10 minutes.
	EnrollTTL time.Duration
}

type phoneConfig struct {
	PhoneConfig
	origin Origin // the one phone origin the enrolment address points at
	page   *template.Template
}

// NewPhoneOrigin is the phone's origin for a tailnet host name such as
// "server.tail1234.ts.net" (what `tailscale serve` publishes on port 443), or
// host:port when something else is configured. The RP ID is the host name
// alone: a passkey is valid for exactly this machine (ADR-004 amendment 6 item 1).
func NewPhoneOrigin(hostport string) (Origin, error) {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	host := hostport
	if strings.Contains(hostport, ":") {
		h, port, err := net.SplitHostPort(hostport)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 || strings.HasPrefix(port, "0") {
			return Origin{}, fmt.Errorf("console: phone host %q: the port must be a number from 1 to 65535", hostport)
		}
		host = h
	}
	switch {
	case hostport == "" || strings.ContainsAny(hostport, "/@?# "):
		return Origin{}, fmt.Errorf("console: phone host %q must be a host name such as server.tailnet.ts.net, not a URL", hostport)
	case host == "localhost" || net.ParseIP(host) != nil || !strings.Contains(host, "."):
		return Origin{}, fmt.Errorf("console: phone host %q must be the machine's full MagicDNS name (an IP address or a bare name has no certificate)", hostport)
	}
	o := Origin{RPID: host, URL: "https://" + hostport}
	if _, err := o.check(); err != nil {
		return Origin{}, err
	}
	return o, nil
}

// PhoneOrigins lists the configured origins that are the phone's: every origin
// but the server's. Pass it to [approvals.Config.PhoneOrigins].
func (c *Console) PhoneOrigins() []string {
	var out []string
	for _, rp := range c.rps {
		if rp.RPID != LocalOrigin.RPID {
			out = append(out, rp.URL)
		}
	}
	return out
}

// UsePhone turns on the phone routes. Call it after [Console.UseApprovals], and
// after [Console.UseScreens] if screens are used, before [Console.Handler]. The
// engine must have been built with the console's [Console.PhoneOrigins]; the
// two must agree on which origins are the phone's.
func (c *Console) UsePhone(cfg PhoneConfig) error {
	switch {
	case c.appr == nil:
		return errors.New("console: UsePhone needs UseApprovals first")
	case cfg.Record == nil || cfg.PolicyVersion == nil:
		return errors.New("console: UsePhone needs Record and PolicyVersion (the enrolment is ledgered)")
	}
	var phone []Origin
	for _, rp := range c.rps {
		isPhone := rp.RPID != LocalOrigin.RPID
		if isPhone != c.appr.IsPhoneOrigin(rp.URL) {
			return fmt.Errorf("console: %s is %s here but the approvals engine disagrees: build it with Config.PhoneOrigins = Console.PhoneOrigins()",
				rp.URL, map[bool]string{true: "a phone origin", false: "the server origin"}[isPhone])
		}
		if isPhone {
			phone = append(phone, rp.Origin)
		}
	}
	if len(phone) != 1 {
		return fmt.Errorf("console: UsePhone needs exactly one phone origin, have %d", len(phone))
	}
	t, err := newTemplate().ParseFS(web.Templates(), "layout.html", "fragments.html")
	if err != nil {
		return fmt.Errorf("console: phone layout: %w", err)
	}
	if t, err = t.Parse(phoneHTML); err != nil {
		return fmt.Errorf("console: phone page: %w", err)
	}
	if cfg.EnrollTTL == 0 {
		cfg.EnrollTTL = 10 * time.Minute
	}
	c.phone = &phoneConfig{PhoneConfig: cfg, origin: phone[0], page: t}
	return nil
}

func (c *Console) phoneRoutes(mux *http.ServeMux) {
	if c.phone == nil {
		return
	}
	mux.HandleFunc("GET /phone", c.phonePage)
	mux.HandleFunc("POST /phone/{id}/match", c.phoneMatch)
	mux.HandleFunc("POST /phone/enroll", c.phoneEnrollRequest)
	mux.HandleFunc("POST /phone/{id}/enrollment", c.phoneEnrollment)
}

// ---- the phone page ----

type phoneCardView struct {
	cardView
	Numbers [3]string
}

type phoneView struct {
	Title, CSRF, Origin, Approver string
	Cards                         []phoneCardView
	Framed                        bool // see Console.framed: no header, no nav
}

func (c *Console) phonePage(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	if !c.appr.IsPhoneOrigin(st.rp.URL) {
		http.NotFound(w, r) // the server console has no phone page
		return
	}
	if st.user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	pending, err := c.appr.Pending(r.Context())
	if err != nil {
		c.log.Error("list approvals", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	v := phoneView{Title: "Approvals", CSRF: c.csrfToken(st), Origin: st.rp.URL, Approver: st.user.Name, Framed: st.framed}
	now := c.now()
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].RequestExpires.Before(pending[j].RequestExpires) })
	for _, a := range pending {
		nums, err := c.appr.PhoneChoices(r.Context(), a.ID)
		var ref *approvals.Refusal
		switch {
		case errors.As(err, &ref):
			continue // decided or expired since the list was read
		case err != nil:
			c.log.Error("phone numbers", "approval", a.ID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		v.Cards = append(v.Cards, phoneCardView{cardViewOf(a, now), nums})
	}
	var buf bytes.Buffer
	if err := c.phone.page.ExecuteTemplate(&buf, "layout", v); err != nil {
		c.log.Error("render phone page", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// cardViewOf is the page's view of a pending card. The text, its split and the
// who/what words all come from the stored card text; Age and ExpiresIn are
// drawn from the clock and are not part of what is signed.
func cardViewOf(a *approvals.Approval, now time.Time) cardView {
	who, what, secs, split := askOf(a)
	return cardView{
		ID: a.ID, Op: a.Op, Project: a.Project, Requester: requesterLabel(a), Class: string(a.Class),
		Expires: a.RequestExpires.UTC().Format(time.RFC3339), Text: a.CardText, DisplaySHA: a.DisplaySHA256,
		Critical: a.Critical(), Sections: secs, Split: split, Who: who, What: what, Risk: approvals.Risk(a),
		Age: ago(now, a.Created), ExpiresIn: until(now, a.RequestExpires),
	}
}

// phoneMatch is POST /phone/{id}/match: the approver tapped one of the numbers.
func (c *Console) phoneMatch(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	actor, ok := c.approvalActor(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	}
	var req struct {
		Choice string `json:"choice"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ReasonMalformed)
		return
	}
	res, err := c.appr.PhoneMatch(r.Context(), approvals.PhoneMatchInput{
		ApprovalID: r.PathValue("id"), Actor: actor, Origin: st.rp.URL, Binding: sum([]byte(st.csrfCookie)), Choice: req.Choice})
	if err != nil {
		c.approvalFailed(w, r, err)
		return
	}
	if res.Denied != nil {
		c.log.Warn("phone number mismatch: card denied", "approval", res.Denied.ID)
		c.emit(Event{Name: EventRefused, Reason: ReasonNumber, ApproverID: actor.ApproverRow, RPID: st.rp.RPID, Origin: st.rp.URL})
		writeJSON(w, http.StatusOK, map[string]any{"matched": false, "state": res.Denied.State})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matched": true})
}

// ReasonNumber is the refusal reason of a wrong number on the phone.
const ReasonNumber = "number_mismatch"

// ---- enrolling the phone ----

// phoneEnrollRequest is POST /phone/enroll, on the server only: the operator asks for
// the critical-class op approvers.enroll. It makes the card; the operator reads
// it and approves it with Windows Hello like any other, and then spends it on
// the server page to get the address.
func (c *Console) phoneEnrollRequest(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	actor, ok := c.approvalActor(r)
	switch {
	case !ok:
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	case actor.Kind != approvals.ActorApprover:
		writeError(w, http.StatusForbidden, "not_an_approver")
		return
	case c.appr.IsPhoneOrigin(st.rp.URL):
		// The phone is not where the phone is enrolled: a stolen unlocked
		// phone must not be able to add itself again or add another device.
		writeError(w, http.StatusForbidden, "enrol_from_the_pc")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ReasonMalformed)
		return
	}
	label, ok := cleanName(req.Label, "Phone passkey")
	if !ok {
		writeError(w, http.StatusBadRequest, ReasonMalformed)
		return
	}
	now := c.now()
	ttl := c.appr.RequestTTL("approvers.enroll")
	rq := spec.Request{
		SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: "q-" + randLower(10),
		Requester: spec.Requester{Kind: "orchestrator", ID: operatorID},
		Project:   "chaperone", Op: "approvers.enroll", Target: spec.Target{Adapter: "console", Ref: actor.ApproverID},
		Params:      map[string]any{"label": label, "origin": c.phone.origin.URL},
		Reason:      "Operator console: add a phone passkey",
		RequestedAt: now.UTC().Truncate(time.Second).Format(specTimeLayout),
		ExpiresAt:   now.Add(ttl).UTC().Truncate(time.Second).Format(specTimeLayout),
	}
	var err error
	if rq.OpHash, err = spec.OpHash(rq); err != nil {
		c.log.Error("hash enrolment request", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	check := spec.ApprovalCheck{Name: "enrol.origin", Passed: true,
		Detail: "the passkey is bound to RP ID " + c.phone.origin.RPID + " and works only at " + c.phone.origin.URL}
	var res approvals.Result
	err = c.appr.Atomic(r.Context(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		var err error
		res, err = c.appr.RequestTx(ctx, tx, approvals.RequestInput{Request: rq, PolicyVersion: c.phone.PolicyVersion(), Checks: []spec.ApprovalCheck{check}})
		if err != nil || res.Refusal != nil || !res.Created {
			return approvals.Effects{}, err // commit: a stop hook may have written
		}
		return res.Effects, c.phone.Record.AppendTx(ctx, tx, approvals.LedgerEvent{
			Name: "op.request", Project: "chaperone", Severity: "WARN",
			Attributes: map[string]any{
				"factory.request_id": rq.RequestID, "factory.op": rq.Op, "factory.op_hash": rq.OpHash,
				"factory.reversibility": "compensable", "factory.requester.kind": "orchestrator", "factory.orchestrator.id": operatorID,
			},
			Body: "orchestrator=" + operatorID + " operator asked to enrol a phone passkey at " + c.phone.origin.URL,
		})
	})
	if err != nil {
		c.log.Error("request phone enrolment", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if res.Refusal != nil {
		writeJSON(w, refusalStatus(res.Refusal.Code), map[string]string{"error": res.Refusal.Code, "why": res.Refusal.Why})
		return
	}
	if !res.Created {
		writeError(w, http.StatusConflict, "already_waiting")
		return
	}
	c.log.Warn("phone enrolment requested", "approval", res.Approval.ID, "origin", c.phone.origin.URL)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "approval": res.Approval.ID})
}

// operatorEnrollment reports whether a is an approvers.enroll the console itself
// asked for, aimed at the configured phone origin.
func (c *Console) operatorEnrollment(a *approvals.Approval) bool {
	return a != nil && a.Op == "approvers.enroll" && a.RequesterKind == "orchestrator" && a.RequesterKey == operatorID &&
		paramString(a.Request.Params, "origin") == c.phone.origin.URL
}

// phoneEnrollment is POST /phone/{id}/enrollment, on the server only: spend the
// approved approvers.enroll and answer with the one-time address of the phone's
// enrolment page and its QR code. The approval is consumed in the same
// transaction that stores the token's hash, so one approval makes one address.
func (c *Console) phoneEnrollment(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	actor, ok := c.approvalActor(r)
	switch {
	case !ok:
		writeError(w, http.StatusUnauthorized, "signed_out")
		return
	case actor.Kind != approvals.ActorApprover:
		writeError(w, http.StatusForbidden, "not_an_approver")
		return
	case c.appr.IsPhoneOrigin(st.rp.URL):
		writeError(w, http.StatusForbidden, "enrol_from_the_pc")
		return
	}
	a, err := c.appr.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		c.log.Error("get approval", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !c.operatorEnrollment(a) {
		writeError(w, http.StatusNotFound, approvals.CodeNoSuchApproval)
		return
	}
	if a.State != approvals.StateApproved {
		writeJSON(w, http.StatusConflict, map[string]string{"error": approvals.CodeApprovalRequired, "why": "this request is " + string(a.State) + "; only an approved one can be spent"})
		return
	}
	if a.Approver != actor.ApproverID {
		// The card was approved by another approver: only that person's
		// credential list grows.
		writeError(w, http.StatusForbidden, "other_approver")
		return
	}
	now := c.now()
	var token string
	err = c.appr.Atomic(r.Context(), func(ctx context.Context, tx *store.Tx) (approvals.Effects, error) {
		fx, err := c.appr.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: a.ID, Request: a.Request})
		if err != nil {
			return approvals.Effects{}, err
		}
		row := actor.ApproverRow
		if token, err = issueEnrollmentTx(ctx, tx, &row, c.phone.EnrollTTL, now); err != nil {
			return approvals.Effects{}, err
		}
		err = c.phone.Record.AppendTx(ctx, tx, approvals.LedgerEvent{
			Name: "op.result", Project: "chaperone", Severity: "WARN",
			Attributes: map[string]any{
				"factory.request_id": a.RequestID, "factory.op_hash": a.OpHash, "factory.execution_id": "x-" + randLower(10),
				"factory.outcome": "succeeded", "factory.policy_version": a.PolicyVersion, "factory.requester.kind": "orchestrator", "factory.orchestrator.id": operatorID,
			},
			Body: "orchestrator=" + operatorID + " phone enrolment address issued for " + c.phone.origin.URL + " (token not recorded)",
		})
		return fx, err
	})
	var ref *approvals.Refusal
	switch {
	case errors.As(err, &ref):
		c.approvalFailed(w, r, err)
		return
	case err != nil:
		c.log.Error("issue phone enrolment", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	// The token is a fragment, so it never reaches a server log or a Referer.
	addr := c.phone.origin.URL + "/enroll#" + token
	img, err := qrImage(addr)
	if err != nil {
		// The address is the real deliverable; the QR code is a convenience.
		c.log.Warn("phone enrolment qr", "err", err)
	}
	c.log.Warn("phone enrolment address issued", "approval", a.ID, "origin", c.phone.origin.URL)
	writeJSON(w, http.StatusOK, map[string]any{"address": addr, "qr": img, "expires_at": now.Add(c.phone.EnrollTTL).UTC().Format(time.RFC3339)})
}

// qrImage is the address as an SVG data: URI, which the page's CSP allows as an
// image (img-src data:).
func qrImage(text string) (string, error) {
	svg, err := qr.SVG(text)
	if err != nil {
		return "", err
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)), nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v)
}
