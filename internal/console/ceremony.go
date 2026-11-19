package console

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyHeader = "X-Ceremony-ID"
	maxBody        = 64 << 10 // an attestation with a TPM chain is a few KB
)

// Refusal reasons: stable codes in events and in the {"error": ...} bodies.
const (
	ReasonCeremony   = "ceremony_unknown" // unknown, expired, replayed, wrong kind, wrong browser
	ReasonMalformed  = "malformed"
	ReasonOrigin     = "origin_mismatch"
	ReasonChallenge  = "challenge_mismatch"
	ReasonRPID       = "rp_id_mismatch"
	ReasonUV         = "uv_missing"
	ReasonUP         = "up_missing"
	ReasonSignature  = "bad_signature"
	ReasonCredential = "credential_not_allowed"
	ReasonAttachment = "attachment_not_allowed" // the kind of authenticator (built in, security key, phone) is not allowed by Config.Authenticators
	ReasonClone      = "clone_warning"
	ReasonEnrolment  = "enrolment_refused"
	ReasonVerify     = "verification_failed"
	ReasonAssertion  = "assertion_refused" // an approval's assertion failed (the text is in Event.Detail, log only)
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": reason})
}

// refused records a refusal and answers with the reason code only: the
// library's text can say which check failed, which an attacker does not need.
func (c *Console) refused(w http.ResponseWriter, r *http.Request, status int, reason string, err error, ev Event) {
	st := stateOf(r)
	ev.Name, ev.Reason, ev.Ceremony = EventRefused, reason, ceremonyOf(r.URL.Path)
	if err != nil {
		ev.Detail = detail(err)
	}
	if ev.RPID == "" {
		ev.RPID, ev.Origin = st.rp.RPID, st.rp.URL
	}
	c.log.Warn("webauthn refused", "path", r.URL.Path, "reason", reason, "detail", ev.Detail)
	c.emit(ev)
	writeError(w, status, reason)
}

func detail(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return strings.TrimSpace(pe.Type + ": " + pe.Details + " " + pe.DevInfo)
	}
	return err.Error()
}

// reasonOf maps a go-webauthn error to a refusal code.
func reasonOf(err error) string {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		return ReasonVerify
	}
	text := pe.Details + " " + pe.DevInfo
	switch {
	case strings.Contains(text, "Error validating challenge"):
		return ReasonChallenge
	case strings.Contains(text, "Error validating origin"), strings.Contains(text, "Error validating top origin"),
		strings.Contains(text, "Error validating topOrigin"), strings.Contains(text, "Error validating cross origin flag"):
		return ReasonOrigin
	case strings.Contains(text, "RP Hash mismatch"):
		return ReasonRPID
	case strings.Contains(text, "User verification required"):
		return ReasonUV
	case strings.Contains(text, "User presence required"):
		return ReasonUP
	case strings.Contains(text, "Session has Expired"):
		return ReasonCeremony
	case pe == protocol.ErrAssertionSignature || strings.Contains(text, "assertion signature"):
		return ReasonSignature
	}
	return ReasonVerify
}

// beginCeremony stores sd and answers with the options and the ceremony id.
func (c *Console) beginCeremony(w http.ResponseWriter, r *http.Request, cm *ceremony, options any) {
	st := stateOf(r)
	cm.ID = randBytes(16)
	cm.Origin = st.rp.URL
	cm.CSRFSum = sum([]byte(st.csrfCookie))
	if err := c.putCeremony(r.Context(), cm); err != nil {
		if errors.Is(err, errTooManyCeremonies) {
			c.log.Warn("ceremony cap reached")
			writeError(w, http.StatusTooManyRequests, "busy")
			return
		}
		c.log.Error("store ceremony", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": b64.EncodeToString(cm.ID), "options": options})
}

// finishCeremony takes (and so burns) the ceremony named in the request and
// checks that it is the right kind, for this origin, from this browser. On
// any failure it has already answered.
func (c *Console) finishCeremony(w http.ResponseWriter, r *http.Request, kind string) (*ceremony, []byte, bool) {
	st := stateOf(r)
	id, err := b64.DecodeString(r.Header.Get(ceremonyHeader))
	if err != nil || len(id) != 16 {
		c.refused(w, r, http.StatusBadRequest, ReasonCeremony, errors.New("bad ceremony id"), Event{})
		return nil, nil, false
	}
	cm, err := c.takeCeremony(r.Context(), id)
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, errNoCeremony) {
			status = http.StatusInternalServerError
		}
		c.refused(w, r, status, ReasonCeremony, err, Event{})
		return nil, nil, false
	}
	if cm.Kind != kind || cm.Origin != st.rp.URL ||
		subtle.ConstantTimeCompare(cm.CSRFSum, sum([]byte(st.csrfCookie))) != 1 {
		c.refused(w, r, http.StatusBadRequest, ReasonCeremony, errors.New("ceremony does not belong to this request"), Event{})
		return nil, nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		c.refused(w, r, http.StatusBadRequest, ReasonMalformed, err, Event{})
		return nil, nil, false
	}
	return cm, body, true
}

// ---- login ----

func (c *Console) loginBegin(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	n, err := c.approverCount(r.Context())
	if err != nil {
		c.log.Error("count approvers", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if n == 0 {
		writeError(w, http.StatusConflict, "no_approver")
		return
	}
	// Discoverable login: the passkey picker names the credential, so the
	// server reveals nothing about who is enrolled before the assertion.
	assertion, sd, err := st.rp.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		c.log.Error("begin login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	c.beginCeremony(w, r, &ceremony{Kind: "login", Session: *sd}, assertion)
}

func (c *Console) loginFinish(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	cm, body, ok := c.finishCeremony(w, r, "login")
	if !ok {
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		c.refused(w, r, http.StatusBadRequest, ReasonMalformed, err, Event{})
		return
	}
	flags := parsed.Response.AuthenticatorData.Flags
	// User verification is the whole point (ADR-004). go-webauthn checks it
	// because the ceremony says "required"; this is the second, explicit check.
	if !flags.UserVerified() {
		c.refused(w, r, http.StatusForbidden, ReasonUV, errors.New("UV flag not set in assertion"), Event{CredentialID: parsed.RawID})
		return
	}
	if !flags.UserPresent() {
		c.refused(w, r, http.StatusForbidden, ReasonUP, errors.New("UP flag not set in assertion"), Event{CredentialID: parsed.RawID})
		return
	}

	var found, blocked *credential
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		cr, err := c.credentialByRawID(r.Context(), rawID)
		if err != nil {
			return nil, err
		}
		// The credential must belong to this origin and RP ID, be live, and
		// belong to the approver the authenticator says it does.
		if cr.Revoked || cr.RPID != st.rp.RPID || cr.Origin != st.rp.URL {
			return nil, protocol.ErrBadRequest.WithDetails("credential is not registered for this origin")
		}
		ap, err := c.approverByID(r.Context(), cr.ApproverID)
		if err != nil {
			return nil, err
		}
		if ap.Disabled || !bytes.Equal(ap.Handle, userHandle) {
			return nil, protocol.ErrBadRequest.WithDetails("approver disabled or user handle mismatch")
		}
		// The setting may have been narrowed since this credential was made: a security key enrolled while it said
		// "any" is refused once it says "platform" again.
		if !c.attachmentAllowed(cr.WA.Authenticator.Attachment) {
			blocked = cr
			return nil, protocol.ErrBadRequest.WithDetails("credential's authenticator kind is not allowed by the authenticators setting")
		}
		found = cr
		return &waUser{handle: ap.Handle, name: ap.Name, creds: []webauthn.Credential{cr.WA}}, nil
	}
	_, updated, err := st.rp.wa.ValidatePasskeyLogin(lookup, cm.Session, parsed)
	if err != nil {
		reason := reasonOf(err)
		ev := Event{CredentialID: parsed.RawID}
		switch {
		case blocked != nil:
			reason, ev.Attachment = ReasonAttachment, string(blocked.WA.Authenticator.Attachment)
		case found == nil:
			reason = ReasonCredential
		}
		c.refused(w, r, http.StatusForbidden, reason, err, ev)
		return
	}
	if updated.Authenticator.CloneWarning {
		c.refused(w, r, http.StatusForbidden, ReasonClone, errors.New("signature counter did not advance"), Event{CredentialID: parsed.RawID})
		return
	}
	if err := c.recordLogin(r.Context(), found, updated); err != nil {
		c.log.Error("record login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	token, err := c.newSession(r.Context(), found.ApproverID, found.ID, st.rp.URL)
	if err != nil {
		c.log.Error("new session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	http.SetCookie(w, c.cookie(st.rp, sessionCookie, token, 0))
	ev := authnFacts(Event{Name: EventLogin, ApproverID: found.ApproverID, CredentialID: found.WA.ID,
		RPID: st.rp.RPID, Origin: st.rp.URL, UserVerified: flags.UserVerified(), SignCount: updated.Authenticator.SignCount}, updated)
	if ap, err := c.approverByID(r.Context(), found.ApproverID); err == nil {
		ev.ApproverSpecID = approverSpecID(ap)
	}
	c.emit(ev)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/"})
}

// ---- enrolment ----

type enrollRequest struct {
	Token string `json:"token"`
	Name  string `json:"name"`  // first approver only
	Label string `json:"label"` // this credential
}

// cleanName accepts 1-64 printable characters.
func cleanName(s, fallback string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = fallback
	}
	if s == "" || utf8.RuneCountInString(s) > 64 {
		return "", false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return s, true
}

func (c *Console) enrollBegin(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		c.refused(w, r, http.StatusBadRequest, ReasonMalformed, err, Event{})
		return
	}
	label, ok1 := cleanName(req.Label, "Passkey")
	name, ok2 := cleanName(req.Name, "operator")
	if !ok1 || !ok2 || req.Token == "" || len(req.Token) > 128 {
		c.refused(w, r, http.StatusBadRequest, ReasonMalformed, errors.New("bad enrolment fields"), Event{})
		return
	}
	tokenSum := sum([]byte(req.Token))
	target, err := c.checkEnrollment(r.Context(), tokenSum)
	if err != nil {
		c.refusedEnroll(w, r, err)
		return
	}

	user := &waUser{name: name}
	cm := &ceremony{Kind: "register", ApproverName: name, CredentialLabel: label, EnrollmentSHA256: tokenSum}
	var opts []webauthn.RegistrationOption
	if target.Valid {
		ap, err := c.approverByID(r.Context(), target.Int64)
		if err != nil || ap.Disabled {
			c.refusedEnroll(w, r, errNoApprover)
			return
		}
		user.handle, user.name, cm.ApproverID = ap.Handle, ap.Name, target
		creds, err := c.credentialsOf(r.Context(), ap.ID)
		if err != nil {
			c.log.Error("list credentials", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		var exclude []protocol.CredentialDescriptor
		for _, cr := range creds {
			if cr.RPID == st.rp.RPID {
				exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: cr.WA.ID})
			}
		}
		opts = append(opts, webauthn.WithExclusions(exclude))
	} else {
		user.handle = randBytes(32)
		cm.NewUserHandle = user.handle
	}
	creation, sd, err := st.rp.wa.BeginRegistration(user, opts...)
	if err != nil {
		c.log.Error("begin registration", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	cm.Session = *sd
	c.beginCeremony(w, r, cm, creation)
}

// refusedEnroll answers a token or approver problem with one code, whichever
// it is, so the endpoint does not tell a guesser which part was wrong.
func (c *Console) refusedEnroll(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusForbidden
	if !errors.Is(err, errEnrollToken) && !errors.Is(err, errApproverExists) && !errors.Is(err, errNoApprover) {
		status = http.StatusInternalServerError
		c.log.Error("enrolment", "err", err)
		writeError(w, status, "internal")
		return
	}
	c.refused(w, r, status, ReasonEnrolment, err, Event{})
}

func (c *Console) enrollFinish(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	cm, body, ok := c.finishCeremony(w, r, "register")
	if !ok {
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		c.refused(w, r, http.StatusBadRequest, ReasonMalformed, err, Event{})
		return
	}
	flags := parsed.Response.AttestationObject.AuthData.Flags
	if !flags.UserVerified() {
		c.refused(w, r, http.StatusForbidden, ReasonUV, errors.New("UV flag not set at registration"), Event{CredentialID: parsed.RawID})
		return
	}
	if !flags.UserPresent() {
		c.refused(w, r, http.StatusForbidden, ReasonUP, errors.New("UP flag not set at registration"), Event{CredentialID: parsed.RawID})
		return
	}
	// Which kinds of authenticator may be enrolled is Config.Authenticators. Everything else here (UV, UP, the
	// relying party, the origin, the attestation) is checked the same for every kind.
	if a := parsed.AuthenticatorAttachment; !c.attachmentAllowed(a) {
		c.refused(w, r, http.StatusForbidden, ReasonAttachment, errors.New("authenticator attachment "+string(a)+" is not allowed by the authenticators setting"),
			Event{CredentialID: parsed.RawID, Attachment: string(a)})
		return
	}
	user := &waUser{handle: cm.Session.UserID, name: cm.ApproverName}
	cred, err := st.rp.wa.CreateCredential(user, cm.Session, parsed)
	if err != nil {
		c.refused(w, r, http.StatusForbidden, reasonOf(err), err, Event{CredentialID: parsed.RawID})
		return
	}
	// What the browser said about the transports is free text: keep the known ones. An attachment it did not give is
	// recorded as the wider kind under the wider setting (recordedAttachment).
	cred.Transport = cleanTransports(cred.Transport)
	cred.Authenticator.Attachment = c.recordedAttachment(cred.Authenticator.Attachment)
	approverID, err := c.saveEnrollment(r.Context(), cm, st.rp.Origin, cred)
	if err != nil {
		c.refusedEnroll(w, r, err)
		return
	}
	c.emit(authnFacts(Event{Name: EventEnrolled, ApproverID: approverID, Bootstrap: !cm.ApproverID.Valid, CredentialID: cred.ID, RPID: st.rp.RPID,
		Origin: st.rp.URL, UserVerified: cred.Flags.UserVerified, SignCount: cred.Authenticator.SignCount}, cred))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/login"})
}

// ceremonyOf names the ceremony a request path belongs to, as the spec's
// console.refused ceremony: login, enroll or approve.
func ceremonyOf(path string) string {
	switch {
	case strings.HasPrefix(path, "/login"):
		return "login"
	case strings.HasPrefix(path, "/enroll"):
		return "enroll"
	}
	return "approve"
}
