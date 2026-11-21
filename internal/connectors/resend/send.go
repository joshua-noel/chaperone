package resend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// evidenceName is the name of the evidence block of the card. It is the name the
// Google connector uses for the same operation, so the card has the same shape.
const evidenceName = "mail.send message"

// sendAdapter is mail.send for target.adapter resend.
//
// What the operator signs is bound to what is sent in three ways.
//
//  1. The op hash covers the project, the target (the sender) and every param
//     (to, cc, bcc, subject, body), and the card shows them.
//  2. Check puts the sender, the recipient counts, the SHA-256 of the body and
//     the SHA-256 of the exact JSON that goes to Resend in the card's evidence.
//     The JSON is made by [Message.JSON], the function the client sends from.
//  3. When Execute runs under an approval, it makes the evidence again and
//     refuses to send unless it is, byte for byte, the evidence that was shown.
type sendAdapter struct{ base }

var _ ops.Adapter = (*sendAdapter)(nil)

// prepared is one validated message and what the card says about it.
type prepared struct {
	pol     string // the project, for the card
	maxN    int    // resend.max_recipients in force
	msg     Message
	n       int
	json    []byte
	reqSHA  string
	bodySHA string
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// recipients validates one list of recipients: its shape, and that no address is
// listed twice in the message. It never repeats an address in an error.
func recipients(r *ops.Request, key string, seen map[string]bool) ([]string, error) {
	list, err := paramStrings(r.Params, key)
	if err != nil {
		return nil, err
	}
	if len(list) > resendspec.MaxRecipients {
		return nil, paramsInvalid("param %s lists %d recipients; at most %d", key, len(list), resendspec.MaxRecipients)
	}
	for i, a := range list {
		if len(a) > resendspec.MaxAddressBytes || !recipientRE.MatchString(a) {
			return nil, paramsInvalid("recipient %d of %s is not a plain lower-case address (no name, no <>, ASCII only)", i+1, key)
		}
		if seen[a] {
			return nil, paramsInvalid("recipient %d of %s is listed twice in the message", i+1, key)
		}
		seen[a] = true
	}
	return list, nil
}

// parse is the one place a send request is validated and rendered. Check and
// Execute both call it, so a request that Check refuses is refused again when
// Execute runs, and both see the same bytes.
func (a *sendAdapter) parse(r *ops.Request) (*prepared, error) {
	pol, err := a.resolve(r)
	if err != nil {
		return nil, err
	}
	// The declaration lists the params; this version has no `attachments`. Say so
	// plainly, because the Gmail side of the same name takes them.
	if _, has := r.Params["attachments"]; has {
		return nil, paramsInvalid("this connector sends plain text only: no attachments through Resend")
	}
	if err := onlyParams(r.Params, resendspec.MailSend.ParamNames()...); err != nil {
		return nil, err
	}
	sender := r.Target.Ref
	if len(sender) > resendspec.MaxAddressBytes || !senderRE.MatchString(sender) {
		return nil, paramsInvalid("target.ref must be the sender: a plain lower-case address (no name, no <>)")
	}
	seen := map[string]bool{}
	to, err := recipients(r, "to", seen)
	if err != nil {
		return nil, err
	}
	cc, err := recipients(r, "cc", seen)
	if err != nil {
		return nil, err
	}
	bcc, err := recipients(r, "bcc", seen)
	if err != nil {
		return nil, err
	}
	if len(to) == 0 {
		return nil, paramsInvalid("param to needs at least one recipient")
	}
	all := slices.Concat(to, cc, bcc)
	if len(all) > resendspec.MaxRecipients {
		return nil, paramsInvalid("at most %d recipients in all", resendspec.MaxRecipients)
	}
	subject, err := paramString(r.Params, "subject")
	if err != nil {
		return nil, err
	}
	if err := checkText("subject", subject, false, resendspec.MaxSubjectBytes); err != nil {
		return nil, err
	}
	if subject != strings.TrimSpace(subject) {
		return nil, paramsInvalid("subject must not start or end with a space")
	}
	body, err := paramString(r.Params, "body")
	if err != nil {
		return nil, err
	}
	if err := checkText("body", body, true, resendspec.MaxBodyBytes); err != nil {
		return nil, err
	}

	// The policy comes before everything that costs anything, and before a card
	// can exist. Each refusal says which part of the message failed and never
	// repeats an address.
	project := clip(r.Project, 60)
	if !pol.SenderAllowed(sender) {
		return nil, policyRefused("sender_listed: the sender is not one of the resend.senders of project %s", project)
	}
	if len(all) > pol.MaxRecipients {
		return nil, policyRefused("recipient_cap: the message has %d recipients; project %s allows at most %d (resend.max_recipients)", len(all), project, pol.MaxRecipients)
	}
	for _, g := range []struct {
		key  string
		list []string
	}{{"to", to}, {"cc", cc}, {"bcc", bcc}} {
		for i, addr := range g.list {
			if !pol.RecipientAllowed(addr) {
				return nil, policyRefused("recipients_allowlisted: recipient %d of %s is not on the resend.allow_recipients of project %s", i+1, g.key, project)
			}
		}
	}
	if err := a.scan("the subject", subject); err != nil {
		return nil, err
	}
	if err := a.scan("the body", body); err != nil {
		return nil, err
	}

	m := Message{From: sender, To: to, Cc: cc, Bcc: bcc, Subject: subject, Text: body}
	raw, err := m.JSON()
	if err != nil {
		return nil, paramsInvalid("the message cannot be rendered")
	}
	return &prepared{pol: project, maxN: pol.MaxRecipients, msg: m, n: len(all), json: raw, reqSHA: sum(raw), bodySHA: sum([]byte(body))}, nil
}

// evidence is the text of the card's evidence block. It holds only values that
// were checked above (an address of a fixed shape, a count, a hex digest).
func (p *prepared) evidence() string {
	var b strings.Builder
	b.WriteString("Sent through: Resend API (plain text only: no attachment, no HTML, no scheduled send)\n")
	fmt.Fprintf(&b, "Sender: %s\n", p.msg.From)
	fmt.Fprintf(&b, "Recipients: %d (to %d, cc %d, bcc %d), every one on the allow-list of project %s\n", p.n, len(p.msg.To), len(p.msg.Cc), len(p.msg.Bcc), p.pol)
	fmt.Fprintf(&b, "Body: %d bytes, SHA-256 %s\n", len(p.msg.Text), p.bodySHA)
	fmt.Fprintf(&b, "Request to Resend: %d bytes, SHA-256 %s", len(p.json), p.reqSHA)
	return b.String()
}

// Check validates the request and renders the message; it sends nothing. It
// reads the vault, to refuse before a card is made when there is no API key.
func (a *sendAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	if err := a.cfg.Client.SendReady(ctx); err != nil {
		return ops.CheckResult{}, credentialRefusal(err)
	}
	return ops.CheckResult{
		Checks: []ops.Check{
			{Name: "sender_listed", Passed: true, Detail: "resend.senders of project " + p.pol},
			{Name: "recipients_allowlisted", Passed: true, Detail: fmt.Sprintf("%d of %d on the allow-list of project %s", p.n, p.n, p.pol)},
			{Name: "recipient_cap", Passed: true, Detail: fmt.Sprintf("%d recipient(s), at most %d", p.n, p.maxN)},
			{Name: "plain_text_only", Passed: true, Detail: "no attachment, no HTML, no reply-to, no scheduled send, no template, no tag, no header"},
			{Name: "no_secret_in_message", Passed: true},
			{Name: "resend_connected", Passed: true, Detail: "sending key present in the vault"},
		},
		Evidence: []ops.Evidence{{Name: evidenceName, Text: p.evidence()}},
	}, nil
}

// bound checks the evidence the card showed against the message that is about
// to be sent. A request that is not released under an approval has none to
// check; a request that is must match it exactly.
func (p *prepared) bound(approved []ops.Evidence) error {
	if len(approved) == 0 {
		return nil
	}
	for _, e := range approved {
		if e.Name == evidenceName {
			if e.Text == p.evidence() {
				return nil
			}
			break
		}
	}
	return policyRefused("approval_binding: the message to be sent is not the message that was approved; nothing was sent")
}

// Execute sends the message once, with an idempotency key made from the
// execution id. The adapter never repeats a send itself (the HTTP transport may replay
// the identical request with the same key, see Client.Send): a send whose answer was lost ends
// `unconfirmed`, and the result says what to look up.
func (a *sendAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	if err := p.bound(r.ApprovedEvidence); err != nil {
		return failed(err, nil), nil
	}
	key := IdempotencyKey(r.ExecutionID)
	if key == "" {
		return failed(paramsInvalid("there is no usable execution id to make the idempotency key from; nothing was sent"), nil), nil
	}
	res := map[string]any{
		"sender": p.msg.From, "recipients": p.n,
		"body_sha256": p.bodySHA, "request_sha256": p.reqSHA, "request_bytes": len(p.json),
	}
	id, err := a.cfg.Client.Send(ctx, p.msg, key)
	switch {
	case err == nil:
	case Definite(err):
		res["error"] = clip(reason(err)+"; nothing was sent", 400)
		return ops.Outcome{Failed: true, Result: res}, nil
	default:
		res["error"] = clip(reason(err)+"; the message may or may not have been sent: look in the Emails page of Resend (or its Logs page) for a message from "+p.msg.From+" just now, before sending again", 400)
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	if strings.TrimSpace(id) == "" {
		res["error"] = "Resend answered without an email id; look in the Emails page of Resend for the message before sending again"
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	// The id is Resend's text: cleaned, capped, and withheld when it looks like a
	// secret. Nothing is decided from it.
	text, held := a.serviceText(id, maxMessageID)
	res["untrusted_text"], res["message_id"] = true, text
	ref := "resend:email/" + text
	if held {
		res["withheld"], ref = true, "resend:email/withheld"
	}
	return ops.Outcome{ExternalRef: ref, Result: res}, nil
}
