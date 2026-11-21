package resend

import (
	"context"
	"errors"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// events is the closed list of delivery events Resend documents (Dashboard,
// "View and manage emails", "Understand email events"). A last_event that is not
// on the list is reported as "other": the word is Resend's, and a word that is
// not known is never shown.
var events = []string{
	"bounced", "canceled", "clicked", "complained", "delivered", "delivery_delayed",
	"failed", "opened", "queued", "scheduled", "sent", "suppressed",
}

// statusAdapter is mail.status. It reads one email and says its last event. It
// shows nothing that Resend wrote except a word of the closed list and a time:
// no subject, no body, no address, no error message.
//
// The email must have been sent from one of the project's resend.senders. The
// check is on the object, after it is read, and it is an exact match on the
// value Resend gives for the sender: Resend's key reads every email of the
// account, and an id is not a reason to show a message that this project did not
// send.
type statusAdapter struct{ base }

var _ ops.Adapter = (*statusAdapter)(nil)

type statusParams struct {
	id  string
	pol string
	// senders is the policy's list, held so Execute fences with the same object
	// that parse resolved.
	senders func(string) bool
}

func (a *statusAdapter) parse(r *ops.Request) (statusParams, error) {
	var p statusParams
	pol, err := a.resolve(r)
	if err != nil {
		return p, err
	}
	if !statusRE.MatchString(r.Target.Ref) {
		return p, paramsInvalid("target.ref must be the id of an email, a UUID such as 49a3999c-0ce1-4ea6-ab68-afcd6dc2e794")
	}
	if err := onlyParams(r.Params, resendspec.MailStatus.ParamNames()...); err != nil {
		return p, err
	}
	return statusParams{id: r.Target.Ref, pol: clip(r.Project, 60), senders: pol.SenderAllowed}, nil
}

// Check validates the request and reads the vault, to refuse when there is no
// status key. It sends nothing.
func (a *statusAdapter) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	if err := a.cfg.Client.StatusReady(ctx); err != nil {
		return ops.CheckResult{}, credentialRefusal(err)
	}
	return ops.CheckResult{Checks: []ops.Check{
		{Name: "sender_fence", Passed: true, Detail: "the email must have been sent from a resend.senders address of project " + p.pol},
		{Name: "status_key_present", Passed: true, Detail: "status key present in the vault"},
	}}, nil
}

// Execute reads the email once and reports its last event.
func (a *statusAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err, nil), nil
	}
	res := map[string]any{"email": p.id}
	em, err := a.cfg.Client.Email(ctx, p.id)
	if err != nil {
		err = credentialRefusal(err)
		if ref, ok := err.(*ops.Refusal); ok {
			return failed(ref, res), nil
		}
		res["error"] = clip(reason(err), 400)
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			res["error"] = "Resend has no email with that id that the status key can see"
		}
		return ops.Outcome{Failed: true, Result: res}, nil // a read changes nothing: the caller may ask again
	}
	if em.ID != p.id {
		res["error"] = "Resend answered for a different email than the one asked for"
		return ops.Outcome{Failed: true, Result: res}, nil
	}
	// The fence: the decision is made on Resend's value as it is, by an exact match,
	// and no text of Resend's goes into the refusal.
	if !p.senders(em.From) {
		res["error"] = "that email was not sent from a sender listed in resend.senders of project " + p.pol + "; nothing about it is shown"
		return ops.Outcome{Failed: true, Result: res}, nil
	}
	res["sender"] = em.From // listed by the policy, so it is the policy's own text
	res["last_event"] = eventWord(em.LastEvent)
	if t, ok := stamp(em.CreatedAt); ok {
		res["created_at"] = t
	}
	return ops.Outcome{ExternalRef: "resend:email/" + p.id, Result: res}, nil
}

// eventWord returns s when it is a documented event, else "other".
func eventWord(s string) string {
	for _, e := range events {
		if s == e {
			return e
		}
	}
	return "other"
}

// stamp returns an RFC 3339 time in UTC for a time as Resend writes it, or false
// when s is not one. Resend's example is "2026-04-03 22:13:42.674981+00".
func stamp(s string) (string, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999Z07", "2006-01-02 15:04:05.999999999Z07:00", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339), true
		}
	}
	return "", false
}
