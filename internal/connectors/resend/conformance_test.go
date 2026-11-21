package resend

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/conformance"
	"github.com/joshua-noel/chaperone/internal/connectors/pintable"
	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendspec"
	"github.com/joshua-noel/chaperone/internal/connectors/resend/resendtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
)

// This test runs the shared connector suite (internal/connectors/conformance)
// against the real adapters and the fake service, for both operations. Neither
// has an entry in Known: every check passes.

// newRig builds a fake service and the real adapters against it. canary is the
// sending key: the fake accepts it, and the suite looks for it, and for every
// key the fake saw, in everything the adapters say.
func newRig(t testing.TB, canary string) *conformance.Rig {
	t.Helper()
	fake := resendtest.New(t)
	status := canary + "-status"
	seed(fake, canary, status)
	reg := redact.NewRegistry()
	client, err := NewClient(ClientConfig{
		SendKey:   func(context.Context) (string, error) { return canary, nil },
		StatusKey: func(context.Context) (string, error) { return status, nil },
		Registry:  reg,
		HTTP:      fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pol := func(project string) *policy.Resend {
		if project != testProject {
			return nil
		}
		return rigPolicy()
	}
	ads, err := Adapters(Config{Client: client, Policy: pol, Redactor: reg})
	if err != nil {
		t.Fatal(err)
	}
	return &conformance.Rig{
		Adapters:      ads,
		WriteCalls:    fake.WriteCalls,
		WritesApplied: fake.WritesApplied,
		// Only what the fake was sent: a rig that listed the canary itself would
		// hide an adapter that ignores it.
		Secrets: fake.Credentials,
		Hostile: func() { fake.Hostile("rotated-" + canary) },
		World:   fake,
	}
}

func sample(op, name, ref string, params map[string]any, code string, change func(*ops.Request)) conformance.Sample {
	return conformance.Sample{Name: name, Code: code, Req: func(*conformance.Rig) *ops.Request { return request(op, ref, params, change) }}
}

func asRun(q *ops.Request) {
	q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1", Project: testProject}
}
func asKey(q *ops.Request)        { q.Caller = &ops.Caller{Kind: ops.KindKey, Project: testProject} }
func otherAdapter(q *ops.Request) { q.Target.Adapter = "google" }
func otherProject(q *ops.Request) { q.Project = "other" }

// with returns the base message with some params changed; a nil value removes one.
func with(kv map[string]any) map[string]any {
	p := mailParams()
	p["cc"] = []any{"dev@team.example.com"}
	p["bcc"] = []any{"lead@team.example.com"}
	for k, v := range kv {
		if v == nil {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return p
}

func many(n int, domain string) []any { return addrs("u", n, domain) }

// addrs makes n distinct addresses on a domain.
func addrs(prefix string, n int, domain string) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = prefix + string(rune('a'+i)) + "@" + domain
	}
	return out
}

func TestConformance(t *testing.T) {
	send := func(name string, params map[string]any) conformance.Sample {
		return sample(OpSend, name, testSender, params, "", nil)
	}
	bad := func(name, code, ref string, params map[string]any, change func(*ops.Request)) conformance.Sample {
		return sample(OpSend, name, ref, params, code, change)
	}
	status := func(name, ref string) conformance.Sample {
		return sample(OpStatus, name, ref, nil, "", nil)
	}
	statusBad := func(name, code, ref string, params map[string]any, change func(*ops.Request)) conformance.Sample {
		return sample(OpStatus, name, ref, params, code, change)
	}
	conformance.Run(t, conformance.Connector{
		Declared: resendspec.Served,
		Pins:     pintable.Pins,
		NewRig:   newRig,
		Ops: map[string]conformance.Op{
			OpSend: {
				// The first valid sample is the base of the generated requests that
				// break each declared limit, so it carries every optional param.
				Valid: []conformance.Sample{
					send("to, cc and bcc", with(nil)),
					send("to only", mailParams()),
					send("a whole listed domain", with(map[string]any{"to": []any{"anyone@team.example.com"}, "cc": nil, "bcc": nil})),
				},
				Invalid: []conformance.Sample{
					bad("a run asks", ops.CodePolicyRefused, testSender, mailParams(), asRun),
					bad("a key asks", ops.CodePolicyRefused, testSender, mailParams(), asKey),
					bad("the Gmail target", ops.CodeParamsInvalid, testSender, mailParams(), otherAdapter),
					bad("a project with no resend block", ops.CodePolicyRefused, testSender, mailParams(), otherProject),
					bad("sender with a display name", ops.CodeParamsInvalid, "Alerts <alerts@mail.example.com>", mailParams(), nil),
					bad("sender in upper case", ops.CodeParamsInvalid, "Alerts@mail.example.com", mailParams(), nil),
					bad("sender not listed", ops.CodePolicyRefused, "billing@mail.example.com", mailParams(), nil),
					bad("recipient not listed", ops.CodePolicyRefused, testSender, with(map[string]any{"to": []any{"stranger@example.org"}}), nil),
					bad("cc not listed", ops.CodePolicyRefused, testSender, with(map[string]any{"cc": []any{"stranger@example.org"}}), nil),
					bad("bcc not listed", ops.CodePolicyRefused, testSender, with(map[string]any{"bcc": []any{"stranger@example.org"}}), nil),
					bad("a subdomain of a listed domain", ops.CodePolicyRefused, testSender, with(map[string]any{"to": []any{"x@mail.team.example.com"}}), nil),
					bad("over the project's cap", ops.CodePolicyRefused, testSender, with(map[string]any{"to": many(6, "team.example.com"), "cc": nil, "bcc": nil}), nil),
					bad("an attachment", ops.CodeParamsInvalid, testSender, with(map[string]any{"attachments": []any{map[string]any{"name": "a.txt", "sha256": strings.Repeat("a", 64)}}}), nil),
					bad("html", ops.CodeParamsInvalid, testSender, with(map[string]any{"html": "<p>hi</p>"}), nil),
					bad("reply_to", ops.CodeParamsInvalid, testSender, with(map[string]any{"reply_to": []any{"ops@example.com"}}), nil),
					bad("scheduled_at", ops.CodeParamsInvalid, testSender, with(map[string]any{"scheduled_at": "in 1 hour"}), nil),
					bad("headers", ops.CodeParamsInvalid, testSender, with(map[string]any{"headers": map[string]any{"X-A": "b"}}), nil),
					bad("tags", ops.CodeParamsInvalid, testSender, with(map[string]any{"tags": []any{}}), nil),
					bad("a template", ops.CodeParamsInvalid, testSender, with(map[string]any{"template": map[string]any{"id": "t"}}), nil),
					bad("a recipient with a display name", ops.CodeParamsInvalid, testSender, with(map[string]any{"to": []any{"Ops <ops@example.com>"}}), nil),
					bad("a recipient in upper case", ops.CodeParamsInvalid, testSender, with(map[string]any{"to": []any{"Ops@example.com"}}), nil),
					bad("the same recipient twice", ops.CodeParamsInvalid, testSender, with(map[string]any{"cc": []any{"ops@example.com"}}), nil),
					bad("a subject that starts with a space", ops.CodeParamsInvalid, testSender, with(map[string]any{"subject": " Hello"}), nil),
					bad("a subject with a newline", ops.CodeParamsInvalid, testSender, with(map[string]any{"subject": "Hello\nBcc: x@example.org"}), nil),
					bad("a body with a bidi override", ops.CodeParamsInvalid, testSender, with(map[string]any{"body": "gnp\u202e.exe"}), nil),
					bad("a body shaped like a secret", ops.CodeRedactionBlocked, testSender, with(map[string]any{"body": "token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}), nil),
					bad("a subject shaped like a secret", ops.CodeRedactionBlocked, testSender, with(map[string]any{"subject": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}), nil),
				},
				Text: conformance.ServiceText,
				// Resend's text that the result can carry is the id it answers with.
				Plant: func(r *conformance.Rig, p conformance.Planted) {
					id := strings.TrimSpace(p.Control + " " + p.Long + " " + p.Secret)
					r.World.(*resendtest.Server).NextID(id)
				},
			},
			OpStatus: {
				Valid: []conformance.Sample{status("a known email", statusEmail)},
				Invalid: []conformance.Sample{
					statusBad("a run asks", ops.CodePolicyRefused, statusEmail, nil, asRun),
					statusBad("a key asks", ops.CodePolicyRefused, statusEmail, nil, asKey),
					statusBad("the Gmail target", ops.CodeParamsInvalid, statusEmail, nil, otherAdapter),
					statusBad("a project with no resend block", ops.CodePolicyRefused, statusEmail, nil, otherProject),
					statusBad("not a uuid", ops.CodeParamsInvalid, "not-an-id", nil, nil),
					statusBad("a uuid in upper case", ops.CodeParamsInvalid, strings.ToUpper(statusEmail), nil, nil),
					statusBad("a path in the id", ops.CodeParamsInvalid, statusEmail+"/../api-keys", nil, nil),
					statusBad("a param", ops.CodeParamsInvalid, statusEmail, map[string]any{"full": true}, nil),
				},
				ReadOnly: true,
				Text:     conformance.NoServiceText,
				// The operation returns no text of Resend's: the planted text goes into
				// every field of the email, and none of it may reach the result.
				Plant: func(r *conformance.Rig, p conformance.Planted) {
					r.World.(*resendtest.Server).EditEmail(statusEmail, func(e *resendtest.Email) {
						e.LastEvent = p.Control
						e.Subject = p.Long
						e.Text = strings.TrimSpace(p.Long + " " + p.Secret)
						e.HTML = p.Control
						e.Extra = map[string]any{"tags": []any{map[string]any{"name": "x", "value": p.Control}}}
					})
				},
			},
		},
	})
}
