package sentry

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/conformance"
	"github.com/joshua-noel/chaperone/internal/connectors/pintable"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentrytest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// This test runs the shared connector suite (internal/connectors/conformance)
// against the real adapters and the fake Sentry (sentrytest). See
// docs/write-a-connector.md.

const testProject = "demo"

// The issues the rig seeds. 1001 is unresolved and has an event; 1002 is
// resolved; 1003 is ignored; 1004 is in a Sentry project the policy does not
// list; 1005 has no event.
const (
	issUnresolved = "1001"
	issResolved   = "1002"
	issIgnored    = "1003"
	issOtherProj  = "1004"
	issNoEvent    = "1005"
)

// seed puts the issues of the rig in the fake.
func seed(fake *sentrytest.Server) {
	ev := &sentrytest.Event{
		ID: "0123456789abcdef0123456789abcdef", Date: "2026-11-20T09:30:00Z", Sensitive: Sensitive,
		Exceptions: []sentrytest.Exception{
			{Type: "ConnectionError", Value: "cause", Frames: []sentrytest.Frame{{Filename: "net/pool.py", Function: "dial", Line: 40}}},
			{Type: "ValueError", Value: "bad total", Frames: []sentrytest.Frame{
				{Filename: "app/main.py", AbsPath: "/home/dev/app/main.py", Function: "run", Line: 9, InApp: true},
				{Filename: "app/cart.py", AbsPath: "/home/dev/app/cart.py", Function: "total", Line: 120, InApp: true},
			}},
		},
	}
	fake.AddIssue(sentrytest.Issue{ID: issUnresolved, ShortID: "WEB-1A", Title: "ValueError: bad total", Culprit: "app.cart in total", Project: "web", Event: ev})
	fake.AddIssue(sentrytest.Issue{ID: issResolved, ShortID: "WEB-1B", Title: "A fixed error", Culprit: "app.old", Project: "web", Status: "resolved", Event: ev})
	fake.AddIssue(sentrytest.Issue{ID: issIgnored, ShortID: "WEB-1C", Title: "An archived error", Project: "web", Status: "ignored", Event: ev})
	fake.AddIssue(sentrytest.Issue{ID: issOtherProj, ShortID: "BILLING-1", Title: "Not for the orchestrator", Project: "billing", Event: ev})
	fake.AddIssue(sentrytest.Issue{ID: issNoEvent, ShortID: "WEB-1D", Title: "No event kept", Project: "web"})
}

// Sensitive is what the fake plants in every part of an event that chapd must
// never return.
const Sensitive = "sensitive-4f9c2d71b3a8e605"

// rigPolicy is the policy of the rig: project "demo" has a sentry block that
// lists the Sentry projects web and api, and two members.
func rigPolicy(baseURL string) PolicyFunc {
	return func(project string) *policy.Sentry {
		switch project {
		case testProject:
			return &policy.Sentry{BaseURL: baseURL, Organization: "acme", Projects: []string{"web", "api"}, Assignees: []string{"dev@example.com", "ops@example.com"}}
		case "broken":
			return &policy.Sentry{Invalid: context.DeadlineExceeded}
		}
		return nil
	}
}

// newRig builds a fake Sentry and the real adapters against it. canary is the
// credential: the fake accepts it, and the suite looks for it, and for every
// credential the fake saw, in everything the adapters say.
func newRig(t testing.TB, canary string) *conformance.Rig {
	t.Helper()
	fake := sentrytest.New(t)
	fake.SetToken(canary)
	seed(fake)
	reg := redact.NewRegistry()
	client, err := NewClient(ClientConfig{
		Credential: func(context.Context) (string, error) { return canary, nil },
		Registry:   reg,
		HTTP:       fake.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ads, err := Adapters(Config{Client: client, Policy: rigPolicy(sentrytest.BaseURL), Redactor: reg})
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

func orchestrator() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{testProject}}
}

// request builds a request as chapd hands it to an adapter. change adjusts it.
func request(op, ref string, params map[string]any, change func(*ops.Request)) func(*conformance.Rig) *ops.Request {
	return func(*conformance.Rig) *ops.Request {
		q := &ops.Request{
			ID: "q-abc123", Op: op, Project: testProject,
			Target: spec.Target{Adapter: sentryspec.Adapter, Ref: ref},
			Params: params, Caller: orchestrator(),
		}
		if change != nil {
			change(q)
		}
		return q
	}
}

func valid(name, op, ref string, params map[string]any) conformance.Sample {
	return conformance.Sample{Name: name, Req: request(op, ref, params, nil)}
}

func refused(name, code, op, ref string, params map[string]any, change func(*ops.Request)) conformance.Sample {
	return conformance.Sample{Name: name, Code: code, Req: request(op, ref, params, change)}
}

func asRun(q *ops.Request) {
	q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1", Project: testProject}
}
func asKey(q *ops.Request) {
	q.Caller = &ops.Caller{Kind: ops.KindKey, KeyID: "k-1", Project: testProject}
}
func otherAdapter(q *ops.Request) { q.Target.Adapter = "other" }
func noBlock(q *ops.Request)      { q.Project = "plain" }
func brokenBlock(q *ops.Request)  { q.Project = "broken" }

// common are the invalid samples every operation shares: who asks, which
// adapter, whose policy.
func common(op, ref string, params map[string]any) []conformance.Sample {
	return []conformance.Sample{
		refused("a run asks", ops.CodePolicyRefused, op, ref, params, asRun),
		refused("a key asks", ops.CodePolicyRefused, op, ref, params, asKey),
		refused("another adapter", ops.CodeParamsInvalid, op, ref, params, otherAdapter),
		refused("a project with no sentry block", ops.CodePolicyRefused, op, ref, params, noBlock),
		refused("a project whose sentry block is unusable", ops.CodePolicyRefused, op, ref, params, brokenBlock),
	}
}

// issueInvalid are the invalid samples of an operation that reads the issue in
// Check.
func issueInvalid(op string, params map[string]any) []conformance.Sample {
	return append(common(op, issUnresolved, params),
		refused("not an issue id", ops.CodeParamsInvalid, op, "WEB-1A", params, nil),
		refused("an issue of a project the policy does not list", ops.CodeScopePath, op, issOtherProj, params, nil),
		refused("an issue Sentry does not have", ops.CodeParamsInvalid, op, "99999", params, nil),
	)
}

// plantIssue puts the planted text where a read of the issue finds it: the
// title, the culprit and the exception.
func plantIssue(id string) func(r *conformance.Rig, p conformance.Planted) {
	return func(r *conformance.Rig, p conformance.Planted) {
		title := p.Control
		if title == "" {
			title = "Plain title"
		}
		r.World.(*sentrytest.Server).Edit(id, func(is *sentrytest.Issue) {
			is.Title = title
			is.Culprit = strings.TrimSpace(p.Long + " " + p.Secret)
			is.AssigneeName = title
			if is.Event != nil {
				ev := *is.Event
				ev.Exceptions = []sentrytest.Exception{{Type: title, Value: p.Secret, Frames: []sentrytest.Frame{
					{Filename: title, Function: strings.TrimSpace(p.Long + " " + p.Secret), Line: 3},
				}}}
				is.Event = &ev
			}
		})
	}
}

func TestConformance(t *testing.T) {
	note := "Looked at this: the retry loop is the cause (see the deploy of 14 Nov)."
	conformance.Run(t, conformance.Connector{
		Declared: sentryspec.Connector,
		Pins:     pintable.Pins,
		NewRig:   newRig,
		Ops: map[string]conformance.Op{
			OpList: {
				// The first valid sample is the base of the generated requests that
				// break each declared limit, so it carries every param.
				Valid: []conformance.Sample{
					valid("every filter", OpList, "web", map[string]any{"status": "unresolved", "level": "error", "limit": 5.0, "cursor": "0:0:0"}),
					valid("no filter", OpList, "web", nil),
					valid("resolved ones", OpList, "web", map[string]any{"status": "resolved"}),
				},
				Invalid: append(common(OpList, "web", nil),
					refused("a project the policy does not list", ops.CodeScopePath, OpList, "billing", nil, nil),
					refused("not a project slug", ops.CodeParamsInvalid, OpList, "Not A Slug", nil, nil),
				),
				ReadOnly: true,
				Text:     conformance.ServiceText,
				Plant:    plantIssue(issUnresolved),
			},
			OpGet: {
				Valid: []conformance.Sample{
					valid("an issue with an event", OpGet, issUnresolved, nil),
					valid("an issue with no event", OpGet, issNoEvent, nil),
				},
				Invalid: append(common(OpGet, issUnresolved, nil),
					refused("not an issue id", ops.CodeParamsInvalid, OpGet, "WEB-1A", nil, nil),
				),
				ReadOnly: true,
				Text:     conformance.ServiceText,
				Plant:    plantIssue(issUnresolved),
			},
			OpResolve: {
				Valid: []conformance.Sample{
					valid("an unresolved issue", OpResolve, issUnresolved, nil),
					valid("an issue that is resolved already", OpResolve, issResolved, nil),
				},
				Invalid: append(issueInvalid(OpResolve, nil),
					refused("an ignored issue", ops.CodePolicyRefused, OpResolve, issIgnored, nil, nil)),
				Text:  conformance.NoServiceText,
				Plant: plantIssue(issUnresolved),
			},
			OpUnresolve: {
				Valid: []conformance.Sample{
					valid("a resolved issue", OpUnresolve, issResolved, nil),
					valid("an issue that is unresolved already", OpUnresolve, issUnresolved, nil),
				},
				Invalid: append(issueInvalid(OpUnresolve, nil),
					refused("an ignored issue", ops.CodePolicyRefused, OpUnresolve, issIgnored, nil, nil)),
				Text:  conformance.NoServiceText,
				Plant: plantIssue(issResolved),
			},
			OpAssign: {
				Valid: []conformance.Sample{
					valid("a member of the list", OpAssign, issUnresolved, map[string]any{"to": "dev@example.com"}),
					valid("a member of the list, in other case", OpAssign, issUnresolved, map[string]any{"to": "OPS@example.com"}),
				},
				Invalid: append(issueInvalid(OpAssign, map[string]any{"to": "dev@example.com"}),
					refused("a member the policy does not list", ops.CodePolicyRefused, OpAssign, issUnresolved, map[string]any{"to": "stranger@example.com"}, nil),
					refused("a team", ops.CodeParamsInvalid, OpAssign, issUnresolved, map[string]any{"to": "team:12"}, nil),
					refused("a user id", ops.CodeParamsInvalid, OpAssign, issUnresolved, map[string]any{"to": "user:7"}, nil),
				),
				Text:  conformance.NoServiceText,
				Plant: plantIssue(issUnresolved),
			},
			OpComment: {
				Valid: []conformance.Sample{
					valid("a plain note", OpComment, issUnresolved, map[string]any{"body": note}),
				},
				Invalid: append(issueInvalid(OpComment, map[string]any{"body": note}),
					refused("a mention of a person", ops.CodePolicyRefused, OpComment, issUnresolved, map[string]any{"body": "please look, @alice"}, nil),
					refused("a mention of a team", ops.CodePolicyRefused, OpComment, issUnresolved, map[string]any{"body": "for #backend"}, nil),
					refused("a link", ops.CodePolicyRefused, OpComment, issUnresolved, map[string]any{"body": "see [the doc](https://example.org)"}, nil),
					refused("an invisible character", ops.CodeParamsInvalid, OpComment, issUnresolved, map[string]any{"body": "a\u200bb"}, nil),
					refused("a secret", ops.CodeRedactionBlocked, OpComment, issUnresolved, map[string]any{"body": "the key is " + conformance.NewPlanted().Secret}, nil),
				),
				// Sentry has no idempotency key for a note. A marker in the text would
				// change what is posted, and a look-up of "the same text, by the same
				// user, a moment ago" cannot tell a repeat from a second note that was
				// meant. chapd does not run an Execute twice for one execution id
				// (docs/connectors.md, rule 3), the way it does not for GitHub's comment.
				NotRepeatable: "Sentry has no idempotency key for a note, and a marker in the text would change what is posted",
				Text:          conformance.NoServiceText,
				Plant:         plantIssue(issUnresolved),
			},
		},
	})
}
