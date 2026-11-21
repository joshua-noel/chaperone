package main

import (
	"strings"
	"testing"
)

// The `chap errors` commands are generated from the declaration of the Sentry
// connector. Each sends the request its declaration describes, and a value that
// breaks the declared shape is a usage error before anything is sent.
func TestErrorsCommandsSendTheDeclaredRequest(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"list with every filter": {
			[]string{"errors", "list", "web", "--status", "resolved", "--level", "fatal", "--limit", "5", "--cursor", "0:5:0"},
			`{"op":"errors.list","params":{"cursor":"0:5:0","level":"fatal","limit":5,"status":"resolved"},"project":"storefront","target":{"adapter":"sentry","ref":"web"}}`,
		},
		"list with none": {
			[]string{"errors", "list", "web"},
			`{"op":"errors.list","params":{},"project":"storefront","target":{"adapter":"sentry","ref":"web"}}`,
		},
		"get":       {[]string{"errors", "get", "4501234567"}, `{"op":"errors.get","params":{},"project":"storefront","target":{"adapter":"sentry","ref":"4501234567"}}`},
		"resolve":   {[]string{"errors", "resolve", "12"}, `{"op":"errors.resolve","params":{},"project":"storefront","target":{"adapter":"sentry","ref":"12"}}`},
		"unresolve": {[]string{"errors", "unresolve", "12"}, `{"op":"errors.unresolve","params":{},"project":"storefront","target":{"adapter":"sentry","ref":"12"}}`},
		"assign": {
			[]string{"errors", "assign", "12", "--to", "dev@example.com"},
			`{"op":"errors.assign","params":{"to":"dev@example.com"},"project":"storefront","target":{"adapter":"sentry","ref":"12"}}`,
		},
		"comment": {
			[]string{"errors", "comment", "12", "--body", "Looked at this."},
			`{"op":"errors.comment","params":{"body":"Looked at this."},"project":"storefront","target":{"adapter":"sentry","ref":"12"}}`,
		},
	} {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch"})
		if code := ta.run(append(c.args, "--project", "storefront")); code != 0 {
			t.Errorf("%s: exit %d: %s", name, code, ta.errb)
			continue
		}
		if len(chapd.reqs) != 1 || !strings.HasSuffix(chapd.reqs[0], "\n"+c.want) {
			t.Errorf("%s: requests = %q, want a body %s", name, chapd.reqs, c.want)
		}
	}
}

func TestErrorsCommandsRefuseABadValueBeforeTheyAsk(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a short id":           {[]string{"errors", "get", "WEB-1A"}, "the issue must be the numeric id"},
		"a project in caps":    {[]string{"errors", "list", "Web"}, "the Sentry project must be a project slug"},
		"a limit too high":     {[]string{"errors", "list", "web", "--limit", "26"}, "--limit must be 1 to 25"},
		"a made-up status":     {[]string{"errors", "list", "web", "--status", "open"}, "--status must be unresolved, resolved or ignored"},
		"a made-up level":      {[]string{"errors", "list", "web", "--level", "loud"}, "--level must be fatal, error, warning, info or debug"},
		"a cursor of anything": {[]string{"errors", "list", "web", "--cursor", "abc"}, "--cursor must be the next_cursor"},
		"a team as assignee":   {[]string{"errors", "assign", "12", "--to", "team:1"}, "--to must be an email address or a username"},
		"no assignee":          {[]string{"errors", "assign", "12"}, "--to must be an email address or a username"},
		"no note":              {[]string{"errors", "comment", "12"}, "--body or --body-file is required"},
	} {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch"})
		code := ta.run(append(c.args, "--project", "storefront"))
		if code != exitUsage || len(chapd.reqs) != 0 || !strings.Contains(ta.errb.String(), c.want) {
			t.Errorf("%s: exit %d, requests %q, stderr %q", name, code, chapd.reqs, ta.errb)
		}
	}
}
