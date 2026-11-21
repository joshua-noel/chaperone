package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sentryBlock = `
sentry:
  base_url: https://sentry.example.com
  organization: acme
  projects: [web, api]
  assignees: [dev@example.com, ops]
`

func TestSentryBlockLoads(t *testing.T) {
	eff, err := linearProject(t, sentryBlock)
	if err != nil {
		t.Fatal(err)
	}
	s := eff.Sentry
	if s == nil || s.Invalid != nil || s.BaseURL != "https://sentry.example.com" || s.Organization != "acme" || len(s.Projects) != 2 || len(s.Assignees) != 2 {
		t.Fatalf("block: %+v", s)
	}
	if !s.ProjectAllowed("web") || s.ProjectAllowed("WEB") || s.ProjectAllowed("webs") || s.ProjectAllowed("") {
		t.Error("ProjectAllowed is not an exact match on a listed slug")
	}
	if m, ok := s.AssigneeAllowed("DEV@example.COM"); !ok || m != "dev@example.com" {
		t.Errorf("AssigneeAllowed = %q %v", m, ok)
	}
	if _, ok := s.AssigneeAllowed("someone@example.com"); ok {
		t.Error("an unlisted member is allowed")
	}
	// The block adds data and enables nothing.
	cat, base := mustDefault(t)
	plain, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"errors.list", "errors.get", "errors.resolve", "errors.unresolve", "errors.assign", "errors.comment"} {
		if eff.Enabled(op) || eff.Enabled(op) != plain.Enabled(op) {
			t.Errorf("%s is enabled, or the sentry block changed its enablement", op)
		}
	}
	// No block: nil, and the ops refuse the project.
	if eff, err := linearProject(t, ""); err != nil || eff.Sentry != nil {
		t.Errorf("no sentry block: %v %v", eff.Sentry, err)
	}
	// A block with no assignees is fine: errors.assign then refuses every request.
	eff, err = linearProject(t, "sentry:\n  base_url: https://sentry.io\n  organization: acme\n  projects: [web]\n")
	if err != nil || eff.Sentry.Invalid != nil || len(eff.Sentry.Assignees) != 0 {
		t.Errorf("no assignees: %+v %v", eff.Sentry, err)
	}
}

// A mistake in the block turns off the Sentry operations only: the block is
// marked invalid with a reason that names the project, the file and the field,
// and the rest of the project works. A key the file format does not know still
// refuses the whole file.
func TestSentryBlockMistakesTurnOffTheSentryOpsOnly(t *testing.T) {
	good := map[string]string{"base_url": "https://sentry.example.com", "organization": "acme", "projects": "[web]", "assignees": "[dev@example.com]"}
	with := func(key, val string) string {
		var b strings.Builder
		b.WriteString("\nsentry:\n")
		for _, k := range []string{"base_url", "organization", "projects", "assignees"} {
			v := good[k]
			if k == key {
				v = val
			}
			if v != "" {
				b.WriteString("  " + k + ": " + v + "\n")
			}
		}
		return b.String()
	}
	long := strings.Repeat("a", SentryMaxSlug+1)
	many := "[" + strings.TrimSuffix(strings.Repeat("p,", SentryMaxProjects+1), ",") + "]"
	manyMembers := "[" + strings.TrimSuffix(strings.Repeat("m,", SentryMaxAssignees+1), ",") + "]"
	for name, c := range map[string]struct{ block, want string }{
		"plain http":                {with("base_url", "http://sentry.example.com"), "base_url"},
		"no base url":               {with("base_url", ""), "base_url"},
		"a path":                    {with("base_url", "https://sentry.example.com/sentry"), "base_url"},
		"a trailing slash":          {with("base_url", "https://sentry.example.com/"), "base_url"},
		"a user name":               {with("base_url", "https://u:p@sentry.example.com"), "base_url"},
		"an IP address":             {with("base_url", "https://192.0.2.5"), "base_url"},
		"localhost":                 {with("base_url", "https://localhost"), "base_url"},
		"upper case host":           {with("base_url", "https://Sentry.Example.com"), "base_url"},
		"a query":                   {with("base_url", "https://sentry.example.com?x=1"), "base_url"},
		"a port too high":           {with("base_url", "https://sentry.example.com:99999"), "port"},
		"no organization":           {with("organization", ""), "organization"},
		"upper-case organization":   {with("organization", "Acme"), "organization"},
		"organization with a slash": {with("organization", "a/b"), "organization"},
		"organization too long":     {with("organization", long), "organization"},
		"no projects":               {with("projects", ""), "projects"},
		"empty projects":            {with("projects", "[]"), "projects"},
		"a project with a slash":    {with("projects", "[web/x]"), "projects entry"},
		"an upper-case project":     {with("projects", "[Web]"), "projects entry"},
		"a repeated project":        {with("projects", "[web, web]"), "twice"},
		"too many projects":         {with("projects", many), "at most"},
		"an assignee as a team":     {with("assignees", "[\"team:12\"]"), "assignees entry"},
		"an assignee as a user id":  {with("assignees", "[\"user:7\"]"), "assignees entry"},
		"an assignee with a space":  {with("assignees", "[\"a b\"]"), "assignees entry"},
		"a repeated assignee":       {with("assignees", "[dev@example.com, DEV@example.com]"), "twice"},
		"too many assignees":        {with("assignees", manyMembers), "at most"},
	} {
		eff, err := linearProject(t, c.block)
		if err != nil {
			t.Errorf("%s: the whole project was refused: %v", name, err)
			continue
		}
		s := eff.Sentry
		if s == nil || s.Invalid == nil || !strings.Contains(s.Invalid.Error(), c.want) {
			t.Errorf("%s: the block is not off with a reason holding %q: %+v", name, c.want, s)
			continue
		}
		if msg := s.Invalid.Error(); !strings.Contains(msg, eff.Project+".yaml") || !strings.Contains(msg, "project "+eff.Project) || !strings.Contains(msg, "errors.resolve") {
			t.Errorf("%s: the reason does not name the project, the file and the ops: %s", name, msg)
		}
		// A block that cannot be used is never half usable.
		if s.BaseURL != "" || s.Organization != "" || len(s.Projects) != 0 || len(s.Assignees) != 0 {
			t.Errorf("%s: an invalid block keeps its fields: %+v", name, s)
		}
		if eff.Invalid != nil {
			t.Errorf("%s: the project is invalid: %v", name, eff.Invalid)
		}
	}
	// A key the file format does not know is a mistake in the file, not in the block.
	for _, block := range []string{
		"\nsentry:\n  base_url: https://sentry.io\n  organization: acme\n  projects: [web]\n  enabled: true\n",
		"\nsentry:\n  base_url: https://sentry.io\n  organization: acme\n  projects: [web]\n  token: abc\n",
	} {
		if _, err := linearProject(t, block); err == nil {
			t.Errorf("an unknown key in the sentry block was accepted: %q", block)
		}
	}
}

func TestCheckSentryBaseURL(t *testing.T) {
	for _, ok := range []string{
		"https://sentry.io", "https://de.sentry.io", "https://us.sentry.io", "https://sentry.example.com",
		"https://sentry.corp.example.com:8443", "https://sentry-1.example.org",
	} {
		if err := CheckSentryBaseURL(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "sentry.io", "http://sentry.io", "https://", "https://sentry", "https://sentry.io/", "https://sentry.io/api",
		"https://sentry.io:", "https://sentry.io:0", "https://sentry.io:65536", "https://-a.example.com", "https://a-.example.com",
		"https://a..example.com", "https://sentry.io.", "https://sentry.io\n", "https://sentry.io@evil.example.com",
		"https://evil.example.com@sentry.io", "https://[::1]", "https://127.0.0.1", "https://10.1.2.3:8443", "https://0x7f.1",
		"https://sentry.123", "https://sen try.io", "https://sentry.io:8443:9", "HTTPS://sentry.io", "https://sentry.io?a=b",
		"https://sentry.io#a", "https://\u0441entry.io", "https://" + strings.Repeat("a", 64) + ".io",
	} {
		if err := CheckSentryBaseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The engine reports an unusable sentry block once, by name, and the other
// blocks and ops of the project keep working.
func TestEngineProblemsNamesAnUnusableSentryBlock(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	file := "project: storefront\nsentry:\n  base_url: http://sentry.example.com\n  organization: acme\n  projects: [web]\n"
	if err := os.WriteFile(filepath.Join(dir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(cat, base, dir)
	probs := e.Problems()
	if len(probs) != 1 || probs[0].Block != "sentry" || probs[0].Project != "storefront" || !strings.Contains(probs[0].Err.Error(), "base_url") {
		t.Fatalf("problems: %+v", probs)
	}
	if eff := e.For("storefront"); eff.Invalid != nil || eff.Sentry == nil || eff.Sentry.Invalid == nil {
		t.Errorf("the project is invalid as a whole, or the block is not marked: %+v", eff)
	}
}
