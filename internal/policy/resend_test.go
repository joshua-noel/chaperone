package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const resendBlock = `
resend:
  senders: [alerts@mail.example.com]
  allow_recipients: [ops@example.com, "@team.example.com"]
  max_recipients: 3
`

func TestResendBlockLoads(t *testing.T) {
	eff, err := linearProject(t, resendBlock)
	if err != nil {
		t.Fatal(err)
	}
	r := eff.Resend
	if r == nil || r.Invalid != nil || len(r.Senders) != 1 || len(r.AllowRecipients) != 2 || r.MaxRecipients != 3 {
		t.Fatalf("block: %+v", r)
	}
	if !r.SenderAllowed("alerts@mail.example.com") || r.SenderAllowed("Alerts@mail.example.com") || r.SenderAllowed("alerts@mail.example.com ") ||
		r.SenderAllowed("x@mail.example.com") || r.SenderAllowed("") {
		t.Error("SenderAllowed is not an exact match on a listed address")
	}
	for _, ok := range []string{"ops@example.com", "anyone@team.example.com", "a.b+c@team.example.com"} {
		if !r.RecipientAllowed(ok) {
			t.Errorf("%s is refused", ok)
		}
	}
	// An exact entry is that address; a domain entry is that whole domain and not a suffix of it.
	for _, no := range []string{
		"", "ops", "@", "@team.example.com", "x@example.com", "Ops@example.com", "ops@example.com.evil.org", "xops@example.com",
		"x@mail.team.example.com", "x@teamxexample.com", "x@eam.example.com", "x@team.example.com.evil.org", "x@@team.example.com",
	} {
		if r.RecipientAllowed(no) {
			t.Errorf("%q is allowed", no)
		}
	}
	// The block adds data and enables nothing.
	cat, base := mustDefault(t)
	plain, err := base.LoadProject("acme-shop", []byte("project: acme-shop\n"), cat)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"mail.send"} {
		if eff.Enabled(op) || eff.Enabled(op) != plain.Enabled(op) {
			t.Errorf("%s is enabled, or the resend block changed its enablement", op)
		}
	}
	// No block: nil, and the Resend side refuses the project.
	if eff, err := linearProject(t, ""); err != nil || eff.Resend != nil {
		t.Errorf("no resend block: %v %v", eff.Resend, err)
	}
	// The cap defaults when it is left out, and is the value in force.
	eff, err = linearProject(t, "resend:\n  senders: [alerts@mail.example.com]\n  allow_recipients: [ops@example.com]\n")
	if err != nil || eff.Resend.Invalid != nil || eff.Resend.MaxRecipients != ResendDefaultMaxRecipients {
		t.Errorf("default cap: %+v %v", eff.Resend, err)
	}
}

// A mistake in the block turns off the Resend side only: the block is marked
// invalid with a reason that names the project, the file and the field, and the
// rest of the project (Gmail's block included) works. A key the file format does
// not know still refuses the whole file.
func TestResendBlockMistakesTurnOffTheResendSideOnly(t *testing.T) {
	good := map[string]string{
		"senders": "[alerts@mail.example.com]", "allow_recipients": "[ops@example.com]", "max_recipients": "3",
	}
	with := func(key, val string) string {
		var b strings.Builder
		b.WriteString("\nresend:\n")
		for _, k := range []string{"senders", "allow_recipients", "max_recipients"} {
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
	manySenders := "[" + strings.TrimSuffix(strings.Repeat("a@mail.example.com,", ResendMaxSenders+1), ",") + "]"
	var allow []string
	for i := range ResendMaxAllow + 1 {
		allow = append(allow, fmt.Sprintf("u%d@example.com", i))
	}
	for name, c := range map[string]struct{ block, want string }{
		"no senders":                   {with("senders", ""), "senders"},
		"empty senders":                {with("senders", "[]"), "senders"},
		"a sender with a display name": {with("senders", "[\"Alerts <alerts@mail.example.com>\"]"), "senders entry"},
		"an upper-case sender":         {with("senders", "[Alerts@mail.example.com]"), "senders entry"},
		"a wildcard sender":            {with("senders", "[\"*@mail.example.com\"]"), "senders entry"},
		"a domain as a sender":         {with("senders", "[\"@mail.example.com\"]"), "senders entry"},
		"a repeated sender":            {with("senders", "[alerts@mail.example.com, alerts@mail.example.com]"), "twice"},
		"too many senders":             {with("senders", manySenders), "at most"},
		"no recipients":                {with("allow_recipients", ""), "allow_recipients"},
		"empty recipients":             {with("allow_recipients", "[]"), "allow_recipients"},
		"a star":                       {with("allow_recipients", "[\"*\"]"), "allow_recipients"},
		"a star domain":                {with("allow_recipients", "[\"@*\"]"), "allow_recipients"},
		"a star subdomain":             {with("allow_recipients", "[\"@*.example.com\"]"), "allow_recipients"},
		"a star address":               {with("allow_recipients", "[\"*@example.com\"]"), "allow_recipients"},
		"a bare domain":                {with("allow_recipients", "[example.com]"), "allow_recipients"},
		"a top-level domain":           {with("allow_recipients", "[\"@com\"]"), "allow_recipients"},
		"a dot":                        {with("allow_recipients", "[\"@.\"]"), "allow_recipients"},
		"empty entry":                  {with("allow_recipients", "[\"\"]"), "allow_recipients"},
		"an upper-case entry":          {with("allow_recipients", "[Ops@example.com]"), "allow_recipients"},
		"a repeated entry":             {with("allow_recipients", "[ops@example.com, ops@example.com]"), "twice"},
		"too many entries":             {with("allow_recipients", "["+strings.Join(allow, ",")+"]"), "at most"},
		"a cap of zero":                {with("max_recipients", "0"), "max_recipients"},
		"a negative cap":               {with("max_recipients", "-1"), "max_recipients"},
		"a cap over the ceiling":       {with("max_recipients", fmt.Sprint(ResendMaxRecipientsCeiling+1)), "max_recipients"},
	} {
		eff, err := linearProject(t, c.block+"google:\n  mail:\n    allow_recipients: [ops@example.com]\n")
		if err != nil {
			t.Errorf("%s: the whole project was refused: %v", name, err)
			continue
		}
		r := eff.Resend
		if r == nil || r.Invalid == nil || !strings.Contains(r.Invalid.Error(), c.want) {
			t.Errorf("%s: the block is not off with a reason holding %q: %+v", name, c.want, r)
			continue
		}
		msg := r.Invalid.Error()
		if !strings.Contains(msg, eff.Project+".yaml") || !strings.Contains(msg, "project "+eff.Project) || !strings.Contains(msg, "mail.send") || !strings.Contains(msg, "Gmail is not affected") {
			t.Errorf("%s: the reason does not name the project, the file and the ops: %s", name, msg)
		}
		// A block that cannot be used is never half usable.
		if len(r.Senders) != 0 || len(r.AllowRecipients) != 0 || r.MaxRecipients != 0 {
			t.Errorf("%s: an invalid block keeps its fields: %+v", name, r)
		}
		if eff.Invalid != nil {
			t.Errorf("%s: the project is invalid: %v", name, eff.Invalid)
		}
		// Mail through Gmail is the block of its own and works.
		if eff.Google == nil || len(eff.Google.Mail.AllowRecipients) != 1 {
			t.Errorf("%s: the google block was lost: %+v", name, eff.Google)
		}
	}
	// A key the file format does not know is a mistake in the file, not in the block.
	for _, block := range []string{
		resendBlock + "  base_url: https://api.resend.com\n",
		resendBlock + "  api_key: re_abc\n",
		resendBlock + "  html: true\n",
		resendBlock + "  attachments: true\n",
	} {
		if _, err := linearProject(t, block); err == nil {
			t.Errorf("an unknown key in the resend block was accepted: %q", block)
		}
	}
}

// The engine reports an unusable resend block once, by name, and the other blocks
// and ops of the project keep working.
func TestEngineProblemsNamesAnUnusableResendBlock(t *testing.T) {
	cat, base := mustDefault(t)
	dir := t.TempDir()
	file := "project: storefront\nresend:\n  senders: [Alerts@mail.example.com]\n  allow_recipients: [ops@example.com]\n"
	if err := os.WriteFile(filepath.Join(dir, "storefront.yaml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(cat, base, dir)
	probs := e.Problems()
	if len(probs) != 1 || probs[0].Block != "resend" || probs[0].Project != "storefront" || !strings.Contains(probs[0].Err.Error(), "senders") {
		t.Fatalf("problems: %+v", probs)
	}
	if eff := e.For("storefront"); eff.Invalid != nil || eff.Resend == nil || eff.Resend.Invalid == nil {
		t.Errorf("the project is invalid as a whole, or the block is not marked: %+v", eff)
	}
}

// An `@domain` entry for a large public mailbox domain, or for a subdomain of one, is
// refused when the block is loaded, with a message that says an exact address is
// needed. An exact address at the same domain, and a domain of one's own, are fine.
// This is the Resend block only: the Gmail block's rule is not changed.
func TestResendRefusesAWholePublicMailboxDomain(t *testing.T) {
	want := []string{
		"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
		"me.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "yandex.com", "mail.com",
		"yahoo.co.uk", "yahoo.co.jp", "yahoo.fr", "yahoo.de", "ymail.com", "rocketmail.com", "msn.com",
		"live.co.uk", "hotmail.co.uk", "hotmail.fr", "outlook.fr", "outlook.de", "gmx.de", "gmx.net", "web.de",
		"mail.ru", "yandex.ru", "qq.com", "163.com", "126.com", "pm.me", "zoho.com", "fastmail.com", "hey.com",
		"duck.com", "tutanota.com", "tuta.io",
	}
	if strings.Join(ResendMailboxDomains, ",") != strings.Join(want, ",") {
		t.Fatalf("the built-in list is %v", ResendMailboxDomains)
	}
	for _, d := range want {
		for _, entry := range []string{"@" + d, "@mail." + d, "@a.b." + d} { // the domain and any subdomain of it
			eff, err := linearProject(t, "resend:\n  senders: [alerts@mail.example.com]\n  allow_recipients: [\""+entry+"\"]\n")
			if err != nil {
				t.Errorf("%s: the whole project was refused: %v", entry, err)
				continue
			}
			r := eff.Resend
			if r == nil || r.Invalid == nil || !strings.Contains(r.Invalid.Error(), entry) || !strings.Contains(r.Invalid.Error(), "exact address") {
				t.Errorf("%s: not refused with a clear reason: %+v", entry, r)
			}
		}
		// An exact address there is fine.
		eff, err := linearProject(t, "resend:\n  senders: [alerts@mail.example.com]\n  allow_recipients: [\"me@"+d+"\"]\n")
		if err != nil || eff.Resend == nil || eff.Resend.Invalid != nil || !eff.Resend.RecipientAllowed("me@"+d) || eff.Resend.RecipientAllowed("you@"+d) {
			t.Errorf("an exact address at %s: %+v %v", d, eff.Resend, err)
		}
	}
	// A domain of one's own, and one that only ends in a listed name, is not on the list.
	eff, err := linearProject(t, "resend:\n  senders: [alerts@mail.example.com]\n  allow_recipients: [\"@team.example.com\", \"@notgmail.com\", \"@gmail.com.example.org\"]\n")
	if err != nil || eff.Resend.Invalid != nil {
		t.Errorf("%+v %v", eff.Resend, err)
	}
	// Gmail's block is untouched.
	if eff, err := linearProject(t, "google:\n  mail:\n    allow_recipients: [\"@gmail.com\"]\n"); err != nil || eff.Google == nil {
		t.Errorf("the Google block changed: %v", err)
	}
}
