package policy

import "testing"

func TestProjectGoogleBlock(t *testing.T) {
	cat, base := mustDefault(t)
	good := `project: storefront
google:
  mail:
    allow_recipients: ["gilliano@example.com", "@acme.example"]
  drive:
    allow_recipients: ["gilliano@example.com"]
    max_role: commenter
`
	eff, err := base.LoadProject("storefront", []byte(good), cat)
	if err != nil {
		t.Fatal(err)
	}
	g := eff.Google
	if g == nil || len(g.Mail.AllowRecipients) != 2 || len(g.Drive.AllowRecipients) != 1 || g.Drive.MaxRole != "commenter" {
		t.Fatalf("google block not read: %+v", g)
	}
	// The block adds data only: the baseline still has both ops off.
	if eff.Enabled("mail.send") || eff.Enabled("drive.share") {
		t.Error("a google: block must not enable mail.send or drive.share")
	}
	none, err := base.LoadProject("storefront", []byte("project: storefront\n"), cat)
	if err != nil || none.Google != nil {
		t.Errorf("no google: block must stay nil: %+v, %v", none, err)
	}
	for name, body := range map[string]string{
		"enable mail":      "ops:\n  mail.send: { enabled: true }\n",
		"display name":     "google:\n  mail:\n    allow_recipients: [\"Bob <bob@example.com>\"]\n",
		"upper case":       "google:\n  mail:\n    allow_recipients: [\"Bob@example.com\"]\n",
		"wildcard":         "google:\n  mail:\n    allow_recipients: [\"*@example.com\"]\n",
		"bare tld":         "google:\n  mail:\n    allow_recipients: [\"@com\"]\n",
		"unicode":          "google:\n  drive:\n    allow_recipients: [\"b\u043eb@example.com\"]\n",
		"owner role":       "google:\n  drive:\n    max_role: owner\n",
		"unknown key":      "google:\n  mail:\n    allow_any: true\n",
		"role as sentence": "google:\n  drive:\n    max_role: \"writer \"\n",
	} {
		if _, err := base.LoadProject("storefront", []byte("project: storefront\n"+body), cat); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
}
