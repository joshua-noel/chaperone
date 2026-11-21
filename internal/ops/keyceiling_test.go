package ops

import "testing"

// The profile and the docs of the Linear issue ops say they are for the
// orchestrator token only. This is the code they describe: a custom key can
// never hold an issue.* op, and none of them is in the key ceiling.
func TestNoIssueOpCanBeInACustomKey(t *testing.T) {
	for _, op := range []string{"issue.get", "issue.list", "issue.comment", "issue.label", "issue.move", "issue.link", "issue.open", "issue.reopen"} {
		if !NeverInKey(op) {
			t.Errorf("%s can be in a key", op)
		}
		if _, ok := KeyUnitKind(op); ok {
			t.Errorf("%s is in the key ceiling", op)
		}
	}
}

// The Sentry ops are for the orchestrator token only: a custom key can never
// hold an errors.* op, and none of them is in the key ceiling.
func TestNoErrorsOpCanBeInACustomKey(t *testing.T) {
	for _, op := range []string{"errors.list", "errors.get", "errors.resolve", "errors.unresolve", "errors.assign", "errors.comment"} {
		if !NeverInKey(op) {
			t.Errorf("%s can be in a key", op)
		}
		if _, ok := KeyUnitKind(op); ok {
			t.Errorf("%s is in the key ceiling", op)
		}
	}
}

// mail.status (the Resend connector's read of a delivery status) is for the
// orchestrator token only: a custom key can never hold it, and it is not in the
// key ceiling. mail.send is in no key either, but for another reason: it is not in
// the ceiling, and an op missing from the ceiling fails closed for a key.
func TestNoMailOpCanBeInACustomKey(t *testing.T) {
	if !NeverInKey("mail.status") {
		t.Error("mail.status can be in a key")
	}
	for _, op := range []string{"mail.status", "mail.send"} {
		if _, ok := KeyUnitKind(op); ok {
			t.Errorf("%s is in the key ceiling", op)
		}
	}
}
