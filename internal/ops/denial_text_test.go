package ops

import (
	"testing"

	"github.com/joshua-noel/chaperone/internal/denialtext"
)

// Every cause code this package emits (denial.go) has plain words in the table chap and the console read, so a denial
// never shows a bare code with no sentence. (internal/denialtext loops over the schema enum for the other direction.)
func TestEveryEmittedCodeHasPlainWords(t *testing.T) {
	for _, c := range []string{
		CodeOpNotInToken, CodeOpDisabled, CodeApprovalRequired, CodeApprovalDenied, CodeApprovalExpired, CodePolicyRefused,
		CodeParamsInvalid, CodeHashMismatch, CodeApprovalConsumed, CodeApprovalIntegrty, CodeApprovalUnavail,
		CodeDisplayMismatch, CodeTokenExpired, CodeTokenInvalid, CodeTokenRevoked, CodeScopeBranch, CodeScopePath,
		CodeRedactionBlocked,
	} {
		if denialtext.Plain(c) == "" {
			t.Errorf("no plain words for %s", c)
		}
	}
}
