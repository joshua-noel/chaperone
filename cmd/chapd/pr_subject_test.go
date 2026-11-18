package main

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// ops writes the evidence block that names a pull request and approvals reads the title from it. The two packages do
// not import each other, so the words are written twice; this keeps them one: if either side changes alone, the title
// would silently drop off the card's headline (and the merge would lose its approved title).
func TestPRSubjectEvidenceWordsAgree(t *testing.T) {
	if ops.PRSubjectEvidence != approvals.EvidencePR {
		t.Errorf("evidence block title: ops %q, approvals %q", ops.PRSubjectEvidence, approvals.EvidencePR)
	}
	if ops.PRTitlePrefix != approvals.EvidenceTitlePrefix {
		t.Errorf("title line prefix: ops %q, approvals %q", ops.PRTitlePrefix, approvals.EvidenceTitlePrefix)
	}
}

// The bridge hands the card's stored evidence to ops (ApprovalInfo.Evidence), which gives it to the adapter at release:
// the approved title the merge is bound to.
func TestInfoOfCarriesTheCardEvidence(t *testing.T) {
	a := &approvals.Approval{Evidence: []approvals.Evidence{{Title: approvals.EvidencePR, Body: approvals.EvidenceTitlePrefix + "feat: x\nAuthor: octo"}}}
	got := infoOf(a).Evidence
	if len(got) != 1 || got[0].Name != ops.PRSubjectEvidence || !strings.HasPrefix(got[0].Text, ops.PRTitlePrefix+"feat: x") {
		t.Fatalf("evidence = %+v", got)
	}
}
