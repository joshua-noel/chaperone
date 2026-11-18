package denialtext

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNextStepPerCause(t *testing.T) {
	for _, c := range []struct {
		name, cause, why, orch string
		want                   string // a fragment of the step; "" means no step
	}{
		{"stale branch", PolicyRefused, "CI_STALE: base_current: head is 1 commit(s) behind main", "main", "chap pr update"},
		{"edited title at the release check: ask again, not update the branch", PolicyRefused, "CI_STALE: title_approved: the pull request title is not the one the approver saw on the card; ask again for a new approval", "main", "ask again so a new card shows the title"},
		{"edited title just before the write", PolicyRefused, "CI_STALE: recheck_title: the pull request title is not the one the approver saw on the card; ask again for a new approval", "", "ask again so a new card shows the title"},
		{"red check", PolicyRefused, "CI_RED: verify: latest verify run concluded failure", "main", "never edit, skip or disable the check"},
		{"flood of two", PolicyRefused, "approval flood: 2 approvals already pending for this caller (limit 2)", "main", "2 requests are waiting for the operator"},
		{"flood of one", PolicyRefused, "approval flood: 1 approval already pending for project x (limit 1)", "main", "1 request is waiting for the operator"},
		{"rate limit", PolicyRefused, "rate limit: health allows 6 calls per minute per run; retry in 12 s", "", "wait the time given"},
		{"expired orchestrator token: the full command", TokenExpired, "orchestrator token old-helper expired", "old-helper", "chapd orch issue -id old-helper -project <p> -ops <op,...>"},
		{"expired run token: stop and report", TokenExpired, "token expired", "", "stop and report to the orchestrator"},
		{"revoked orchestrator token: no workaround", TokenRevoked, "the token was revoked", "main", "ask the operator"},
		{"revoked run token: report to the orchestrator", TokenRevoked, "the token was revoked", "", "stop and report to the orchestrator; do not re-issue or work around it"},
		{"params", ParamsInvalid, "unknown op", "", "correct the request and ask again"},
		{"hash mismatch", HashMismatch, "x", "", "make a new request"},
		{"consumed", ApprovalConsumed, "x", "", "works once"},
		{"integrity fault", ApprovalIntegrity, "x", "", "tell the operator"},
		{"display fault", DisplayMismatch, "x", "", "tell the operator"},
		{"approvals unavailable", ApprovalUnavail, "x", "main", "tell the operator"},
		{"branch scope", ScopeBranch, "x", "", "scope this token gives"},
		{"path scope", ScopePath, "x", "", "scope this token gives"},
		{"redaction", RedactionBlocked, "x", "", "take the secret out"},
		// A revoked token is not re-issued, whatever the id (checked below).
		// Nothing the caller can do: the "not possible" line stays.
		{"not in token", OpNotInToken, "pr.merge is not in this run's token", "", ""},
		{"disabled", OpDisabled, "deploy is disabled", "", ""},
		{"plain policy refusal", PolicyRefused, `state "Backlog" is not one intake.move may set`, "", ""},
		{"a stop word inside the text is not a stop code", PolicyRefused, `the title says "CI_STALE: x"`, "", ""},
		{"unknown", "SOMETHING_NEW", "x", "", ""},
	} {
		got := NextStep(c.cause, c.why, c.orch)
		if c.want == "" {
			if got != "" {
				t.Errorf("%s: step %q, want none", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: step %q lacks %q", c.name, got, c.want)
		}
	}
}

// A revoked token comes from a stop, a run that ended or a replaced token: the text must not name the operator as
// the cause, and must offer no way round it.
func TestRevokedTokenGetsNoWorkaround(t *testing.T) {
	for _, c := range []struct{ orch, want string }{
		{"", "stop and report to the orchestrator"},
		{"main", "ask the operator"},
	} {
		got := NextStep(TokenRevoked, "the token was revoked", c.orch)
		if strings.Contains(got, "chapd orch issue") || strings.Contains(got, "starting the run again") ||
			strings.Contains(got, "stopped by the operator") ||
			!strings.Contains(got, "revoked or its run has ended") || !strings.Contains(got, "do not re-issue or work around it") ||
			!strings.Contains(got, c.want) {
			t.Errorf("a revoked token (orch %q) must say it was revoked or its run ended, offer no workaround and say %q: %q", c.orch, c.want, got)
		}
		// Only the orchestrator is sent to the operator; a run reports to the orchestrator.
		if c.orch == "" && strings.Contains(got, "operator") {
			t.Errorf("a run is not sent to the operator: %q", got)
		}
	}
	if strings.Contains(Plain(TokenRevoked), "operator") {
		t.Errorf("the plain words must not blame the operator: %q", Plain(TokenRevoked))
	}
}

// An expired token: only an orchestrator has a re-issue command, and a run is never offered one.
func TestExpiredTokenStepDependsOnTheCaller(t *testing.T) {
	orch := NextStep(TokenExpired, "", "main")
	if !strings.Contains(orch, "chapd orch issue -id main -project <p> -ops <op,...>") || !strings.Contains(orch, "elevated") {
		t.Errorf("an orchestrator gets the full working command: %q", orch)
	}
	run := NextStep(TokenExpired, "", "")
	if strings.Contains(run, "chapd") || strings.Contains(run, "issue") || strings.Contains(run, "again") ||
		!strings.Contains(run, "stop and report to the orchestrator") {
		t.Errorf("a run gets no re-issue or restart step: %q", run)
	}
}

func TestNextStepFromTheCodeAlone(t *testing.T) {
	if NextStep(TokenExpired, "", "main") == "" || NextStep(TokenExpired, "", "") == "" {
		t.Error("an expired token needs no text to say what to do")
	}
	if got := NextStep(PolicyRefused, "", ""); got != "" {
		t.Errorf("a policy refusal with no text has no step, got %q", got)
	}
}

// denialSchemaCodes is the cause_code enum of the embedded spec schema.
func denialSchemaCodes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../spec/specdata/schemas/denial.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties struct {
			CauseCode struct {
				Enum []string `json:"enum"`
			} `json:"cause_code"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Properties.CauseCode.Enum) == 0 {
		t.Fatal("no cause_code enum in denial.schema.json")
	}
	return doc.Properties.CauseCode.Enum
}

// Every code Chaperone emits has plain words. The net, package and image codes (surfaces net, pkg, image) are raised by
// the runner's egress proxy and admission, never by Chaperone, so the table leaves them out; a new schema code lands in
// one of the two groups or this test fails.
func TestPlainCoversEveryCodeChaperoneEmits(t *testing.T) {
	var runner, ours int
	for _, c := range denialSchemaCodes(t) {
		if strings.HasPrefix(c, "NET_") || strings.HasPrefix(c, "PKG_") || strings.HasPrefix(c, "IMAGE_") {
			runner++
			if Plain(c) != "" {
				t.Errorf("%s is raised by the runner, not Chaperone: the table must not describe it", c)
			}
			continue
		}
		ours++
		if Plain(c) == "" {
			t.Errorf("no plain words for %s, a code Chaperone emits", c)
		}
	}
	if runner != 6 || ours != 18 {
		t.Errorf("the schema has %d the runner codes and %d others, expected 6 and 18: decide where a new code belongs", runner, ours)
	}
	if Plain("NOPE") != "" {
		t.Error("an unknown code must show as itself, not as invented words")
	}
}

// No next step names a way round a control, and each one reads as a plain line.
func TestNextStepsNeverCoachAWayRound(t *testing.T) {
	banned := []string{"workaround", "bypass", "circumvent", "instead use", "try another", "disable", "skip", "edit the check", "--no-verify", "force"}
	// the why lines of the refusals that have a step of their own, besides the plain code
	whys := map[string][]string{PolicyRefused: {
		"CI_RED: verify: latest verify run concluded failure",
		"CI_STALE: title_approved: the pull request title is not the one the approver saw on the card; ask again for a new approval",
		"CI_STALE: recheck_title: the pull request title is not the one the approver saw on the card; ask again for a new approval",
	}}
	for _, c := range denialSchemaCodes(t) {
		for _, orch := range []string{"", "main"} {
			steps := []string{NextStep(c, "", orch)}
			for _, why := range whys[c] {
				steps = append(steps, NextStep(c, why, orch))
			}
			for _, got := range steps {
				if got == "" {
					continue
				}
				if strings.ContainsAny(got, "\n\r") {
					t.Errorf("%s: the step is not one line: %q", c, got)
				}
				low := strings.ToLower(got)
				for _, b := range banned {
					if !strings.Contains(low, b) {
						continue
					}
					// the steps that forbid a way round say so in words
					if strings.Contains(low, "do not "+b) || strings.Contains(low, "never "+b) || strings.Contains(low, "never edit, skip or disable") {
						continue
					}
					t.Errorf("%s: step %q may coach a way round a control (%q)", c, got, b)
				}
			}
		}
	}
}
