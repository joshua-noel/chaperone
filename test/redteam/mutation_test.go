package redteam

// The mutation check (L1-19 acceptance: "each replay names its incident and
// fails when the matching control is removed"). For each control below, the
// test writes a copy of ONE source file with the control removed, runs the
// matching red-team test against that copy (`go test -overlay`, so the checkout
// itself is never touched), and requires the test to FAIL: a non-zero exit, a
// `--- FAIL` line for that test, and no build failure (a mutation that does not
// compile proves nothing). If a mutation survives, the replay does not protect
// its control.
//
// Each anchor must match exactly once in its file. When a source file changes
// and an anchor no longer matches, this test fails and says which one: update
// the anchor to the same control, never loosen the expected failure.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type mutation struct {
	name     string // the control that is removed
	file     string // relative to the module root
	old      string // must occur exactly once
	new      string
	test     string // the test that must go red
	pkg      string // the package that test lives in; empty means this one, ./test/redteam
	incident string
}

var mutations = []mutation{
	{
		name: "merge refuses a red verify", incident: "22 Oct merge on red (RT-01)",
		file: "internal/ops/pr_merge.go", old: `case r.Conclusion != "success":`, new: `case false:`,
		test: "TestRT01MergeOnRed",
	},
	{
		name: "merge needs the head CI saw", incident: "18 Oct merge on stale CI (RT-02)",
		file: "internal/ops/pr_merge.go", old: `add("head_matches_request", pull.Head.SHA == req.HeadSHA,`, new: `add("head_matches_request", true,`,
		test: "TestRT02MergeOnStaleCI",
	},
	{
		name: "medium and high tier PRs need an approval", incident: "RT-03",
		file: "internal/ops/pr_merge.go", old: `if tier.Tier != TierLow && !req.Approved {`, new: `if false {`,
		test: "TestRT03RiskTierNeedsAnApproval",
	},
	{
		name: "deleting or skipping tests is at least medium", incident: "RT-03 (b)",
		file: "internal/ops/pr_merge_tier.go", old: `if weakensTests(f) {`, new: `if false {`,
		test: "TestRT03RiskTierNeedsAnApproval",
	},
	{
		name: "requirements files are at least medium", incident: "RT-03 (e)",
		file: "internal/ops/pr_merge_tier.go", old: `if anyGlob(g.Medium, name) || anyGlob(baselineMedium, name) {`, new: `if anyGlob(g.Medium, name) {`,
		test: "TestRT03RiskTierNeedsAnApproval",
	},
	{
		name: "an approval is bound to its op hash", incident: "approval binding, A approved and B requested (RT-11)",
		file: "internal/approvals/consume.go", old: `if hash != a.OpHash ||`, new: `if hash == "" ||`,
		test: "TestRT11ApprovalIsBoundToItsRequest",
	},
	{
		name: "a token cannot decide an approval", incident: "an agent approves itself (RT-13)",
		file: "internal/approvals/decide.go", old: `if actor.Kind != ActorApprover {`, new: `if false {`,
		test: "TestRT13NoTokenCanDecide",
	},
	{
		name: "pending approvals are capped per caller", incident: "push-bomb (RT-15)",
		file: "internal/ops/service.go", old: `} else if n >= chap.PerRun {`, new: `} else if false {`,
		test: "TestRT15PushBombOverHTTP",
	},
	{
		name: "the redactor masks registered secrets", incident: "19 Oct secret in a log (RT-26)",
		file: "internal/redact/registry.go", old: "func (r *Registry) RedactBytes(b []byte) ([]byte, Result) {\n\tvar hits []Hit",
		new:  "func (r *Registry) RedactBytes(b []byte) ([]byte, Result) {\n\tif true {\n\t\treturn b, Result{}\n\t}\n\tvar hits []Hit",
		test: "TestRT26CanaryNeverAppearsAnywhere",
	},
	{
		name: "a request that holds a secret is refused before it is stored", incident: "RT-26 agent-supplied secret in the ops table",
		file: "internal/ops/service.go", old: `if s.submissionLeaks(sub) {`, new: `if false {`,
		test: "TestRT26AgentSuppliedSecret",
	},
	{
		name: "a denial never echoes a secret", incident: "RT-26 agent-supplied secret in a denial body",
		file: "internal/ops/denial.go", old: `if s.leaks(d.Verb, d.Target, d.Why, d.Command) {`, new: `if false {`,
		test: "TestRT26AgentSuppliedSecret",
	},
	{
		name: "a revoked orchestrator token is refused", incident: "orchestrator token revoked (ADR-007)",
		file: "internal/runtoken/orch.go", old: "\tif revoked.Valid {\n\t\treturn nil, forOrch(misuse(refuse(CauseTokenRevoked", new: "\tif false {\n\t\treturn nil, forOrch(misuse(refuse(CauseTokenRevoked",
		test: "TestOrchTokenRevokedIsRefusedAtOnce",
	},
	{
		name: "interim tokens stop at allow_interim=false", incident: "interim token after the switch-off (RT-52)",
		file: "internal/runtoken/verify.go", old: `if !keys.AllowInterim() {`, new: `if false {`,
		test: "TestRT52InterimTokenAfterSwitchOff",
	},
	{
		name: "a push may update only the task branch", incident: "push to base, tags, other refs (RT-05)",
		file: "internal/ops/git_gate.go", old: `if why := gitPushRefusal(c, p); why != "" {`, new: `if why := ""; why != "" {`,
		test: "TestRT05PushToTheWrongRef",
	},
	{
		name: "the mint ceiling leaves out the critical ops", incident: "RT-52 mint ceiling vs policy profile",
		file: "internal/runtoken/keyset.go", old: "\t\"deploy\", \"data.apply\", \"mail.send\", \"drive.share\", \"notion.write\",\n}", new: "\t\"deploy\", \"data.apply\", \"mail.send\", \"drive.share\", \"notion.write\",\n\t\"repo.settings\", \"host.scripts.refresh\",\n}",
		test: "TestRT52MintCeiling",
	},
	// Google connectors (L1-16). The replays are rt24_google_test.go.
	{
		name: "mail.send refuses a recipient off the allowlist", incident: "22 Oct demo email to a recipient nobody listed (RT-24)",
		file: "internal/connectors/google/gmail.go", old: `if bad := refuseUnlisted(pol.Mail.AllowRecipients, all); len(bad) > 0 {`, new: `if bad := refuseUnlisted(pol.Mail.AllowRecipients, all); len(bad) > 0 && false {`,
		test: "TestRT24OffListRecipientNeverGetsACard",
	},
	{
		name: "drive.share refuses a role above the cap", incident: "a share that grants more than the project allows (RT-24)",
		file: "internal/connectors/google/drive.go", old: `if roleRank[role] > roleRank[capRole] {`, new: `if false {`,
		test: "TestRT24DriveRoleCapAndAllowlist",
	},
	{
		name: "mail.send refuses a secret inside an attachment", incident: "secret leaves in an attachment (RT-25, RT-26)",
		file: "internal/connectors/google/gmail.go", old: `if _, res := g.cfg.Redactor.RedactBytes(data); res.Blocked() {`, new: `if _, res := g.cfg.Redactor.RedactBytes(data); res.Blocked() && false {`,
		test: "TestRT24SecretInMailIsRefused",
	},
	{
		name: "mail.send sends only the attachment whose SHA-256 is on the card", incident: "attachment swapped after the card (RT-12)",
		file: "internal/connectors/google/gmail.go", old: `if SumHex(data) != sum {`, new: `if false {`,
		test: "TestRT24SwappedAttachmentIsNotSent",
	},
	{
		name: "mail.send fails closed when Google refuses the sign-in", incident: "revoked or expired Google grant (L1-16 acceptance)",
		file: "internal/connectors/google/gmail.go", old: `if p := st.Problem(g.cfg.Source.cfg.Now()); p != "" {`, new: `if p := st.Problem(g.cfg.Source.cfg.Now()); p != "" && false {`,
		test: "TestRT24RevokedGoogleGrantFailsClosed",
	},
	{
		name: "the mail card carries the SHA-256 of the rendered message", incident: "message differs from what the card showed (RT-24)",
		file: "internal/connectors/google/gmail.go", old: `fmt.Fprintf(&b, "Rendered message: %d bytes, SHA-256 %s\n", len(p.mime), p.sha)`, new: `_ = p.sha`,
		test: "TestRT24CardShowsTheRenderedMessage",
	},
	// The console screens (L1-20). Their replays are in internal/console (they
	// need a signed-in browser and a Windows Hello stand-in, which only that
	// package has); RT-14 and RT-26 in the table above point there.
	{
		name: "the console shows nothing without a Hello session", incident: "operator console reached without a session (RT-14)",
		file: "internal/console/screens.go", old: `if st.user != nil {`, new: `if true {`,
		test: "TestScreensNeedASession", pkg: "./internal/console",
	},
	{
		name: "a secret is stored only by spending its approval", incident: "secret written on a session alone (ADR-003 item 5, decision #21)",
		file: "internal/console/screens_secrets.go", old: `return s.c.appr.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: a.ID, Request: h.req})`, new: `return approvals.Effects{}, nil`,
		test: "TestSecretImportNeedsAFreshHelloApproval", pkg: "./internal/console",
	},
	{
		name: "the value stored is the value that was approved", incident: "value swapped between the card and the write (RT-11)",
		file: "internal/console/screens_secrets.go", old: `if !hmac.Equal([]byte(h.commitment()), []byte(paramString(a.Request.Params, "value_commitment"))) {`, new: `if false {`,
		test: "TestSecretCommitRefusals", pkg: "./internal/console",
	},
	{
		name: "Stop all logs OPERATOR_STOP_ALL", incident: "stop and revoke (RT-33)",
		file: "internal/console/screens_home.go", old: `n, err := s.cfg.Runs.RevokeAll(r.Context(), runtoken.StopOperatorStopAll)`, new: `n, err := s.cfg.Runs.RevokeAll(r.Context(), runtoken.StopOperatorStopRun)`,
		test: "TestStopAllRevokesEveryRunAndLogsOperatorStopAll", pkg: "./internal/console",
	},
	{
		name: "Revoke orchestrator revokes the token", incident: "orchestrator token revoked from the console (ADR-007 item 7)",
		file: "internal/console/screens_runs.go", old: `switch err := s.cfg.Orch.Revoke(r.Context(), id, "console"); {`, new: `switch err := error(nil); {`,
		test: "TestRevokeOrchestrator", pkg: "./internal/console",
	},
	{
		name: "deploy needs the load gate to say normal", incident: "deploy on a busy host (RT-23)",
		file: "internal/ops/deploy_facts.go", old: `case g.Mode != LoadGateNormal:`, new: `case false:`,
		test: "TestRT23DeployPreconditions",
	},
	{
		name: "deploy refuses a zero-byte backup", incident: "20 Oct 0-byte dump (RT-23)",
		file: "internal/ops/deploy_facts.go", old: `case b.Bytes <= 0:`, new: `case false:`,
		test: "TestRT23DeployPreconditions",
	},
	{
		name: "deploy refuses a stale backup", incident: "backup older than 26 h (RT-23)",
		file: "internal/ops/deploy_facts.go", old: "\tcase age > maxAge:\n\t\treturn false, fmt.Sprintf(\"the last valid backup is", new: "\tcase false:\n\t\treturn false, fmt.Sprintf(\"the last valid backup is",
		test: "TestRT23DeployPreconditions",
	},
	{
		name: "deploy needs the commit to be on the base branch", incident: "deploy of an unmerged commit (RT-23)",
		file: "internal/ops/deploy.go", old: `onBase := (cmp.Status == "identical" || cmp.Status == "behind") && cmp.AheadBy == 0`, new: `onBase := true`,
		test: "TestRT23DeployPreconditions",
	},
	{
		name: "a deploy that leaves the pilot down is failed", incident: "deploy followed by a dead pilot (RT-23)",
		file: "internal/ops/deploy.go", old: "\tif !after.OK() {\n\t\tres[\"error\"] = \"the runbook finished but", new: "\tif false {\n\t\tres[\"error\"] = \"the runbook finished but",
		test: "TestRT23DeployFailedPostHealth",
	},
	// The approvals engine as chapd wires it (cmd/chapd/approvals.go). Their replays
	// are end-to-end tests in ./cmd/chapd: the real engine, op pipeline, ledger and
	// policy over a fake GitHub, with a Windows Hello stand-in.
	{
		name: "a release spends its approval", incident: "an approval used for a second release (RT-11 e)",
		file: "internal/ops/lifecycle.go", old: `return s.appr.ConsumeTx(ctx, tx, rec.ApprovalID, sreq)`, new: `return nil`,
		test: "TestE2EApprovedMergeRunsExactlyOnce", pkg: "./cmd/chapd",
	},
	{
		name: "a denied card never releases the op", incident: "a denial that still lets the op run (ADR-004 section 6, item 5)",
		file: "cmd/chapd/approvals.go", old: "\tcase approvals.OutcomeDenied:\n\t\tdec.Reason = d.Reason", new: "\tcase approvals.OutcomeDenied:\n\t\tdec.Approved, dec.Reason = true, d.Reason",
		test: "TestE2EDenyIsSticky", pkg: "./cmd/chapd",
	},
	// The phone (L1-22): number matching, the channel cross-check, the push
	// allowlist, the enrolment and the origin binding.
	{
		name: "the phone gets no challenge before its number matched", incident: "phone approve without number matching (RT-18)",
		file: "internal/approvals/decide.go", old: `if e.channelOf(in.Origin) == "phone" {`, new: `if false {`,
		test: "TestRT18PhoneNeedsItsNumberToApprove",
	},
	{
		name: "a wrong number on the phone denies the card", incident: "blind tap on the phone page (RT-18)",
		file: "internal/approvals/phone.go", old: `if len(in.Choice) != 2 || subtle.ConstantTimeCompare([]byte(in.Choice), []byte(p.code)) != 1 {`, new: `if len(in.Choice) != 2 || subtle.ConstantTimeCompare([]byte(in.Choice), []byte(p.code)) == 5 {`,
		test: "TestRT18WrongNumberDeniesAndStartsTheCooldown",
	},
	{
		name: "a phone assertion is not a PC assertion", incident: "channel confusion between the two devices (RT-18)",
		file: "internal/approvals/decide.go", old: `if ev.Channel != e.channelOf(ch.Origin) {`, new: `if false {`,
		test: "TestRT18PhoneNeedsItsNumberToApprove",
	},
	{
		name: "a push is built only from allowlisted text", incident: "request text in a push, lock-screen leakage (RT-19)",
		file: "internal/notify/payload.go", old: `if !projectRE.MatchString(w.Project) {`, new: `if false {`,
		test: "TestRT19NoParameterReachesAPush",
	},
	{
		name: "an assertion is accepted only at the origin it was made for", incident: "look-alike origin collects an assertion (RT-18)",
		file: "internal/console/console.go", old: `RPOrigins:             []string{o.URL},`,
		new:  `RPOrigins:             []string{o.URL, "https://pc.tail1234.ts.net.evil.example", "https://pc-tail1234.ts.net", "http://pc.tail1234.ts.net", "https://pc.tail1234.ts.net:8443", "https://xpc.tail1234.ts.net", "http://localhost:55398"},`,
		test: "TestPhoneLookAlikeOriginsCollectNothing", pkg: "./internal/console",
	},
	{
		name: "the phone cannot enrol another device", incident: "a stolen unlocked phone adds a device (RT-20)",
		file: "internal/console/phone.go", old: "\tcase c.appr.IsPhoneOrigin(st.rp.URL):\n\t\t// The phone is not where the phone is enrolled", new: "\tcase st.rp == nil:\n\t\t// The phone is not where the phone is enrolled",
		test: "TestPhonePageAndRoutesAreForTheRightOrigin", pkg: "./internal/console",
	},
	{
		name: "one approval makes one enrolment address", incident: "an approved enrolment spent twice (RT-20)",
		file: "internal/console/phone.go", old: `fx, err := c.appr.ConsumeTx(ctx, tx, approvals.ConsumeInput{ApprovalID: a.ID, Request: a.Request})`, new: `fx, err := approvals.Effects{}, error(nil)`,
		test: "TestPhoneEnrolmentEndToEnd", pkg: "./internal/console",
	},
	// Ledger anchors (L1-21, RT-27). The replays live in internal/ledger: they need
	// a second, forged chain and the scheduler's fake clock.
	{
		name: "an anchor record must match the chain's hashes", incident: "a whole-chain rewrite before an anchor (RT-27)",
		file: "internal/ledger/anchor_verify.go", old: `case got != c.want:`, new: `case false:`,
		test: "TestAnchorDetectsRewriteOfEveryEventBeforeIt", pkg: "./internal/ledger",
	},
	{
		name: "an anchor record's signature is checked", incident: "a forged anchor record offered as evidence (RT-27)",
		file: "internal/ledger/anchor_verify.go", old: `case !r.Verify(pub):`, new: `case !r.Verify(pub) && false:`,
		test: "TestVerifyAnchorsOtherProblems", pkg: "./internal/ledger",
	},
	{
		name: "a missing export for 26 hours raises an alert", incident: "the ledger export stops and nobody notices (ADR-006)",
		file: "internal/ledger/anchor_sched.go", old: `if age := now.Sub(lastOK); age > a.cfg.StaleAfter {`, new: `if age := now.Sub(lastOK); false && age > a.cfg.StaleAfter {`,
		test: "TestMissingExportRaisesAlertAfter26Hours", pkg: "./internal/ledger",
	},
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find the source directory")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("not the module root: %v", err)
	}
	return root
}

func TestMutationsTurnTheReplaysRed(t *testing.T) {
	root := moduleRoot(t)
	sem := make(chan struct{}, 2) // compiling is heavy: two at a time
	for _, m := range mutations {
		t.Run(m.test, func(t *testing.T) {
			t.Parallel()
			src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m.file)))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ReplaceAll(string(src), "\r\n", "\n")
			if n := strings.Count(text, m.old); n != 1 {
				t.Fatalf("the anchor for %q matches %d times in %s, want exactly 1; the control moved: update the anchor\n%s", m.name, n, m.file, m.old)
			}
			patched := strings.Replace(text, m.old, m.new, 1)

			dir := t.TempDir()
			patchedPath := filepath.Join(dir, filepath.Base(m.file))
			if err := os.WriteFile(patchedPath, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(root, filepath.FromSlash(m.file)): patchedPath}})
			ovPath := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(ovPath, ov, 0o644); err != nil {
				t.Fatal(err)
			}

			sem <- struct{}{}
			defer func() { <-sem }()
			pkg := m.pkg
			if pkg == "" {
				pkg = "./test/redteam"
			}
			cmd := exec.Command(goTool(), "test", "-overlay="+ovPath, "-count=1", "-timeout=6m", "-run", "^"+m.test+"$", pkg)
			cmd.Dir = root
			start := time.Now()
			out, err := cmd.CombinedOutput()
			text = string(out)
			t.Logf("%s: mutated run took %s", m.test, time.Since(start).Round(time.Second))
			switch {
			case strings.Contains(text, "[build failed]") || strings.Contains(text, "[setup failed]") || strings.Contains(text, "cannot find package"):
				t.Fatalf("the mutation did not build, so it proves nothing:\n%s", tail(text))
			case err == nil:
				t.Fatalf("SURVIVED: with %q removed (%s) %s still passes. The replay does not protect this control.\n%s", m.name, m.file, m.test, tail(text))
			case !strings.Contains(text, "--- FAIL: "+m.test):
				t.Fatalf("the mutated run failed, but not in %s:\n%s", m.test, tail(text))
			}
		})
	}
}

func tail(s string) string {
	if len(s) > 3000 {
		return "..." + s[len(s)-3000:]
	}
	return s
}
