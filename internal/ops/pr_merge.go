package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `pr.merge` (ticket L1-10): the nine steps of ADR-002. Step 1
// (authorize: run or orchestrator token, op in scope, op enabled) belongs to the
// chapd op pipeline and has already happened when Merge is called.
//
// Rules the code keeps:
//
//   - A refusal is a result ([PRVerdict], nil error), never a retry. The only
//     writes are the merge and the token revocations, and the merge is sent at
//     most once.
//   - GitHub is read with a read-only token and written with a second token that
//     is minted after the last check, used for the single merge call, and
//     revoked at once, whatever the answer.
//   - The merge carries `sha` = the head that was checked, so GitHub itself
//     answers 409 if the head moved after step 7.
//   - Medium and high tier PRs stop with [PRCauseApprovalRequired] unless the op
//     pipeline says [PRMergeRequest.Approved]. The pipeline says so only for a
//     request released under an approval it spent in the same commit
//     (cmd/chapd/approvals.go wires the approvals engine, L1-12).

// Verdict outcomes. They are the `outcome` values of the API's DryRunVerdict.
type PROutcome string

const (
	// PRAllow: every precondition holds; the merge is (or, in a dry run, would be) released.
	PRAllow PROutcome = "allow"
	// PRApproval: the PR is mergeable but its tier needs an approval first.
	PRApproval PROutcome = "approval"
	// PRRefuse: a precondition failed. The caller gets the verdict, no retry.
	PRRefuse PROutcome = "refuse"
)

// Denial cause codes the verdicts use (spec denial.schema.json).
const (
	PRCausePolicyRefused    = "OP_POLICY_REFUSED"
	PRCauseApprovalRequired = "OP_APPROVAL_REQUIRED"
)

// Stop codes a refusal can name (the spec's stop table). The op pipeline raises
// the stop; this package only says which one applies.
const (
	StopCIRed   = "CI_RED"   // verify ran on the exact head and did not pass
	StopCIStale = "CI_STALE" // no verify result for the exact head, or the head or base moved
)

// ErrMergeUnconfirmed: the merge was sent and the answer or the read-back did
// not show whether it happened. The op must end `unconfirmed`, not `failed`.
var ErrMergeUnconfirmed = errors.New("ops: pr.merge outcome unconfirmed")

// GitHubAPI is the part of *[gh.Client] that pr.merge and pr.update use. The
// fake server in ghtest backs the tests.
type GitHubAPI interface {
	GetPull(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) (*gh.Pull, error)
	ListPullFiles(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) ([]gh.PullFile, error)
	Compare(ctx context.Context, tok *gh.Token, repo gh.Repo, base, head string) (*gh.Comparison, error)
	ListCheckRuns(ctx context.Context, tok *gh.Token, repo gh.Repo, sha string, q gh.CheckRunQuery) ([]gh.CheckRun, error)
	MergePull(ctx context.Context, tok *gh.Token, repo gh.Repo, number int, req gh.MergeRequest) (*gh.MergeResult, error)
	UpdatePullBranch(ctx context.Context, tok *gh.Token, repo gh.Repo, number int, expectedHeadSHA string) (string, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
	// AppNumericID is the ID GitHub gives Chaperone's own App on repo: the App whose check runs a local_ci policy accepts.
	AppNumericID(ctx context.Context, repo gh.Repo) (int64, error)
}

var _ GitHubAPI = (*gh.Client)(nil)

// PRPolicy is the project policy pr.merge and pr.update read. The op pipeline
// loads `policy/<project>.yaml` and fills it.
type PRPolicy struct {
	// Version is the policy version echoed in verdicts. Optional.
	Version string
	// Repo is the project's repository ("owner/name"). When set, the pr.merge and
	// pr.update adapters refuse a request for any other repository. Optional.
	Repo string
	// Base is the project's merge base branch (for example feat/d1-private-pilot).
	Base string
	// ExtraChecks are check names that must pass besides `verify`, with the same
	// rules (GitHub Actions app, latest run wins, success, on the exact head).
	ExtraChecks []string
	// Tiers adds to the baseline path classifier.
	Tiers PRTierGlobs
	// Invalid, when set, says that the policy file's tier globs cannot be used: pr.merge and pr.update refuse with it (cause
	// OP_POLICY_REFUSED, the operator's fault and not the agent's) and every other op of the project is unaffected. The
	// policy engine sets it when the file loads; projectPR also checks Tiers itself, for a policy built by hand.
	Invalid error
	// LocalCI makes pr.merge read the result of a local CI run, posted by Chaperone's own App, as a required check
	// (ADR-002 amendment 10). Nil: `verify` from GitHub Actions and the extra checks, nothing else.
	LocalCI *PRLocalCI
}

func (p PRPolicy) validate() error {
	if p.Base == "" || strings.ContainsAny(p.Base, " \t\r\n") {
		return errors.New("ops: policy has no merge base")
	}
	for _, n := range p.ExtraChecks {
		if n == "" {
			return errors.New("ops: policy has an empty check name")
		}
	}
	if l := p.LocalCI; l != nil && (l.Check == "" || len(l.Check) > 64 || strings.ContainsAny(l.Check, "\r\n\x00")) {
		return errors.New("ops: policy local_ci has no usable check name")
	}
	return p.Tiers.Validate()
}

// requiredChecks returns `verify` first, then the project's extra names, once each.
func (p PRPolicy) requiredChecks() []string {
	names := []string{"verify"}
	seen := map[string]bool{"verify": true}
	for _, n := range p.ExtraChecks {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

// PRLocalCI is the `pr.local_ci` block.
type PRLocalCI struct {
	// Check is the name of the check run `ci.report` posts.
	Check string
	// Instead drops `verify` from GitHub Actions from the required checks, and the local check takes its place. The
	// extra checks stay required. False: the local check is required on top of `verify`.
	Instead bool
}

// actionsChecks returns the check names pr.merge reads from GitHub Actions: requiredChecks, less `verify` when a
// local check stands in for it.
func (p PRPolicy) actionsChecks() []string {
	names := p.requiredChecks()
	if p.LocalCI != nil && p.LocalCI.Instead {
		return names[1:]
	}
	return names
}

// PRCheck is one precondition and its result (the API's Check).
type PRCheck struct {
	Name   string // at most 64 characters
	Passed bool
	Detail string // why it failed (at most 300 characters; never a secret, never the PR title), or a note on a passed check
}

// PRSubjectEvidence is the title of the card evidence that names the PR, and PRTitlePrefix starts its first line. The
// approvals package reads the title from it (approvals.EvidencePR and approvals.EvidenceTitlePrefix: the same words;
// cmd/chapd's TestPRSubjectEvidenceWordsAgree pins them together), so the card's headline can say which change is asked
// for, and the merge reads the approved title from it (approvedTitle).
const (
	PRSubjectEvidence = "pull request"
	PRTitlePrefix     = "Title: "
)

// titleLine is the PR title as the evidence holds it: the whole title, control characters made visible ("?")
// and format characters (bidi, zero width) replaced by a space. It is never
// clipped (checkTitle already limits a title that can be merged to 72 characters), so the evidence is exactly the
// text that merge compares with the PR's title.
func titleLine(title string) string {
	return untrusted.Line(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, title))
}

// approvedTitle is the title the operator saw: the first line of the "pull request" evidence of the approval, without
// its prefix. It is "" when the approval has no such evidence (no approval, or a card made before the evidence existed).
func approvedTitle(ev []Evidence) string {
	for _, e := range ev {
		if e.Name == PRSubjectEvidence {
			line, _, _ := strings.Cut(e.Text, "\n")
			t, _ := strings.CutPrefix(line, PRTitlePrefix)
			return t
		}
	}
	return ""
}

// text is the evidence body: Title on the first line (the card headline reads it), then the author and the size.
func (s PRSubject) text() string {
	author := s.Author
	if author == "" {
		author = "(unknown)"
	}
	return fmt.Sprintf("%s%s\nAuthor: %s\nSize: %d file(s), +%d -%d", PRTitlePrefix, titleLine(s.Title), oneWord(author), s.Files, s.Additions, s.Dels)
}

// PRSubject is what the PR is about, read from GitHub on the same GET as the checks: the approval card names it so the
// approver sees which change he is approving. Every string here is the PR author's text: untrusted.
type PRSubject struct {
	Title                  string
	Author                 string // login; empty for a deleted account
	Files, Additions, Dels int
}

// subjectOf reads the PR's subject from the pull GitHub returned.
func subjectOf(p *gh.Pull) PRSubject {
	s := PRSubject{Title: p.Title, Files: p.ChangedFiles, Additions: p.Additions, Dels: p.Deletions}
	if p.User != nil {
		s.Author = p.User.Login
	}
	return s
}

// PRVerdict is what policy says about a PR: the dry-run answer and the record
// of a real attempt.
type PRVerdict struct {
	Outcome PROutcome
	// Cause is the denial cause for approval and refuse outcomes.
	Cause string
	// Stop is the stop code a refusal maps to, or "".
	Stop string
	// Why is one line for the denial; it names the failing checks.
	Why           string
	Tier          PRTier   // set once the files were classified
	TierPaths     []string // paths that set the tier, for the approval card
	Head          string   // the exact head H the checks are about
	PolicyVersion string
	Checks        []PRCheck
	Subject       PRSubject // set once the PR was read
}

// WouldAllow is the API's `would_allow`.
func (v PRVerdict) WouldAllow() bool { return v.Outcome == PRAllow }

// add records a check. detail says why it failed and is dropped when it passed.
func (v *PRVerdict) add(name string, passed bool, detail string) {
	if passed {
		detail = ""
	}
	v.Checks = append(v.Checks, PRCheck{Name: name, Passed: passed, Detail: checkDetail(detail)})
}

func (v *PRVerdict) failed() bool {
	for _, c := range v.Checks {
		if !c.Passed {
			return true
		}
	}
	return false
}

// refuse turns the failed checks into a refusal.
func (v *PRVerdict) refuse(stop string) {
	var why []string
	for _, c := range v.Checks {
		if !c.Passed {
			why = append(why, c.Name+": "+c.Detail)
		}
	}
	v.Outcome, v.Cause, v.Stop = PRRefuse, PRCausePolicyRefused, stop
	v.Why = clip(strings.Join(why, "; "), 400)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n-3], "") + "..."
}

// PRMergeRequest is one `pr.merge` call, after step 1.
type PRMergeRequest struct {
	Repo    gh.Repo
	Number  int
	Base    string // params.base: must equal the policy's merge base
	HeadSHA string // params.head_sha: the head the caller means; must equal the PR's head
	Policy  PRPolicy
	// Approved is set by the op pipeline only after the approvals engine verified
	// a valid approval bound to this op hash (whose params include HeadSHA).
	Approved bool
	// ApprovedTitle is the PR title the approver saw on the card (the first line of the card's "pull request"
	// evidence), or "" when there is none. When set, the merge refuses if the PR's title is another one now, and the
	// squash commit header is this title: the signed text is the merged text.
	ApprovedTitle string
	// DryRun returns the verdict without a write token, a merge or any write.
	DryRun bool
}

// PRMergeResult is the outcome of [PRMerger.Merge].
type PRMergeResult struct {
	Verdict PRVerdict
	// Merged is true only after the read-back showed the PR merged.
	Merged         bool
	MergeCommitSHA string
	// ExternalRef is the PR URL, for the op.result `external_ref`.
	ExternalRef string
	// WriteTokenRevoked is true if a write token was minted and GitHub accepted its revocation.
	WriteTokenRevoked bool
	// Warnings are non-fatal problems (a token that could not be revoked: it
	// still expires within the hour).
	Warnings []string
}

// PRMergerConfig builds a [PRMerger].
type PRMergerConfig struct {
	GitHub GitHubAPI
	Tokens TokenMinter
}

// PRMerger runs pr.merge and pr.update. One value is shared by the whole
// process: it owns the per-repo mutex.
type PRMerger struct {
	gh     GitHubAPI
	tokens TokenMinter
	locks  repoLocks
}

// NewPRMerger returns a PRMerger.
func NewPRMerger(cfg PRMergerConfig) (*PRMerger, error) {
	if cfg.GitHub == nil || cfg.Tokens == nil {
		return nil, errors.New("ops: PRMerger needs GitHub and Tokens")
	}
	return &PRMerger{gh: cfg.GitHub, tokens: cfg.Tokens}, nil
}

var headRE = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func (r PRMergeRequest) validate() error {
	if _, err := gh.ParseRepo(r.Repo.String()); err != nil {
		return err
	}
	if r.Number <= 0 {
		return fmt.Errorf("ops: pull request number %d", r.Number)
	}
	if !headRE.MatchString(r.HeadSHA) {
		return errors.New("ops: pr.merge needs head_sha as a full lower-case commit SHA")
	}
	return r.Policy.validate()
}

// Merge runs ADR-002 steps 2-9. The error is for infrastructure faults (GitHub
// 5xx, rate limit, token mint, cancelled context) and for
// [ErrMergeUnconfirmed]; a policy refusal is a result.
func (m *PRMerger) Merge(ctx context.Context, req PRMergeRequest) (res *PRMergeResult, err error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if !req.DryRun {
		unlock, err := m.locks.lock(ctx, req.Repo.String())
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	res = &PRMergeResult{}
	read, err := m.tokens.Mint(ctx, req.Repo, gh.PermsEvaluateMerge())
	if err != nil {
		return nil, err
	}
	defer func() {
		if rerr := m.revoke(ctx, read); rerr != nil {
			if err != nil {
				err = errors.Join(err, rerr)
			} else {
				res.Warnings = append(res.Warnings, rerr.Error())
			}
		}
	}()

	v, _, err := m.evaluate(ctx, read, req)
	res.Verdict = v
	if err != nil {
		return nil, err
	}
	if v.Outcome != PRAllow || req.DryRun {
		return res, nil
	}

	// Step 7: nothing moved. Steps 2 and 4 again, and the title of the PR as it
	// reads now (it is the commit header and may have been edited).
	pull, refused, err := m.recheck(ctx, read, req, &res.Verdict)
	if err != nil {
		return nil, err
	}
	if refused {
		return res, nil
	}

	// Step 8: merge exactly H with a token minted now.
	write, err := m.tokens.Mint(ctx, req.Repo, gh.PermsMerge())
	if err != nil {
		return nil, err
	}
	commitTitle := pull.Title // the recheck made it the approved title when there is one
	if req.ApprovedTitle != "" {
		commitTitle = req.ApprovedTitle
	}
	merged, mergeErr := m.gh.MergePull(ctx, write, req.Repo, req.Number, gh.MergeRequest{
		SHA: req.HeadSHA, Method: gh.MergeSquash, CommitTitle: commitTitle,
	})
	if rerr := m.revoke(ctx, write); rerr != nil {
		res.Warnings = append(res.Warnings, "write token: "+rerr.Error())
	} else {
		res.WriteTokenRevoked = true
	}
	if mergeErr != nil {
		var api *gh.APIError
		if errors.As(mergeErr, &api) && api.RateLimit == nil &&
			(api.Status == http.StatusMethodNotAllowed || api.Status == http.StatusConflict || api.Status == http.StatusUnprocessableEntity) {
			stop := ""
			if api.Status == http.StatusConflict {
				stop = StopCIStale // the head moved after step 7: GitHub's `sha` check caught it
			}
			res.Verdict.add("merge_write", false, fmt.Sprintf("GitHub refused the merge (%d): %s", api.Status, api.Detail()))
			res.Verdict.refuse(stop)
			return res, nil
		}
		// Anything else (5xx, timeout, rate limit): the merge may or may not have
		// happened. Look once; never send it again.
		back, rerr := m.readBack(ctx, read, req)
		switch {
		case rerr != nil:
			return nil, fmt.Errorf("%w: merge call failed (%v) and read-back failed (%v)", ErrMergeUnconfirmed, mergeErr, rerr)
		case !back.Merged:
			return nil, fmt.Errorf("pr.merge: GitHub did not merge: %w", mergeErr)
		}
		return m.merged(res, req, back, ""), nil
	}

	// Step 9: confirm.
	back, rerr := m.readBack(ctx, read, req)
	if rerr != nil {
		return nil, fmt.Errorf("%w: read-back failed: %v", ErrMergeUnconfirmed, rerr)
	}
	if !back.Merged {
		return nil, fmt.Errorf("%w: GitHub answered merged but the PR reads open", ErrMergeUnconfirmed)
	}
	return m.merged(res, req, back, merged.SHA), nil
}

func (m *PRMerger) merged(res *PRMergeResult, req PRMergeRequest, back *gh.Pull, answered string) *PRMergeResult {
	res.Merged = true
	res.MergeCommitSHA = back.MergeCommitSHA
	if res.MergeCommitSHA == "" {
		res.MergeCommitSHA = answered
	}
	res.ExternalRef = safeURL(back.HTMLURL, 300)
	if res.ExternalRef == "" {
		res.ExternalRef = fmt.Sprintf("https://github.com/%s/pull/%d", req.Repo, req.Number)
	}
	res.ExternalRef = clip(untrusted.Line(res.ExternalRef), 300)
	res.Verdict.add("merged", true, "")
	return res
}

// readBack reads the PR once after the write, on a context that survives the
// caller's cancellation (a timed-out merge is exactly when we must look).
func (m *PRMerger) readBack(ctx context.Context, tok *gh.Token, req PRMergeRequest) (*gh.Pull, error) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	return m.gh.GetPull(rctx, tok, req.Repo, req.Number)
}

// revoke revokes and wipes a token. It uses a context that survives the
// caller's cancellation so a cancelled op still revokes.
func (m *PRMerger) revoke(ctx context.Context, tok *gh.Token) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := m.gh.RevokeToken(rctx, tok)
	tok.Wipe()
	if err != nil {
		return fmt.Errorf("revoke installation token: %w", err)
	}
	return nil
}

// pullChecks are the state checks of ADR-002 step 2 (and step 7): open, not
// draft, merge base, same repository, mergeable, and the head the caller named.
// prefix is "" for step 2 and "recheck_" for step 7.
func pullChecks(prefix string, pull *gh.Pull, req PRMergeRequest) []PRCheck {
	var out []PRCheck
	add := func(name string, ok bool, detail string) {
		if ok {
			detail = ""
		}
		out = append(out, PRCheck{Name: prefix + name, Passed: ok, Detail: checkDetail(detail)})
	}
	add("pr_open", pull.State == "open" && !pull.Merged, "pull request is "+oneWord(pull.State)+", merged="+fmt.Sprint(pull.Merged))
	add("pr_not_draft", !pull.Draft, "pull request is a draft")
	add("base_branch", pull.Base.Ref == req.Policy.Base && (req.Base == "" || req.Base == req.Policy.Base),
		fmt.Sprintf("PR base is %s, request base is %s, project merge base is %s", oneWord(pull.Base.Ref), oneWord(req.Base), req.Policy.Base))
	sameRepo := pull.Head.Repo != nil && strings.EqualFold(pull.Head.Repo.FullName, req.Repo.String())
	add("head_same_repo", sameRepo, "head branch is not in "+req.Repo.String()+" (fork or deleted repository)")
	add("mergeable", pull.Mergeable == nil || *pull.Mergeable, "GitHub reports a merge conflict")
	add("head_matches_request", pull.Head.SHA == req.HeadSHA,
		fmt.Sprintf("PR head is %s, request named %s", short(pull.Head.SHA), short(req.HeadSHA)))
	return out
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return oneWord(sha)
}

// oneWord makes attacker-influenced text safe to put in a one-line detail: a
// control character is shown as "?", a format character as a space.
func oneWord(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	return clip(untrusted.Line(s), 80)
}

// checkDetail is the detail of a check: one line, with no control or format
// character (a bidi override, a zero-width joiner) from the text it quotes,
// and at most 300 bytes. The pull request author and GitHub wrote some of it.
func checkDetail(s string) string { return clip(untrusted.Line(s), 300) }

// titleEdited is why a merge is refused when the title is not the approved one. It never repeats a title (they are
// the author's text).
const titleEdited = "the pull request title is not the one the approver saw on the card; ask again for a new approval"

// titleApproved reports whether title is the one on the card: always true when the request carries no approved title.
func (r PRMergeRequest) titleApproved(title string) bool {
	return r.ApprovedTitle == "" || titleLine(title) == r.ApprovedTitle
}

// evaluate is steps 2-6 and the tier part of step 5. It returns a verdict (never
// nil-safe to ignore on error: it holds the checks so far) and the PR it read.
func (m *PRMerger) evaluate(ctx context.Context, tok *gh.Token, req PRMergeRequest) (PRVerdict, *gh.Pull, error) {
	v := PRVerdict{Outcome: PRAllow, Head: req.HeadSHA, PolicyVersion: req.Policy.Version}

	// Step 2: read the PR.
	pull, err := m.gh.GetPull(ctx, tok, req.Repo, req.Number)
	switch {
	case errors.Is(err, gh.ErrNotFound):
		v.add("pr_exists", false, "no such pull request")
		v.refuse("")
		return v, nil, nil
	case err != nil:
		return v, nil, fmt.Errorf("pr.merge: read PR: %w", err)
	}
	v.Subject = subjectOf(pull)
	v.Checks = append(v.Checks, pullChecks("", pull, req)...)
	if v.failed() {
		stop := ""
		if pull.Head.SHA != req.HeadSHA {
			stop = StopCIStale
		}
		v.refuse(stop)
		return v, pull, nil
	}

	// Step 3: the required checks on exactly H. The ones named by policy come from GitHub Actions only; with a
	// local_ci block, the local check comes from Chaperone's own App only (amendment 10).
	for _, name := range req.Policy.actionsChecks() {
		runs, err := m.gh.ListCheckRuns(ctx, tok, req.Repo, req.HeadSHA, gh.CheckRunQuery{
			CheckName: name, AppID: gh.GitHubActionsAppID, All: true,
		})
		if errors.Is(err, gh.ErrListTruncated) {
			v.add(name, false, "more check runs than GitHub listed; result is ambiguous")
			v.refuse("")
			return v, pull, nil
		}
		if err != nil {
			return v, pull, fmt.Errorf("pr.merge: read check %s: %w", name, err)
		}
		c, stop := judgeCheck(name, gh.GitHubActionsAppID, "GitHub Actions", runs, req.HeadSHA)
		v.Checks = append(v.Checks, c)
		if !c.Passed {
			v.refuse(stop)
			return v, pull, nil
		}
	}
	if l := req.Policy.LocalCI; l != nil {
		own, err := m.gh.AppNumericID(ctx, req.Repo)
		if err != nil {
			return v, pull, fmt.Errorf("pr.merge: find Chaperone's App: %w", err)
		}
		runs, err := m.gh.ListCheckRuns(ctx, tok, req.Repo, req.HeadSHA, gh.CheckRunQuery{CheckName: l.Check, AppID: own, All: true})
		if errors.Is(err, gh.ErrListTruncated) {
			v.add(l.Check, false, "more check runs than GitHub listed; result is ambiguous")
			v.refuse("")
			return v, pull, nil
		}
		if err != nil {
			return v, pull, fmt.Errorf("pr.merge: read check %s: %w", l.Check, err)
		}
		c, stop := judgeCheck(l.Check, own, "Chaperone's App", runs, req.HeadSHA)
		v.Checks = append(v.Checks, c)
		if !c.Passed {
			v.refuse(stop)
			return v, pull, nil
		}
	}

	// Step 4: base is current.
	cmp, err := m.gh.Compare(ctx, tok, req.Repo, req.Policy.Base, req.HeadSHA)
	if err != nil {
		return v, pull, fmt.Errorf("pr.merge: compare: %w", err)
	}
	v.add("base_current", cmp.BehindBy == 0, fmt.Sprintf("head is %d commit(s) behind %s; run pr.update, then wait for verify on the new head", cmp.BehindBy, req.Policy.Base))
	if v.failed() {
		v.refuse(StopCIStale)
		return v, pull, nil
	}

	// Step 6 (before the tier, so no approval card is raised for a PR that
	// would be refused anyway): the title is the squash commit header.
	if err := checkTitle(pull.Title); err != nil {
		v.add("title", false, err.Error())
		v.refuse("")
		return v, pull, nil
	}
	v.add("title", true, "")
	// The approver saw one title on the card; a PR that has another one now is a different request (it needs a new card).
	if !req.titleApproved(pull.Title) {
		v.add("title_approved", false, titleEdited)
		v.refuse(StopCIStale)
		return v, pull, nil
	}

	// Step 5: risk tier by path.
	files, err := m.gh.ListPullFiles(ctx, tok, req.Repo, req.Number)
	var tier PRTierResult
	var hidden hiddenText
	hidden.see("title", "titles", pull.Title, false)
	if pull.User != nil {
		hidden.see("author name", "author names", pull.User.Login, false)
	}
	hidden.see("base branch name", "base branch names", pull.Base.Ref, false)
	switch {
	case errors.Is(err, gh.ErrListTruncated):
		tier = PRTierResult{Tier: TierHigh, Unclassified: true}
	case err != nil:
		return v, pull, fmt.Errorf("pr.merge: read files: %w", err)
	default:
		pf := make([]PRFile, len(files))
		for i, f := range files {
			hidden.see("file path", "file paths", f.Filename, false)
			if f.PreviousFilename != "" {
				hidden.see("file path", "file paths", f.PreviousFilename, false)
			}
			pf[i] = PRFile{Path: f.Filename, PreviousPath: f.PreviousFilename, Status: f.Status, Patch: f.Patch, Changes: f.Additions + f.Deletions}
		}
		tier = req.Policy.Tiers.Classify(pf)
	}
	v.Tier, v.TierPaths = tier.Tier, tier.Paths
	if w := hidden.text(); w != "" {
		// The text is shown cleaned. Say so, so the operator knows it was changed. The tier above was
		// computed from the raw paths (and their hidden-character-free form), never from the cleaned text.
		v.Checks = append(v.Checks, PRCheck{Name: "hidden_text", Passed: true, Detail: checkDetail(w)})
	}
	detail := tierDetail(tier)
	if tier.Tier != TierLow && !req.Approved {
		v.add("risk_tier", false, detail+"; needs an approval bound to this exact head")
		v.Outcome, v.Cause = PRApproval, PRCauseApprovalRequired
		v.Why = clip("pr.merge needs an approval for this exact head: "+detail, 400)
		return v, pull, nil
	}
	v.Checks = append(v.Checks, PRCheck{Name: "risk_tier", Passed: true, Detail: checkDetail(detail)})
	return v, pull, nil
}

func tierDetail(t PRTierResult) string {
	var b strings.Builder
	b.WriteString("tier " + string(t.Tier))
	if t.Unclassified {
		b.WriteString(" (a path the policy cannot classify counts as high)")
	}
	if t.TestsWeakened {
		b.WriteString(" (the PR deletes or skips tests)")
	}
	if len(t.Paths) > 0 {
		b.WriteString(": ")
		for i, p := range t.Paths {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(oneWord(p))
		}
		if t.More > 0 {
			fmt.Fprintf(&b, " and %d more", t.More)
		}
	}
	return b.String()
}

// judgeCheck applies ADR-002 step 3 to the runs of one check name on H. Only
// runs of the one App that policy trusts for that name count (GitHub Actions
// for `verify` and the extra checks, Chaperone's own App for a local_ci check):
// the query filters by app and this repeats the filter so a wrong server
// answer cannot admit a forged run. Of the runs on H
// the latest one decides (operator decision, 24 Oct: an older failed run does
// not block a green re-run, and an older green run does not hide a newer red
// or running one). It must be completed with conclusion success, for H.
func judgeCheck(name string, appID int64, appName string, runs []gh.CheckRun, head string) (PRCheck, string) {
	var r gh.CheckRun
	n := 0
	for _, c := range runs {
		if c.Name == name && c.AppID == appID {
			if n == 0 || laterRun(c, r) {
				r = c
			}
			n++
		}
	}
	fail := func(stop, format string, a ...any) (PRCheck, string) {
		return PRCheck{Name: name, Detail: checkDetail(fmt.Sprintf(format, a...))}, stop
	}
	if n == 0 {
		return fail(StopCIStale, "no %s run from %s on head %s", name, appName, short(head))
	}
	switch {
	case r.HeadSHA != head:
		return fail(StopCIStale, "%s run is for head %s, not %s", name, short(r.HeadSHA), short(head))
	case r.Status != "completed":
		return fail("", "latest %s run is %s, not completed", name, oneWord(r.Status))
	case r.Conclusion != "success":
		return fail(StopCIRed, "latest %s run concluded %s, not success", name, oneWord(r.Conclusion))
	}
	return PRCheck{Name: name, Passed: true, Detail: "success on " + short(head)}, ""
}

// laterRun reports whether a started after b: highest started_at, then the
// higher run id. A run with no started_at counts as the latest, so a run whose
// time GitHub did not give can only make the verdict stricter, never hide.
func laterRun(a, b gh.CheckRun) bool {
	switch {
	case a.StartedAt.IsZero() != b.StartedAt.IsZero():
		return a.StartedAt.IsZero()
	case !a.StartedAt.Equal(b.StartedAt):
		return a.StartedAt.After(b.StartedAt)
	}
	return a.ID > b.ID
}

// recheck is step 7: read the PR again and compare the base again. It appends
// its checks to v and reports whether it refused. On success it returns the
// fresh PR (its title is the one that gets merged).
func (m *PRMerger) recheck(ctx context.Context, tok *gh.Token, req PRMergeRequest, v *PRVerdict) (*gh.Pull, bool, error) {
	pull, err := m.gh.GetPull(ctx, tok, req.Repo, req.Number)
	if err != nil {
		return nil, false, fmt.Errorf("pr.merge: recheck PR: %w", err)
	}
	v.Checks = append(v.Checks, pullChecks("recheck_", pull, req)...)
	if err := checkTitle(pull.Title); err != nil {
		v.add("recheck_title", false, err.Error())
	} else if !req.titleApproved(pull.Title) {
		v.add("recheck_title", false, titleEdited)
	}
	if v.failed() {
		v.refuse(StopCIStale)
		return pull, true, nil
	}
	cmp, err := m.gh.Compare(ctx, tok, req.Repo, req.Policy.Base, req.HeadSHA)
	if err != nil {
		return nil, false, fmt.Errorf("pr.merge: recheck compare: %w", err)
	}
	v.add("recheck_base_current", cmp.BehindBy == 0, fmt.Sprintf("base moved: head is now %d commit(s) behind %s", cmp.BehindBy, req.Policy.Base))
	if v.failed() {
		v.refuse(StopCIStale)
		return pull, true, nil
	}
	return pull, false, nil
}
