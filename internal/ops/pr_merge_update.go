package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// PRUpdateRequest is one `pr.update` call, after step 1 (authorize). It brings
// the base into the PR branch (`PUT /pulls/{n}/update-branch`), which replaces
// `gh pr update-branch` in merge-procedure.md.
type PRUpdateRequest struct {
	Repo   gh.Repo
	Number int
	// ExpectedHeadSHA is required. It must equal the PR's head now, and GitHub
	// refuses the update (422) if the head moves before the write.
	ExpectedHeadSHA string
	Policy          PRPolicy
}

// PRUpdateResult is the outcome of [PRMerger.UpdateBranch].
type PRUpdateResult struct {
	Verdict PRVerdict
	// Updated is true if GitHub accepted the update (202). GitHub does the
	// merge into the branch asynchronously.
	Updated bool
	OldHead string
	// NewHead is the head read straight after the accepted update. If GitHub has
	// not finished it equals OldHead: read the PR again. Either way a new head
	// voids every earlier verify, and the next pr.merge starts at step 2.
	NewHead           string
	Message           string
	ExternalRef       string
	WriteTokenRevoked bool
	Warnings          []string
}

// UpdateBranch runs pr.update under the same per-repo mutex as Merge, so an
// update cannot move a head while a merge of the same repo is between its
// checks and its write. A refusal is a result; an error is an infrastructure fault.
func (m *PRMerger) UpdateBranch(ctx context.Context, req PRUpdateRequest) (res *PRUpdateResult, err error) {
	merge := PRMergeRequest{Repo: req.Repo, Number: req.Number, HeadSHA: req.ExpectedHeadSHA, Policy: req.Policy}
	if err := merge.validate(); err != nil {
		return nil, fmt.Errorf("pr.update needs expected_head_sha: %w", err)
	}
	unlock, err := m.locks.lock(ctx, req.Repo.String())
	if err != nil {
		return nil, err
	}
	defer unlock()

	res = &PRUpdateResult{OldHead: req.ExpectedHeadSHA}
	res.Verdict = PRVerdict{Outcome: PRAllow, Head: req.ExpectedHeadSHA, PolicyVersion: req.Policy.Version}
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

	v := &res.Verdict
	pull, err := m.gh.GetPull(ctx, read, req.Repo, req.Number)
	switch {
	case errors.Is(err, gh.ErrNotFound):
		v.add("pr_exists", false, "no such pull request")
		v.refuse("")
		return res, nil
	case err != nil:
		return nil, fmt.Errorf("pr.update: read PR: %w", err)
	}
	// Same state checks as merge step 2, except that a draft may be updated and
	// "mergeable" does not matter (a conflict is exactly why one would update).
	for _, c := range pullChecks("", pull, merge) {
		if c.Name != "pr_not_draft" && c.Name != "mergeable" {
			v.Checks = append(v.Checks, c)
		}
	}
	if v.failed() {
		v.refuse("")
		return res, nil
	}
	cmp, err := m.gh.Compare(ctx, read, req.Repo, req.Policy.Base, req.ExpectedHeadSHA)
	if err != nil {
		return nil, fmt.Errorf("pr.update: compare: %w", err)
	}
	v.add("branch_behind", cmp.BehindBy > 0, "head is already up to date with "+req.Policy.Base)
	if v.failed() {
		v.refuse("")
		return res, nil
	}

	write, err := m.tokens.Mint(ctx, req.Repo, gh.PermsPush())
	if err != nil {
		return nil, err
	}
	msg, updErr := m.gh.UpdatePullBranch(ctx, write, req.Repo, req.Number, req.ExpectedHeadSHA)
	if rerr := m.revoke(ctx, write); rerr != nil {
		res.Warnings = append(res.Warnings, "write token: "+rerr.Error())
	} else {
		res.WriteTokenRevoked = true
	}
	if updErr != nil {
		var api *gh.APIError
		if errors.As(updErr, &api) && api.RateLimit == nil &&
			(api.Status == http.StatusUnprocessableEntity || api.Status == http.StatusConflict) {
			v.add("update_write", false, fmt.Sprintf("GitHub refused the update (%d): %s", api.Status, api.Detail()))
			v.refuse(StopCIStale)
			return res, nil
		}
		return nil, fmt.Errorf("pr.update: %w", updErr)
	}
	res.Updated, res.Message = true, clip(untrusted.Line(msg), 300)
	v.add("update_write", true, "")
	res.NewHead = res.OldHead
	res.ExternalRef = safeURL(pull.HTMLURL, 300)
	if after, rerr := m.readBack(ctx, read, merge); rerr == nil {
		res.NewHead = after.Head.SHA
		if res.ExternalRef == "" {
			res.ExternalRef = safeURL(after.HTMLURL, 300)
		}
	} else {
		res.Warnings = append(res.Warnings, "read-back after update: "+strings.TrimSpace(rerr.Error()))
	}
	return res, nil
}
