package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Pull is the part of a pull request ADR-002 reads.
type Pull struct {
	Number         int     `json:"number"`
	State          string  `json:"state"` // "open" or "closed"
	Draft          bool    `json:"draft"`
	Merged         bool    `json:"merged"`
	Mergeable      *bool   `json:"mergeable"` // nil while GitHub computes it
	MergeableState string  `json:"mergeable_state"`
	Title          string  `json:"title"`
	HTMLURL        string  `json:"html_url"`
	MergeCommitSHA string  `json:"merge_commit_sha"`
	Base           PullRef `json:"base"`
	Head           PullRef `json:"head"`

	// What pr.view shows besides the above. GitHub sends them on the same GET; the merge path ignores them.
	Body         string      `json:"body"`
	User         *PullUser   `json:"user"` // nil for a deleted account
	Labels       []PullLabel `json:"labels"`
	CreatedAt    string      `json:"created_at"`
	UpdatedAt    string      `json:"updated_at"`
	ClosedAt     string      `json:"closed_at"`
	MergedAt     string      `json:"merged_at"`
	Commits      int         `json:"commits"`
	Additions    int         `json:"additions"`
	Deletions    int         `json:"deletions"`
	ChangedFiles int         `json:"changed_files"`
}

// PullUser is the author of a pull request.
type PullUser struct {
	Login string `json:"login"`
}

// PullLabel is a label on a pull request.
type PullLabel struct {
	Name string `json:"name"`
}

// PullRef is one side of a pull request.
type PullRef struct {
	Ref  string    `json:"ref"`
	SHA  string    `json:"sha"`
	Repo *PullRepo `json:"repo"` // nil when the head repository was deleted
}

// PullRepo is the repository of a pull request side.
type PullRepo struct {
	FullName string `json:"full_name"`
}

// GetPull reads one pull request (GET /pulls/{n}).
func (c *Client) GetPull(ctx context.Context, tok *Token, repo Repo, number int) (*Pull, error) {
	if err := validPull(repo, number); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var p Pull
	if err := c.do(ctx, call{method: http.MethodGet, path: pullPath(repo, number, ""), secret: secret}, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DiffMediaType is GitHub's media type for a unified diff of a pull request.
const DiffMediaType = "application/vnd.github.diff"

// GetPullDiff reads the whole unified diff of a pull request (GET /pulls/{n} with the diff media type). GitHub
// answers 406 for a diff it will not generate (too many files or lines). The bytes are GitHub's, untrusted text.
func (c *Client) GetPullDiff(ctx context.Context, tok *Token, repo Repo, number int) ([]byte, error) {
	if err := validPull(repo, number); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var diff []byte
	if err := c.do(ctx, call{method: http.MethodGet, path: pullPath(repo, number, ""), secret: secret, accept: DiffMediaType}, &diff); err != nil {
		return nil, err
	}
	return diff, nil
}

// ListPullFilesPage reads one page of the changed files (GET /pulls/{n}/files). page counts from 1; perPage is
// 1 to 100. GitHub lists at most 3000 files, so a page past that is empty.
func (c *Client) ListPullFilesPage(ctx context.Context, tok *Token, repo Repo, number, page, perPage int) ([]PullFile, error) {
	if err := validPull(repo, number); err != nil {
		return nil, err
	}
	if page < 1 || perPage < 1 || perPage > 100 {
		return nil, fmt.Errorf("%w: files page %d of %d", ErrInvalidArgument, page, perPage)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	q := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
	batch := []PullFile{}
	if err := c.do(ctx, call{method: http.MethodGet, path: pullPath(repo, number, "/files"), query: q, secret: secret}, &batch); err != nil {
		return nil, err
	}
	return batch, nil
}

// PullFile is one changed file of a pull request.
type PullFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"` // set for a rename
	Status           string `json:"status"`            // added, removed, modified, renamed, ...
	Additions        int    `json:"additions"`
	Deletions        int    `json:"deletions"`
	Patch            string `json:"patch"` // unified diff; GitHub omits it for a very large or binary file
}

// maxFilePages: GitHub lists at most 3000 files of a pull request.
const maxFilePages = 3000 / perPage

// ListPullFiles lists every changed file (GET /pulls/{n}/files, 100 per page).
// If GitHub's 3000-file cap is reached the list may be incomplete and the call
// fails with [ErrListTruncated], so a path classifier never sees a partial list
// as complete.
func (c *Client) ListPullFiles(ctx context.Context, tok *Token, repo Repo, number int) ([]PullFile, error) {
	if err := validPull(repo, number); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var all []PullFile
	for page := 1; page <= maxFilePages; page++ {
		var batch []PullFile
		q := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		if err := c.do(ctx, call{method: http.MethodGet, path: pullPath(repo, number, "/files"), query: q, secret: secret}, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < perPage {
			return all, nil
		}
	}
	return nil, fmt.Errorf("%w: pull request has %d or more files", ErrListTruncated, len(all))
}

// Comparison is the part of a compare result ADR-002 step 4 needs.
type Comparison struct {
	Status       string // identical, ahead, behind, diverged
	AheadBy      int
	BehindBy     int
	TotalCommits int
	BaseSHA      string // base_commit.sha: what base resolved to
	MergeBaseSHA string
}

// Compare compares base...head (GET /compare/{base}...{head}). base is a branch
// name or SHA; head is normally the exact head SHA. BehindBy > 0 means the head
// lacks commits of the base.
func (c *Client) Compare(ctx context.Context, tok *Token, repo Repo, base, head string) (*Comparison, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if err := validRef(base); err != nil {
		return nil, err
	}
	if err := validRef(head); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var out struct {
		Status       string `json:"status"`
		AheadBy      int    `json:"ahead_by"`
		BehindBy     int    `json:"behind_by"`
		TotalCommits int    `json:"total_commits"`
		BaseCommit   struct {
			SHA string `json:"sha"`
		} `json:"base_commit"`
		MergeBaseCommit struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	path := repo.path("/compare/" + refPath(base) + "..." + refPath(head))
	if err := c.do(ctx, call{method: http.MethodGet, path: path, secret: secret}, &out); err != nil {
		return nil, err
	}
	return &Comparison{Status: out.Status, AheadBy: out.AheadBy, BehindBy: out.BehindBy, TotalCommits: out.TotalCommits,
		BaseSHA: out.BaseCommit.SHA, MergeBaseSHA: out.MergeBaseCommit.SHA}, nil
}

// Merge methods GitHub accepts.
const (
	MergeSquash = "squash"
	MergeMerge  = "merge"
	MergeRebase = "rebase"
)

// MergeRequest is the body of PUT /pulls/{n}/merge. SHA is required: GitHub
// merges only if the pull request head still equals it, and answers 409 if not
// (ADR-002 step 8).
type MergeRequest struct {
	SHA           string // exact head SHA the caller verified
	Method        string // MergeSquash (default), MergeMerge or MergeRebase
	CommitTitle   string
	CommitMessage string
}

// MergeResult is GitHub's answer to a merge.
type MergeResult struct {
	SHA     string `json:"sha"` // merge commit
	Merged  bool   `json:"merged"`
	Message string `json:"message"`
}

// MergePull merges pull number if its head is still req.SHA. A refusal (405:
// not mergeable, checks, base modified; 409: head moved; 422) comes back as an
// *APIError after one request: never retried here, and callers must not loop.
func (c *Client) MergePull(ctx context.Context, tok *Token, repo Repo, number int, req MergeRequest) (*MergeResult, error) {
	if err := validPull(repo, number); err != nil {
		return nil, err
	}
	if err := validSHA(req.SHA); err != nil {
		return nil, fmt.Errorf("merge needs the exact head sha: %w", err)
	}
	method := req.Method
	switch method {
	case "":
		method = MergeSquash
	case MergeSquash, MergeMerge, MergeRebase:
	default:
		return nil, fmt.Errorf("%w: merge method %q", ErrInvalidArgument, req.Method)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]string{"sha": req.SHA, "merge_method": method}
	if req.CommitTitle != "" {
		body["commit_title"] = req.CommitTitle
	}
	if req.CommitMessage != "" {
		body["commit_message"] = req.CommitMessage
	}
	var out MergeResult
	if err := c.do(ctx, call{method: http.MethodPut, path: pullPath(repo, number, "/merge"), body: body, secret: secret}, &out); err != nil {
		return nil, err
	}
	if !out.Merged {
		return nil, fmt.Errorf("gh: merge answered 2xx but merged=false: %s", out.Message)
	}
	return &out, nil
}

// UpdatePullBranch merges the base into the head branch (PUT
// /pulls/{n}/update-branch). expectedHeadSHA is required; GitHub answers 422
// if the head moved. GitHub does the update asynchronously (202): read the pull
// request again for the new head.
func (c *Client) UpdatePullBranch(ctx context.Context, tok *Token, repo Repo, number int, expectedHeadSHA string) (message string, err error) {
	if err := validPull(repo, number); err != nil {
		return "", err
	}
	if err := validSHA(expectedHeadSHA); err != nil {
		return "", fmt.Errorf("update-branch needs expected_head_sha: %w", err)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return "", err
	}
	var out struct {
		Message string `json:"message"`
	}
	err = c.do(ctx, call{method: http.MethodPut, path: pullPath(repo, number, "/update-branch"),
		body: map[string]string{"expected_head_sha": expectedHeadSHA}, secret: secret}, &out)
	return out.Message, err
}

// NewPull is the input of [Client.CreatePull].
type NewPull struct {
	Title string
	Head  string // branch in the same repository
	Base  string
	Body  string
	Draft bool
}

// CreatePull opens a pull request (POST /pulls). Head must be a branch of the
// same repository: "owner:branch" (a fork) is refused.
func (c *Client) CreatePull(ctx context.Context, tok *Token, repo Repo, in NewPull) (*Pull, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Title) == "" {
		return nil, fmt.Errorf("%w: title", ErrInvalidArgument)
	}
	if err := validRef(in.Head); err != nil {
		return nil, err
	}
	if err := validRef(in.Base); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"title": in.Title, "head": in.Head, "base": in.Base, "draft": in.Draft}
	if in.Body != "" {
		body["body"] = in.Body
	}
	var p Pull
	if err := c.do(ctx, call{method: http.MethodPost, path: repo.path("/pulls"), body: body, secret: secret}, &p); err != nil {
		return nil, err
	}
	if p.Number == 0 {
		return nil, errors.New("gh: create pull answered without a number")
	}
	return &p, nil
}

func validPull(repo Repo, number int) error {
	if err := repo.validate(); err != nil {
		return err
	}
	if number <= 0 {
		return fmt.Errorf("%w: pull request number %d", ErrInvalidArgument, number)
	}
	return nil
}

func pullPath(repo Repo, number int, rest string) string {
	return repo.path("/pulls/" + strconv.Itoa(number) + rest)
}
