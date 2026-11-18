package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHubActionsAppID is the App ID of GitHub Actions (ADR-002 step 3). Filtering
// check-runs by it stops a commit status or another App from posting a fake
// `verify`.
const GitHubActionsAppID int64 = 15368

// CheckRun is a check run on a commit.
type CheckRun struct {
	ID         int64
	Name       string
	HeadSHA    string
	Status     string // queued, in_progress, completed, ...
	Conclusion string // success, failure, cancelled, skipped, ...; empty until completed
	AppID      int64  // the App that created the run; 0 if GitHub omitted it
	HTMLURL    string
	// StartedAt is when the run started; zero if GitHub omitted it. With ID it
	// orders runs of one name on one commit: the latest run is the one that counts.
	StartedAt time.Time
}

// CheckRunQuery filters [Client.ListCheckRuns].
type CheckRunQuery struct {
	CheckName string // exact name; empty for all names
	AppID     int64  // only runs created by this App; 0 for any
	// All asks for every run of a name; the default is the latest run per name.
	// ADR-002 step 3 (amendment 5) reads them all and picks the latest by StartedAt, then ID.
	All bool
}

// ListCheckRuns lists check runs for a full commit SHA (GET
// /commits/{sha}/check-runs with check_name, app_id and filter). If GitHub
// reports more runs than the page returned, it fails with [ErrListTruncated]
// rather than hand back a partial list.
func (c *Client) ListCheckRuns(ctx context.Context, tok *Token, repo Repo, sha string, q CheckRunQuery) ([]CheckRun, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if err := validSHA(sha); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	v := url.Values{"per_page": {strconv.Itoa(perPage)}, "filter": {"latest"}}
	if q.All {
		v.Set("filter", "all")
	}
	if q.CheckName != "" {
		v.Set("check_name", q.CheckName)
	}
	if q.AppID > 0 {
		v.Set("app_id", strconv.FormatInt(q.AppID, 10))
	}
	var out struct {
		TotalCount int `json:"total_count"`
		CheckRuns  []struct {
			ID         int64     `json:"id"`
			Name       string    `json:"name"`
			HeadSHA    string    `json:"head_sha"`
			Status     string    `json:"status"`
			Conclusion string    `json:"conclusion"`
			HTMLURL    string    `json:"html_url"`
			StartedAt  time.Time `json:"started_at"`
			App        *struct {
				ID int64 `json:"id"`
			} `json:"app"`
		} `json:"check_runs"`
	}
	if err := c.do(ctx, call{method: http.MethodGet, path: repo.path("/commits/" + sha + "/check-runs"), query: v, secret: secret}, &out); err != nil {
		return nil, err
	}
	if out.TotalCount > len(out.CheckRuns) {
		return nil, fmt.Errorf("%w: %d check runs, %d returned", ErrListTruncated, out.TotalCount, len(out.CheckRuns))
	}
	runs := make([]CheckRun, len(out.CheckRuns))
	for i, r := range out.CheckRuns {
		runs[i] = CheckRun{ID: r.ID, Name: r.Name, HeadSHA: r.HeadSHA, Status: r.Status, Conclusion: r.Conclusion, HTMLURL: r.HTMLURL, StartedAt: r.StartedAt}
		if r.App != nil {
			runs[i].AppID = r.App.ID
		}
	}
	return runs, nil
}

// CheckRunRequest is the input of [Client.CreateCheckRun]: a check run that is already finished.
type CheckRunRequest struct {
	Name       string // the check's name, as policy fixes it (for example local-ci)
	HeadSHA    string // the full commit SHA the result is about
	Conclusion string // success or failure: nothing else is ever posted
	Title      string // output title, at most 200 characters
	Summary    string // output summary (Markdown), at most 4000 characters
	DetailsURL string // optional
}

// CreateCheckRun posts a finished check run on a commit (POST /check-runs, status completed). Only a GitHub App can
// create a check run, and GitHub records which one: that is why ADR-002 amendment 10 accepts a check run of
// Chaperone's own App and no commit status (a status has no App behind it, so a person's token could post it).
// Needs `checks: write`.
func (c *Client) CreateCheckRun(ctx context.Context, tok *Token, repo Repo, in CheckRunRequest) (*CheckRun, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if err := validSHA(in.HeadSHA); err != nil {
		return nil, err
	}
	if in.Conclusion != "success" && in.Conclusion != "failure" {
		return nil, fmt.Errorf("%w: check conclusion %q", ErrInvalidArgument, in.Conclusion)
	}
	if n := len([]rune(in.Name)); n < 1 || n > 100 || strings.ContainsAny(in.Name, "\r\n\x00") {
		return nil, fmt.Errorf("%w: check name", ErrInvalidArgument)
	}
	if len([]rune(in.Title)) > 200 || len([]rune(in.Summary)) > 4000 || strings.Contains(in.Title, "\x00") || strings.Contains(in.Summary, "\x00") {
		return nil, fmt.Errorf("%w: check output is too long", ErrInvalidArgument)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"name":       in.Name,
		"head_sha":   in.HeadSHA,
		"status":     "completed",
		"conclusion": in.Conclusion,
		"output":     map[string]string{"title": in.Title, "summary": in.Summary},
	}
	if in.DetailsURL != "" {
		body["details_url"] = in.DetailsURL
	}
	var out struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		HTMLURL    string `json:"html_url"`
		App        *struct {
			ID int64 `json:"id"`
		} `json:"app"`
	}
	if err := c.do(ctx, call{method: http.MethodPost, path: repo.path("/check-runs"), body: body, secret: secret}, &out); err != nil {
		return nil, err
	}
	if out.ID == 0 {
		return nil, errors.New("gh: create check run answered without an id")
	}
	run := &CheckRun{ID: out.ID, Name: out.Name, HeadSHA: out.HeadSHA, Status: out.Status, Conclusion: out.Conclusion, HTMLURL: out.HTMLURL}
	if out.App != nil {
		run.AppID = out.App.ID
	}
	return run, nil
}

// AppNumericID returns the numeric ID of Chaperone's own App, as GitHub reports it for the installation on repo. The
// configured AppID may be the App's client ID (the `iss` of the App JWT accepts both), and a check run's `app.id` is
// the numeric one.
func (c *Client) AppNumericID(ctx context.Context, repo Repo) (int64, error) {
	inst, err := c.FindInstallation(ctx, repo)
	if err != nil {
		return 0, err
	}
	if inst.AppID <= 0 {
		return 0, errors.New("gh: the installation reports no App id")
	}
	return inst.AppID, nil
}
