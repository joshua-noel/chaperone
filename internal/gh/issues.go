package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Issue is the part of an issue the issue ops read. GitHub's issues endpoints
// also answer for pull requests; PullRequest is non-nil for those.
type Issue struct {
	Number      int          `json:"number"`
	State       string       `json:"state"` // "open" or "closed"
	Title       string       `json:"title"`
	HTMLURL     string       `json:"html_url"`
	Labels      []IssueLabel `json:"labels"`
	PullRequest *struct{}    `json:"pull_request"`
}

// IssueLabel is one label of an issue.
type IssueLabel struct {
	Name string `json:"name"`
}

// HasLabel reports whether the issue carries the label (exact name).
func (i *Issue) HasLabel(name string) bool {
	for _, l := range i.Labels {
		if l.Name == name {
			return true
		}
	}
	return false
}

// IssueComment is a comment GitHub created.
type IssueComment struct {
	ID      int64  `json:"id"`
	HTMLURL string `json:"html_url"`
}

// NewIssue is a request to open an issue.
type NewIssue struct {
	Title  string
	Body   string
	Labels []string
}

func validIssue(repo Repo, number int) error {
	if err := repo.validate(); err != nil {
		return err
	}
	if number <= 0 {
		return fmt.Errorf("%w: issue number %d", ErrInvalidArgument, number)
	}
	return nil
}

func issuePath(repo Repo, number int, rest string) string {
	return repo.path("/issues/" + strconv.Itoa(number) + rest)
}

// GetIssue reads one issue (GET /issues/{n}).
func (c *Client) GetIssue(ctx context.Context, tok *Token, repo Repo, number int) (*Issue, error) {
	if err := validIssue(repo, number); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var i Issue
	if err := c.do(ctx, call{method: http.MethodGet, path: issuePath(repo, number, ""), secret: secret}, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

// CreateIssue opens an issue (POST /issues).
func (c *Client) CreateIssue(ctx context.Context, tok *Token, repo Repo, in NewIssue) (*Issue, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Title) == "" || !utf8.ValidString(in.Title) {
		return nil, fmt.Errorf("%w: title", ErrInvalidArgument)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"title": in.Title}
	if in.Body != "" {
		body["body"] = in.Body
	}
	if len(in.Labels) > 0 {
		body["labels"] = in.Labels
	}
	var i Issue
	if err := c.do(ctx, call{method: http.MethodPost, path: repo.path("/issues"), body: body, secret: secret}, &i); err != nil {
		return nil, err
	}
	if i.Number == 0 {
		return nil, errors.New("gh: create issue answered without a number")
	}
	return &i, nil
}

// CreateIssueComment adds a comment to an issue (POST /issues/{n}/comments).
func (c *Client) CreateIssueComment(ctx context.Context, tok *Token, repo Repo, number int, text string) (*IssueComment, error) {
	if err := validIssue(repo, number); err != nil {
		return nil, err
	}
	if strings.TrimSpace(text) == "" || !utf8.ValidString(text) {
		return nil, fmt.Errorf("%w: comment body", ErrInvalidArgument)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var cm IssueComment
	if err := c.do(ctx, call{method: http.MethodPost, path: issuePath(repo, number, "/comments"), body: map[string]any{"body": text}, secret: secret}, &cm); err != nil {
		return nil, err
	}
	if cm.ID == 0 {
		return nil, errors.New("gh: create comment answered without an id")
	}
	return &cm, nil
}

// ReopenIssue sets an issue to open (PATCH /issues/{n}, state_reason
// "reopened"). It touches nothing else of the issue.
func (c *Client) ReopenIssue(ctx context.Context, tok *Token, repo Repo, number int) (*Issue, error) {
	if err := validIssue(repo, number); err != nil {
		return nil, err
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	var i Issue
	body := map[string]any{"state": "open", "state_reason": "reopened"}
	if err := c.do(ctx, call{method: http.MethodPatch, path: issuePath(repo, number, ""), body: body, secret: secret}, &i); err != nil {
		return nil, err
	}
	return &i, nil
}
