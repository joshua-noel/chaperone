package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Installation is an App installation on an account.
type Installation struct {
	ID      int64
	AppID   int64
	Account string // login of the account that installed the App
}

// FindInstallation returns the App's installation on repo (App JWT auth).
func (c *Client) FindInstallation(ctx context.Context, repo Repo) (Installation, error) {
	if err := repo.validate(); err != nil {
		return Installation{}, err
	}
	jwt, err := c.asApp(ctx)
	if err != nil {
		return Installation{}, err
	}
	var out struct {
		ID      int64 `json:"id"`
		AppID   int64 `json:"app_id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := c.do(ctx, call{method: http.MethodGet, path: repo.path("/installation"), secret: jwt}, &out); err != nil {
		return Installation{}, err
	}
	return Installation{ID: out.ID, AppID: out.AppID, Account: out.Account.Login}, nil
}

// Permission levels GitHub accepts in a token request.
const (
	Read  = "read"
	Write = "write"
	Admin = "admin"
)

// The permission sets of ADR-002 decision item 1, one per use. Each call
// returns a fresh map. None includes `workflows`: Phase 1 never mints it.
func PermsEvaluateMerge() map[string]string {
	return map[string]string{"pull_requests": Read, "checks": Read, "contents": Read, "metadata": Read}
}

// PermsOpenPull is what pr.open needs: GitHub checks head and base with the
// token, and a token without contents:read cannot read them, so POST /pulls
// answers 422 "not all refs are readable" (seen live, first the runner runs 25 Oct).
func PermsOpenPull() map[string]string {
	return map[string]string{"pull_requests": Write, "contents": Read, "metadata": Read}
}
func PermsFetch() map[string]string { return map[string]string{"contents": Read} }
func PermsPush() map[string]string {
	return map[string]string{"contents": Write, "pull_requests": Write, "metadata": Read}
}
func PermsMerge() map[string]string { return PermsPush() }

// PermsDeployRead is what deploy reads before it records anything: the commit and its checks.
func PermsDeployRead() map[string]string {
	return map[string]string{"contents": Read, "checks": Read, "metadata": Read}
}
func PermsDeploy() map[string]string { return map[string]string{"deployments": Write} }

// PermsIssueRead is what the issue ops need to read the labels of the issue
// they act on (issue.comment and issue.reopen check them before they write).
func PermsIssueRead() map[string]string {
	return map[string]string{"issues": Read, "metadata": Read}
}

// PermsIssueWrite is what issue.open, issue.comment and issue.reopen need for
// their one write. It holds no contents or pull_requests permission.
func PermsIssueWrite() map[string]string {
	return map[string]string{"issues": Write, "metadata": Read}
}

// TokenRequest narrows an installation token. Both fields are required: GitHub
// gives a token for every repository and every permission of the installation
// when they are omitted, which is exactly what ADR-002 forbids.
type TokenRequest struct {
	// Repositories are repository names (not "owner/name") in the installation's account.
	Repositories []string
	// Permissions maps a permission name ("contents") to read, write or admin.
	Permissions map[string]string
}

var permNameRE = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

func (r TokenRequest) validate() error {
	if len(r.Repositories) == 0 || len(r.Repositories) > 500 {
		return fmt.Errorf("%w: a token request needs 1-500 repositories", ErrInvalidArgument)
	}
	seen := map[string]bool{}
	for _, n := range r.Repositories {
		if !validName(n) || seen[n] {
			return fmt.Errorf("%w: repository name %q", ErrInvalidArgument, n)
		}
		seen[n] = true
	}
	if len(r.Permissions) == 0 {
		return fmt.Errorf("%w: a token request needs at least one permission", ErrInvalidArgument)
	}
	for k, v := range r.Permissions {
		if !permNameRE.MatchString(k) || level(v) == 0 {
			return fmt.Errorf("%w: permission %q: %q", ErrInvalidArgument, k, v)
		}
	}
	return nil
}

func level(s string) int {
	switch s {
	case Read:
		return 1
	case Write:
		return 2
	case Admin:
		return 3
	}
	return 0
}

// MintToken creates an installation token narrowed to req (POST
// /app/installations/{id}/access_tokens, App JWT auth).
//
// It then checks GitHub's answer: repository_selection must be "selected", every
// repository and permission in the answer must be within the request (GitHub
// adds metadata:read on its own, which is allowed). If the token is broader, it
// is revoked at once and the call fails with [ErrNotNarrowed]; the caller never
// receives it. The token is opaque: no length or prefix is assumed.
func (c *Client) MintToken(ctx context.Context, installationID int64, req TokenRequest) (*Token, error) {
	if installationID <= 0 {
		return nil, fmt.Errorf("%w: installation id", ErrInvalidArgument)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	jwt, err := c.asApp(ctx)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Token               string            `json:"token"`
		ExpiresAt           time.Time         `json:"expires_at"`
		Permissions         map[string]string `json:"permissions"`
		RepositorySelection string            `json:"repository_selection"`
		Repositories        []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}
	err = c.do(ctx, call{
		method: http.MethodPost,
		path:   "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens",
		body:   map[string]any{"repositories": req.Repositories, "permissions": req.Permissions},
		secret: jwt,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Token == "" {
		return nil, errors.New("gh: access_tokens answered without a token")
	}
	tok := newToken(resp.Token, resp.ExpiresAt, req.Repositories, resp.Permissions)
	reject := func(cause error) (*Token, error) {
		revokeErr := c.RevokeToken(ctx, tok)
		tok.Wipe()
		if revokeErr != nil {
			return nil, fmt.Errorf("%w (revoking it also failed: %v)", cause, revokeErr)
		}
		return nil, cause
	}
	if resp.ExpiresAt.IsZero() {
		return reject(errors.New("gh: access_tokens answered without expires_at"))
	}
	if resp.RepositorySelection != "selected" {
		return reject(fmt.Errorf("%w: repository_selection %q", ErrNotNarrowed, resp.RepositorySelection))
	}
	asked := make(map[string]bool, len(req.Repositories))
	for _, n := range req.Repositories {
		asked[n] = true
	}
	granted := make([]string, 0, len(resp.Repositories))
	for _, r := range resp.Repositories {
		if !asked[r.Name] {
			return reject(fmt.Errorf("%w: repository %q", ErrNotNarrowed, r.Name))
		}
		granted = append(granted, r.Name)
	}
	if len(granted) == 0 {
		return reject(fmt.Errorf("%w: answer lists no repositories", ErrNotNarrowed))
	}
	for k, v := range resp.Permissions {
		if k == "metadata" && v == Read {
			continue
		}
		want, ok := req.Permissions[k]
		if !ok || level(v) == 0 || level(v) > level(want) {
			return reject(fmt.Errorf("%w: permission %s:%s", ErrNotNarrowed, k, v))
		}
	}
	tok.Repositories = granted
	return tok, nil
}

// RevokeToken calls DELETE /installation/token with tok itself (204 on success).
// It does not wipe the local copy; call [Token.Wipe] after. A 401 means the
// token was already dead and is returned as [ErrUnauthorized].
func (c *Client) RevokeToken(ctx context.Context, tok *Token) error {
	secret, err := c.asToken(tok)
	if err != nil {
		return err
	}
	return c.do(ctx, call{method: http.MethodDelete, path: "/installation/token", secret: secret}, nil)
}

// PermsReportCI is what ci.report needs: `checks: write` to post the check run, and metadata. An installation that
// was not granted `checks: write` (the operator step of ADR-002 amendment 10) answers the token request with 422,
// and ci.report fails there without posting anything.
func PermsReportCI() map[string]string {
	return map[string]string{"checks": Write, "metadata": Read}
}

// PermsReadPull is what pr.view, pr.diff and pr.files need: read the pull request, nothing more. It holds no
// `contents` permission, so the token cannot read a file or a branch; the diff comes from the pull request endpoint.
func PermsReadPull() map[string]string {
	return map[string]string{"pull_requests": Read, "metadata": Read}
}

// PermsReadPullChecks is what pr.checks needs: the pull request (for its head commit) and the check runs on it.
func PermsReadPullChecks() map[string]string {
	return map[string]string{"pull_requests": Read, "checks": Read, "metadata": Read}
}
