package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

const (

	// MaxShareRecipients is the most people one `drive.share` names.
	MaxShareRecipients = 5
	// LinkRestricted is the only link visibility this connector can produce: a
	// permission for a named person. It never creates "anyone with the link" or
	// a domain-wide permission.
	LinkRestricted = "restricted"
)

var driveIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{10,100}$`)

// DriveConfig builds the `drive.share` [ops.Adapter].
type DriveConfig struct {
	Source    *Source
	Policy    PolicyFunc
	Endpoints Endpoints
	HTTP      *http.Client
}

// Drive is the `drive.share` adapter.
type Drive struct {
	cfg DriveConfig
	api *apiClient
}

var _ ops.Adapter = (*Drive)(nil)

// NewDrive returns the adapter.
func NewDrive(cfg DriveConfig) (*Drive, error) {
	if cfg.Source == nil || cfg.Policy == nil {
		return nil, errors.New("google: drive.share needs a token source and a policy")
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	return &Drive{cfg: cfg, api: &apiClient{hc: cfg.HTTP, src: cfg.Source}}, nil
}

// roleRank orders the roles a share may grant. owner, organizer and
// fileOrganizer are not in it: this connector can never hand over ownership or
// manage a shared drive.
var roleRank = map[string]int{"reader": 1, "commenter": 2, "writer": 3}

type driveFile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MimeType     string `json:"mimeType"`
	Trashed      bool   `json:"trashed"`
	Capabilities struct {
		CanShare bool `json:"canShare"`
	} `json:"capabilities"`
	Owners []struct {
		EmailAddress string `json:"emailAddress"`
	} `json:"owners"`
}

type shareRequest struct {
	project    string
	fileID     string
	fileName   string
	recipients []string
	role       string
	cap        string
	account    string
}

func (d *Drive) parse(ctx context.Context, r *ops.Request) (*shareRequest, error) {
	if r.Target.Adapter != googleAdapter {
		return nil, paramsInvalid("target adapter must be %s", googleAdapter)
	}
	account := r.Target.Ref
	if err := checkAddress(account); err != nil {
		return nil, paramsInvalid("target ref must be the sharing account's address: %v", err)
	}
	if err := onlyParams(r.Params, "file_id", "file_name", "recipients", "role", "link_visibility"); err != nil {
		return nil, err
	}
	fileID, err := paramString(r.Params, "file_id")
	if err != nil {
		return nil, err
	}
	if !driveIDRE.MatchString(fileID) {
		return nil, paramsInvalid("file_id is not a Drive file id")
	}
	fileName, err := paramString(r.Params, "file_name")
	if err != nil {
		return nil, err
	}
	if err := checkText("file_name", fileName, false, 300); err != nil {
		return nil, err
	}
	rcpt, err := paramStrings(r.Params, "recipients")
	if err != nil {
		return nil, err
	}
	if len(rcpt) == 0 || len(rcpt) > MaxShareRecipients {
		return nil, paramsInvalid("recipients needs 1 to %d addresses", MaxShareRecipients)
	}
	seen := map[string]bool{}
	for _, a := range rcpt {
		if err := checkAddress(a); err != nil {
			return nil, paramsInvalid("recipient: %v", err)
		}
		if seen[a] {
			return nil, paramsInvalid("recipient %s is listed twice", clipText(a, 60))
		}
		seen[a] = true
	}
	role, err := paramString(r.Params, "role")
	if err != nil {
		return nil, err
	}
	if _, ok := roleRank[role]; !ok {
		return nil, paramsInvalid("role must be one of %v (never owner or organizer)", policy.GoogleRoles)
	}
	// link_visibility is required so that the card always says it.
	vis, err := paramString(r.Params, "link_visibility")
	if err != nil {
		return nil, err
	}
	if vis != LinkRestricted {
		return nil, paramsInvalid("link_visibility must be %q: Chaperone shares with named people only, never with anyone who has the link", LinkRestricted)
	}

	pol := d.cfg.Policy(r.Project)
	if pol == nil || len(pol.Drive.AllowRecipients) == 0 {
		return nil, policyRefused("drive.share is refused for project %s: its policy file has no google.drive.allow_recipients", r.Project)
	}
	if bad := refuseUnlisted(pol.Drive.AllowRecipients, rcpt); len(bad) > 0 {
		return nil, policyRefused("recipient not on the Drive allowlist of project %s: %s", r.Project, clipText(strings.Join(bad, ", "), 200))
	}
	capRole := pol.Drive.MaxRole
	if capRole == "" {
		capRole = "reader"
	}
	if roleRank[role] > roleRank[capRole] {
		return nil, policyRefused("role %s is above the cap of project %s (%s)", role, r.Project, capRole)
	}

	st := d.cfg.Source.Status(ctx)
	if p := st.Problem(d.cfg.Source.cfg.Now()); p != "" {
		return nil, policyRefused("%s", p)
	}
	if st.Account != account {
		return nil, policyRefused("the request is for account %s but Chaperone is connected as %s", clipText(account, 60), clipText(st.Account, 60))
	}
	if !slices.Contains(st.Scopes, ScopeDrive) {
		return nil, policyRefused("the saved Google sign-in has no Drive scope; run `chapd connect google -drive`")
	}
	return &shareRequest{project: r.Project, fileID: fileID, fileName: fileName, recipients: rcpt, role: role, cap: capRole, account: account}, nil
}

func (d *Drive) url(path string, q url.Values) string {
	u := strings.TrimRight(d.cfg.Endpoints.Drive, "/") + "/drive/v3" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// lookup reads the file and refuses a share the file does not allow: the name
// the agent gave must be the name Drive has (the card shows the agent's text,
// so it must be true), the file must not be in the bin, and the account must be
// allowed to share it.
func (d *Drive) lookup(ctx context.Context, s *shareRequest) (*driveFile, error) {
	var f driveFile
	err := d.api.call(ctx, http.MethodGet, d.url("/files/"+url.PathEscape(s.fileID), url.Values{
		"fields": {"id,name,mimeType,trashed,capabilities(canShare),owners(emailAddress)"}, "supportsAllDrives": {"true"},
	}), nil, &f)
	var ae *APIError
	switch {
	case errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusForbidden):
		return nil, paramsInvalid("Drive has no file %s that this account can see", clipText(s.fileID, 40))
	case err != nil:
		return nil, fmt.Errorf("google: read the Drive file: %w", err)
	}
	switch {
	case f.ID != s.fileID:
		return nil, paramsInvalid("Drive answered for another file")
	case f.Trashed:
		return nil, paramsInvalid("the file is in the bin")
	case !f.Capabilities.CanShare:
		return nil, policyRefused("this account may not share that file")
	case f.Name != s.fileName:
		return nil, paramsInvalid("file_name %q is not the file's name in Drive (%q)", clipText(s.fileName, 80), clipText(f.Name, 80))
	}
	return &f, nil
}

// Check validates the request and reads the file; it changes nothing.
func (d *Drive) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	s, err := d.parse(ctx, r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	f, err := d.lookup(ctx, s)
	if err != nil {
		return ops.CheckResult{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Shared as: %s (Drive API)\n", s.account)
	fmt.Fprintf(&b, "File in Drive: %s (%s, id %s)\n", f.Name, f.MimeType, f.ID)
	fmt.Fprintf(&b, "Role: %s (the cap for project %s is %s)\n", s.role, s.project, s.cap)
	b.WriteString("Link visibility: restricted: named people only; no link and no domain sharing\n")
	b.WriteString("No notification e-mail is sent; the file appears under \"Shared with me\"")
	return ops.CheckResult{
		Checks: []ops.Check{
			{Name: "recipients_allowlisted", Passed: true, Detail: fmt.Sprintf("%d of %d on the Drive allowlist of project %s", len(s.recipients), len(s.recipients), s.project)},
			{Name: "role_within_cap", Passed: true, Detail: s.role + " <= " + s.cap},
			{Name: "file_name_matches_drive", Passed: true},
			{Name: "google_connected", Passed: true, Detail: "drive scope as " + s.account},
		},
		Evidence: []ops.Evidence{{Name: "drive.share file", Text: b.String()}},
	}, nil
}

// Execute creates one permission per recipient. A permission for the same
// person is replaced by Drive, so a retry after a crash is harmless.
func (d *Drive) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	s, err := d.parse(ctx, r)
	if err == nil {
		_, err = d.lookup(ctx, s)
	}
	if err != nil {
		return ops.Outcome{Failed: true, Result: map[string]any{"error": clipText(err.Error(), 300)}}, nil
	}
	res := map[string]any{"file_id": s.fileID, "role": s.role}
	var done []string
	for _, rc := range s.recipients {
		var perm struct {
			ID string `json:"id"`
		}
		err := d.api.call(ctx, http.MethodPost, d.url("/files/"+url.PathEscape(s.fileID)+"/permissions", url.Values{
			"sendNotificationEmail": {"false"}, "supportsAllDrives": {"true"}, "fields": {"id"},
		}), map[string]string{"type": "user", "role": s.role, "emailAddress": rc}, &perm)
		switch {
		case err == nil:
			done = append(done, rc)
			res["shared_with"] = slices.Clone(done)
		case isDefinite(err):
			res["error"] = fmt.Sprintf("sharing with %s was refused: %s", rc, clipText(err.Error(), 200))
			return ops.Outcome{Failed: true, Result: res}, nil
		default:
			res["error"] = fmt.Sprintf("sharing with %s may or may not have happened: %s", rc, clipText(err.Error(), 200))
			return ops.Outcome{Unconfirmed: true, Result: res}, nil
		}
	}
	return ops.Outcome{ExternalRef: "gdrive:file/" + clipText(s.fileID, 100), Result: res}, nil
}
