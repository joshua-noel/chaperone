package google

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// Limits of one message.
const (
	MaxRecipients      = 10
	MaxSubjectBytes    = 200
	MaxBodyBytes       = 64 << 10
	MaxAttachments     = 5
	MaxAttachmentBytes = 5 << 20
	MaxTotalAttachment = 10 << 20

	googleAdapter = "google"
)

var (
	attNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// executableExt are the file types Gmail itself refuses to deliver. Refusing
	// them here means no card is made for a message that cannot be sent.
	executableExt = []string{".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".jar", ".dll", ".lnk", ".cpl", ".hta", ".reg"}
)

// ErrNoAttachment: the content store has nothing under that SHA-256.
var ErrNoAttachment = errors.New("google: no staged attachment with that SHA-256")

// AttachmentStore resolves an attachment by the SHA-256 of its content. The
// content is staged by chapd, never by the agent's path: the agent names the
// hash, the adapter fetches the bytes and checks them against it, so nothing
// an agent says can make Chaperone read another file.
type AttachmentStore interface {
	Get(sha256hex string) ([]byte, error)
}

// DirStore is an [AttachmentStore] over a folder of files named by their
// lower-case hex SHA-256 (no extension). chapd's staging command writes them.
type DirStore struct{ Dir string }

// Get implements AttachmentStore.
func (d DirStore) Get(sum string) ([]byte, error) {
	if !sha256RE.MatchString(sum) {
		return nil, ErrNoAttachment
	}
	p := filepath.Join(d.Dir, sum)
	st, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoAttachment
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxAttachmentBytes {
		return nil, fmt.Errorf("google: staged attachment %s is not a regular file of at most %d bytes", sum[:12], MaxAttachmentBytes)
	}
	return os.ReadFile(p)
}

// PolicyFunc returns the project's `google:` block, or nil when it has none
// (then both ops refuse the project).
type PolicyFunc func(project string) *policy.Google

// GmailConfig builds the `mail.send` [ops.Adapter].
type GmailConfig struct {
	Source      *Source
	Policy      PolicyFunc
	Attachments AttachmentStore // nil: attachments are refused
	Redactor    Redactor        // nil: no secret scan (tests only)
	Endpoints   Endpoints
	HTTP        *http.Client
}

// Gmail is the `mail.send` adapter.
type Gmail struct {
	cfg GmailConfig
	api *apiClient
}

var _ ops.Adapter = (*Gmail)(nil)

// NewGmail returns the adapter.
func NewGmail(cfg GmailConfig) (*Gmail, error) {
	if cfg.Source == nil || cfg.Policy == nil {
		return nil, errors.New("google: mail.send needs a token source and a policy")
	}
	if cfg.Redactor == nil {
		return nil, errors.New("google: mail.send needs a redactor")
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	return &Gmail{cfg: cfg, api: &apiClient{hc: cfg.HTTP, src: cfg.Source}}, nil
}

// prepared is one validated message and its rendering.
type prepared struct {
	msg      Message
	account  string
	project  string
	mime     []byte
	sha      string
	atts     []Attachment
	attBytes int
}

func (g *Gmail) prepare(ctx context.Context, r *ops.Request) (*prepared, error) {
	if r.Target.Adapter != googleAdapter {
		return nil, paramsInvalid("target adapter must be %s", googleAdapter)
	}
	account := r.Target.Ref
	if err := checkAddress(account); err != nil {
		return nil, paramsInvalid("target ref must be the sending account's address: %v", err)
	}
	if err := onlyParams(r.Params, "to", "cc", "bcc", "subject", "body", "attachments"); err != nil {
		return nil, err
	}
	var rec [3][]string
	for i, k := range []string{"to", "cc", "bcc"} {
		l, err := paramStrings(r.Params, k)
		if err != nil {
			return nil, err
		}
		rec[i] = l
	}
	to, cc, bcc := rec[0], rec[1], rec[2]
	if len(to) == 0 {
		return nil, paramsInvalid("param to needs at least one recipient")
	}
	all := slices.Concat(to, cc, bcc)
	if len(all) > MaxRecipients {
		return nil, paramsInvalid("at most %d recipients in all", MaxRecipients)
	}
	seen := map[string]bool{}
	for _, a := range all {
		if err := checkAddress(a); err != nil {
			return nil, paramsInvalid("recipient: %v", err)
		}
		if seen[a] {
			return nil, paramsInvalid("recipient %s is listed twice", clipText(a, 60))
		}
		seen[a] = true
	}
	subject, err := paramString(r.Params, "subject")
	if err != nil {
		return nil, err
	}
	if err := checkText("subject", subject, false, MaxSubjectBytes); err != nil {
		return nil, err
	}
	if subject != strings.TrimSpace(subject) {
		return nil, paramsInvalid("subject must not start or end with a space")
	}
	body, err := paramString(r.Params, "body")
	if err != nil {
		return nil, err
	}
	if err := checkText("body", body, true, MaxBodyBytes); err != nil {
		return nil, err
	}

	// The allowlist comes before everything that costs anything, and before a
	// card can exist.
	pol := g.cfg.Policy(r.Project)
	if pol == nil || len(pol.Mail.AllowRecipients) == 0 {
		return nil, policyRefused("mail.send is refused for project %s: its policy file has no google.mail.allow_recipients", r.Project)
	}
	if bad := refuseUnlisted(pol.Mail.AllowRecipients, all); len(bad) > 0 {
		return nil, policyRefused("recipient not on the allowlist of project %s: %s", r.Project, clipText(strings.Join(bad, ", "), 200))
	}

	if err := scan(g.cfg.Redactor, "the subject", subject); err != nil {
		return nil, err
	}
	if err := scan(g.cfg.Redactor, "the body", body); err != nil {
		return nil, err
	}
	atts, total, err := g.attachments(r.Params["attachments"])
	if err != nil {
		return nil, err
	}

	st := g.cfg.Source.Status(ctx)
	if p := st.Problem(g.cfg.Source.cfg.Now()); p != "" {
		return nil, policyRefused("%s", p)
	}
	if st.Account != account {
		return nil, policyRefused("the request is for account %s but Chaperone is connected as %s", clipText(account, 60), clipText(st.Account, 60))
	}
	if !slices.Contains(st.Scopes, ScopeGmailSend) {
		return nil, policyRefused("the saved Google sign-in has no gmail.send scope; run `chapd connect google` again")
	}

	msg := Message{From: account, To: to, Cc: cc, Bcc: bcc, Subject: subject, Body: body, Attachments: atts, Boundary: r.ID}
	raw := msg.Render()
	return &prepared{msg: msg, account: account, project: r.Project, mime: raw, sha: SumHex(raw), atts: atts, attBytes: total}, nil
}

// attachments resolves the attachments param: a list of {name, sha256}. The
// bytes come from the store and must hash to the stated SHA-256 (so a store
// that was changed after the card is caught); each is scanned for secrets.
func (g *Gmail) attachments(v any) ([]Attachment, int, error) {
	if v == nil {
		return nil, 0, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, 0, paramsInvalid("param attachments must be a list of {name, sha256}")
	}
	if len(list) == 0 {
		return nil, 0, nil
	}
	if len(list) > MaxAttachments {
		return nil, 0, paramsInvalid("at most %d attachments", MaxAttachments)
	}
	if g.cfg.Attachments == nil {
		return nil, 0, paramsInvalid("this build has no attachment store; send without attachments")
	}
	var out []Attachment
	var total int
	names := map[string]bool{}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, 0, paramsInvalid("each attachment must be {name, sha256}")
		}
		if err := onlyParams(m, "name", "sha256"); err != nil {
			return nil, 0, err
		}
		name, err := paramString(m, "name")
		if err != nil {
			return nil, 0, err
		}
		sum, err := paramString(m, "sha256")
		if err != nil {
			return nil, 0, err
		}
		if !attNameRE.MatchString(name) || strings.HasSuffix(name, " ") || strings.Contains(name, "..") {
			return nil, 0, paramsInvalid("attachment name %q must be plain letters, digits, space, dot, dash or underscore", clipText(name, 60))
		}
		if slices.Contains(executableExt, strings.ToLower(filepath.Ext(name))) {
			return nil, 0, paramsInvalid("attachment %s is an executable type that Gmail refuses", clipText(name, 60))
		}
		if names[strings.ToLower(name)] {
			return nil, 0, paramsInvalid("attachment name %s is used twice", clipText(name, 60))
		}
		names[strings.ToLower(name)] = true
		if !sha256RE.MatchString(sum) {
			return nil, 0, paramsInvalid("attachment %s: sha256 must be 64 lower-case hex characters", clipText(name, 60))
		}
		if err := scan(g.cfg.Redactor, "attachment name "+clipText(name, 40), name); err != nil {
			return nil, 0, err
		}
		data, err := g.cfg.Attachments.Get(sum)
		if errors.Is(err, ErrNoAttachment) {
			return nil, 0, paramsInvalid("attachment %s: no staged file has SHA-256 %s", clipText(name, 60), sum)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("google: read attachment %s: %w", clipText(name, 60), err)
		}
		if SumHex(data) != sum {
			return nil, 0, paramsInvalid("attachment %s: the staged file does not match SHA-256 %s", clipText(name, 60), sum)
		}
		total += len(data)
		if len(data) > MaxAttachmentBytes || total > MaxTotalAttachment {
			return nil, 0, paramsInvalid("attachments are too large (at most %d bytes each, %d in all)", MaxAttachmentBytes, MaxTotalAttachment)
		}
		if g.cfg.Redactor != nil {
			if _, res := g.cfg.Redactor.RedactBytes(data); res.Blocked() {
				return nil, 0, redactionBlocked("attachment "+clipText(name, 40), res)
			}
		}
		out = append(out, Attachment{Name: name, Data: data, SHA256: sum})
	}
	return out, total, nil
}

// Check validates the request and renders the message; it sends nothing.
func (g *Gmail) Check(ctx context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := g.prepare(ctx, r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	n := len(p.msg.To) + len(p.msg.Cc) + len(p.msg.Bcc)
	return ops.CheckResult{
		Checks: []ops.Check{
			{Name: "recipients_allowlisted", Passed: true, Detail: fmt.Sprintf("%d of %d on the allowlist of project %s", n, n, p.project)},
			{Name: "no_secret_in_message", Passed: true},
			{Name: "attachments_match_sha256", Passed: true, Detail: fmt.Sprintf("%d attachment(s)", len(p.atts))},
			{Name: "google_connected", Passed: true, Detail: "gmail.send as " + p.account},
		},
		Evidence: []ops.Evidence{{Name: "mail.send message", Text: p.evidence()}},
	}, nil
}

func (p *prepared) evidence() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Sent as: %s (Gmail API, scope gmail.send)\n", p.account)
	fmt.Fprintf(&b, "Rendered message: %d bytes, SHA-256 %s\n", len(p.mime), p.sha)
	fmt.Fprintf(&b, "Every recipient is on the allowlist of project %s.\n", p.project)
	if len(p.atts) == 0 {
		b.WriteString("Attachments: none")
	} else {
		b.WriteString("Attachments:")
		for _, a := range p.atts {
			fmt.Fprintf(&b, "\n  %s  %d bytes  SHA-256 %s", a.Name, len(a.Data), a.SHA256)
		}
	}
	return b.String()
}

// Execute sends the message once. It never retries a send whose answer was
// lost: that ends `unconfirmed`.
func (g *Gmail) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := g.prepare(ctx, r)
	if err != nil {
		return ops.Outcome{Failed: true, Result: map[string]any{"error": clipText(err.Error(), 300)}}, nil
	}
	res := map[string]any{
		"account": p.account, "rendered_sha256": p.sha, "rendered_bytes": len(p.mime),
		"recipients": len(p.msg.To) + len(p.msg.Cc) + len(p.msg.Bcc), "attachments": len(p.atts),
	}
	var sent struct {
		ID       string   `json:"id"`
		ThreadID string   `json:"threadId"`
		Labels   []string `json:"labelIds"`
	}
	endpoint := strings.TrimRight(g.cfg.Endpoints.Gmail, "/") + "/gmail/v1/users/me/messages/send?" + url.Values{"alt": {"json"}}.Encode()
	err = g.api.call(ctx, http.MethodPost, endpoint, map[string]string{"raw": base64.RawURLEncoding.EncodeToString(p.mime)}, &sent)
	switch {
	case err == nil:
	case isDefinite(err):
		res["error"] = clipText(err.Error(), 300)
		if errors.Is(err, ErrReauthRequired) {
			res["error"] = "Google no longer accepts the saved sign-in; nothing was sent"
		}
		return ops.Outcome{Failed: true, Result: res}, nil
	default:
		res["error"] = "the send may or may not have happened: " + clipText(err.Error(), 200)
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	if sent.ID == "" {
		res["error"] = "Gmail answered without a message id; check the Sent folder"
		return ops.Outcome{Unconfirmed: true, Result: res}, nil
	}
	res["message_id"], res["thread_id"] = sent.ID, sent.ThreadID
	return ops.Outcome{ExternalRef: "gmail:message/" + clipText(sent.ID, 64), Result: res}, nil
}
