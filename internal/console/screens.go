package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/vault"
	"github.com/joshua-noel/chaperone/web"
)

// The console screens (ticket L1-20): Home, Operations catalog, Ledger, Runs
// (with "Revoke orchestrator") and Secrets, on top of the Approvals screen of
// L1-12. Server-rendered html/template pages with htmx for the few actions.
//
// What a screen may show. Metadata only: a secret's id, kind, fingerprint and
// dates (ADR-003 item 4), never a value; a token's fingerprint, never the
// token. Nothing here reads a secret, so the canary test (screens_test.go) can
// assert that none of them can print one.
//
// What a screen may do, and what it asks first:
//
//   - Stop all, Revoke run, Revoke orchestrator take away authority, so the
//     signed-in session is enough (like Deny on the Approvals screen); the
//     browser asks "are you sure" first.
//   - Secret import and rotation add authority. They are the critical-class op
//     secrets.write: the value is held in memory while the card is decided and
//     is stored only after a fresh Windows Hello assertion approved that exact
//     request (screens_secrets.go).
//
// Screens are off until [Console.UseScreens] is called, after
// [Console.UseApprovals].

// RunsAdmin is the run registry as the console uses it. *runtoken.Runs is one.
type RunsAdmin interface {
	List(ctx context.Context, state string, limit int, afterRunID string) ([]runtoken.RunRecord, string, error)
	Get(ctx context.Context, runID string) (runtoken.RunRecord, error)
	Revoke(ctx context.Context, runID, stop string) error
	RevokeAll(ctx context.Context, stop string) (int, error)
}

// OrchAdmin is the orchestrator token registry as the console uses it.
// *runtoken.Orchestrators is one.
type OrchAdmin interface {
	List(ctx context.Context) ([]runtoken.OrchInfo, error)
	Revoke(ctx context.Context, id, by string) error
}

// LedgerView reads and verifies the ledger. *ledger.Ledger is one.
type LedgerView interface {
	Chain() string
	Head(ctx context.Context) (seq int64, hash string, err error)
	Query(ctx context.Context, p ledger.QueryParams) ([]spec.Event, error)
	Verify(ctx context.Context, againstExport bool) (ledger.Report, error)
}

// PolicyView is the op catalog and the policy in force. *policy.Engine is one.
type PolicyView interface {
	Catalog() *policy.Catalog
	Baseline() *policy.Pack
	For(project string) *policy.Effective
}

// VaultAdmin lists, imports and rotates secrets. *vault.Vault is one. No
// method returns a value.
type VaultAdmin interface {
	List(ctx context.Context) ([]vault.Info, error)
	Import(ctx context.Context, m vault.Meta, value []byte) (vault.Info, error)
	Rotate(ctx context.Context, id string, value []byte) (vault.Info, error)
}

// ScreensConfig configures [Console.UseScreens].
type ScreensConfig struct {
	// Version is chapd's version, shown on Home.
	Version string

	Runs   RunsAdmin  // required
	Orch   OrchAdmin  // required
	Ledger LedgerView // required
	Policy PolicyView // required

	// Vault turns on secret import and rotation. Nil: the Secrets screen says
	// the vault is not configured and has no form.
	Vault VaultAdmin
	// Record appends the operator's secrets.write events (op.request,
	// op.result) inside the caller's transaction. Required with Vault.
	Record approvals.Ledger

	// Projects names projects to list on the catalog even before they have
	// made a request. Projects that appear in ops or runs are listed anyway.
	Projects []string
}

// operatorID is the orchestrator id the console uses for what the operator
// asks for himself (the same one chapd records for approvers.enroll).
const operatorID = "operator"

type screens struct {
	c     *Console
	cfg   ScreensConfig
	pages map[string]*template.Template
	frag  *template.Template
	pend  *pendingSecrets
}

// UseScreens turns on the L1-20 screens and the routes behind them. Call it
// after [Console.UseApprovals] and before [Console.Handler].
func (c *Console) UseScreens(cfg ScreensConfig) error {
	switch {
	case c.appr == nil:
		return errors.New("console: UseScreens needs UseApprovals first")
	case cfg.Runs == nil || cfg.Orch == nil || cfg.Ledger == nil || cfg.Policy == nil:
		return errors.New("console: UseScreens needs Runs, Orch, Ledger and Policy")
	case cfg.Vault != nil && cfg.Record == nil:
		return errors.New("console: UseScreens: Vault needs Record (secret writes are ledgered)")
	}
	s := &screens{c: c, cfg: cfg, pages: map[string]*template.Template{}, pend: newPendingSecrets(c.now)}
	for _, name := range []string{"dashboard", "catalog", "ledger", "runs", "secrets"} {
		t, err := newTemplate().ParseFS(web.Templates(), "layout.html", "fragments.html", name+".html")
		if err != nil {
			return fmt.Errorf("console: parse template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	frag, err := newTemplate().ParseFS(web.Templates(), "fragments.html")
	if err != nil {
		return fmt.Errorf("console: parse fragments: %w", err)
	}
	s.frag = frag
	c.scr = s
	return nil
}

func (c *Console) screenRoutes(mux *http.ServeMux) {
	s := c.scr
	if s == nil {
		return
	}
	mux.HandleFunc("GET /catalog", s.catalogPage)
	mux.HandleFunc("GET /ledger", s.ledgerPage)
	mux.HandleFunc("POST /ledger/verify", s.ledgerVerify)
	mux.HandleFunc("GET /runs", s.runsPage)
	mux.HandleFunc("POST /runs/{id}/revoke", s.runRevoke)
	mux.HandleFunc("POST /stop-all", s.stopAll)
	mux.HandleFunc("POST /orchestrators/{id}/revoke", s.orchRevoke)
	mux.HandleFunc("GET /secrets", s.secretsPage)
	mux.HandleFunc("POST /secrets/request", s.secretRequest)
	mux.HandleFunc("POST /secrets/{id}/commit", s.secretCommit)
	mux.HandleFunc("POST /secrets/{id}/cancel", s.secretCancel)
}

// ---- shared plumbing ----

// shell is what layout.html needs from every page.
type shell struct {
	Title, CSRF, Origin, Approver string
	Framed                        bool // see Console.framed: no header, no nav
	// Restricted: the page is a read-only view (see Console.restricted): it draws no enabled state-changing control, so a
	// template puts every write section (a form, a POST button) in {{if not .Restricted}}. Legacy: the browser sent no
	// Sec-Fetch-Site, so the note cannot offer a way out.
	Restricted, Legacy bool
}

func (s *screens) shell(st *reqState, title string) shell {
	return shell{Title: title, CSRF: s.c.csrfToken(st), Origin: st.rp.URL, Approver: st.user.Name, Framed: st.framed,
		Restricted: st.restricted, Legacy: st.legacy}
}

// user returns the request's signed-in approver. A signed-out GET is sent to
// the sign-in page; a signed-out POST (an htmx call) is answered 401 with
// HX-Redirect so the browser leaves the page.
func (s *screens) user(w http.ResponseWriter, r *http.Request) (*reqState, bool) {
	st := stateOf(r)
	if st.user != nil {
		return st, true
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	w.Header().Set("HX-Redirect", "/login")
	http.Error(w, "signed out", http.StatusUnauthorized)
	return nil, false
}

func (s *screens) fail(w http.ResponseWriter, what string, err error) {
	s.c.log.Error(what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// page renders a full page into a buffer first so a template error is a clean
// 500 and never half a page.
func (s *screens) page(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		s.fail(w, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// fragment renders one named template (an htmx response).
func (s *screens) fragment(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.frag.ExecuteTemplate(&buf, name, data); err != nil {
		s.fail(w, "render fragment "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// notice is the small status box ("notice" in fragments.html).
type notice struct {
	Bad         bool
	Title, Text string
}

func (s *screens) say(w http.ResponseWriter, status int, title, text string) {
	s.fragment(w, status, "notice", notice{Bad: status >= 400, Title: title, Text: text})
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func unixStamp(sec int64) string { return stamp(time.Unix(sec, 0)) }

// eventTime parses an event's time_unix_nano.
func eventTime(e spec.Event) time.Time {
	n, err := strconv.ParseInt(e.TimeUnixNano, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func attrString(e spec.Event, key string) string {
	if v, ok := e.Attributes[key].(string); ok {
		return v
	}
	return ""
}

func bodyOf(e spec.Event) string {
	if e.Body == nil {
		return ""
	}
	return *e.Body
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}

// Ledger paging for the screens: events come oldest first from the ledger, the
// screens want the newest, so look at the newest window of the chain and widen
// it until enough matches are found or the cap is reached.
const (
	pageEvents    = 1000
	maxEventsSeen = 128000
)

// newestEvents returns up to n events matching p (and keep, when set), newest
// first. truncated is true when fewer than n were found and older events were
// not searched because of the cap.
func (s *screens) newestEvents(ctx context.Context, p ledger.QueryParams, n int, keep func(spec.Event) bool) (out []spec.Event, truncated bool, err error) {
	head, _, err := s.cfg.Ledger.Head(ctx)
	if err != nil {
		return nil, false, err
	}
	if head < 0 {
		return nil, false, nil
	}
	for window := int64(pageEvents); ; window *= 4 {
		from := head - window
		if from < -1 {
			from = -1
		}
		out = out[:0]
		after := from
		for {
			q := p
			q.AfterSeq, q.Limit = &after, pageEvents
			evs, err := s.cfg.Ledger.Query(ctx, q)
			if err != nil {
				return nil, false, err
			}
			for _, e := range evs {
				if keep == nil || keep(e) {
					out = append(out, e)
				}
			}
			if len(evs) < pageEvents {
				break
			}
			after = evs[len(evs)-1].Seq
		}
		if len(out) >= n || from == -1 {
			break
		}
		if window >= maxEventsSeen {
			truncated = true
			break
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, truncated, nil
}

// knownProjects lists the projects the console has heard of: configured ones,
// and any that appear in the ops, runs or approvals tables.
func (s *screens) knownProjects(ctx context.Context) ([]string, error) {
	set := map[string]bool{}
	for _, p := range s.cfg.Projects {
		set[p] = true
	}
	for _, table := range []string{"ops", "runs", "approvals"} {
		rows, err := s.c.db.SQL().QueryContext(ctx, `SELECT DISTINCT project FROM `+table)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return nil, err
			}
			set[p] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	out := make([]string, 0, len(set))
	for p := range set {
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// join renders a list for a table cell.
func join(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	return strings.Join(list, ", ")
}
