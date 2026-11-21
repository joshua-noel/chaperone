package console

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/web"
)

var b64 = base64.RawURLEncoding

// relyingParty is one configured origin and its WebAuthn instance.
type relyingParty struct {
	Origin
	host string // URL host, the exact value a Host header must have
	wa   *webauthn.WebAuthn
	// waFramed is wa that also accepts a cross-origin assertion (an approval made in a frame) whose signed topOrigin is
	// one of Config.FrameAncestors. Nil when there are none. Only VerifyAssertion uses it, and only for a cross-origin
	// assertion: sign-in and enrolment never do.
	waFramed *webauthn.WebAuthn
}

// Console is the operator console. Build one with [New]; mount [Console.Handler].
type Console struct {
	db          *store.DB
	rps         map[string]*relyingParty // by URL host
	csrfKey     [32]byte
	pages       map[string]*template.Template
	now         func() time.Time
	emitFn      func(Event)
	authn       Authenticators // Config.Authenticators, never empty
	log         *slog.Logger
	sessionIdle time.Duration
	sessionMax  time.Duration
	ceremonyTTL time.Duration

	// frameAncestors are the origins that may frame the pages in framablePaths (Config.FrameAncestors).
	frameAncestors []string

	// L1-12 (approvals.go): set by UseApprovals.
	appr     *approvals.Engine
	apprOpts ApprovalsOptions
	apprPage *template.Template
	// stale remembers the last read-only look at each pending merge card (stale.go).
	stale staleCache

	// L1-22 (phone.go): set by UsePhone.
	phone *phoneConfig

	// L1-20 (screens.go): set by UseScreens.
	scr *screens
}

// New checks cfg and builds a console. The database must already be migrated.
func New(cfg Config) (*Console, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := &Console{
		db:          cfg.DB,
		rps:         map[string]*relyingParty{},
		now:         cfg.Now,
		emitFn:      cfg.OnEvent,
		log:         cfg.Log,
		sessionIdle: cfg.SessionIdle,
		sessionMax:  cfg.SessionMax,
		ceremonyTTL: cfg.CeremonyTTL,
		authn:       cmp.Or(cfg.Authenticators, AuthenticatorsPlatform),
		// a copy: the guard puts it in a response header, so nothing may change it after validation
		frameAncestors: append([]string(nil), cfg.FrameAncestors...),
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.sessionIdle == 0 {
		c.sessionIdle = 30 * time.Minute
	}
	if c.sessionMax == 0 {
		c.sessionMax = 8 * time.Hour
	}
	if c.ceremonyTTL == 0 {
		c.ceremonyTTL = 5 * time.Minute
	}
	copy(c.csrfKey[:], randBytes(32))

	name := cfg.DisplayName
	if name == "" {
		name = "Chaperone"
	}
	for _, o := range cfg.Origins {
		host, _ := o.check() // validated above
		build := func(framed bool) (*webauthn.WebAuthn, error) {
			wc := &webauthn.Config{
				RPID:                  o.RPID,
				RPDisplayName:         name,
				RPOrigins:             []string{o.URL},
				AttestationPreference: protocol.PreferNoAttestation,
				// ADR-004 section 1 and amendment 15: a discoverable key and user verification, always. Platform
				// authenticators only (Windows Hello, Touch ID, a phone's own passkey) unless Config.Authenticators
				// is "any", which leaves the attachment open so the browser also offers a security key and a phone.
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					AuthenticatorAttachment: c.registrationAttachment(),
					RequireResidentKey:      protocol.ResidentKeyRequired(),
					ResidentKey:             protocol.ResidentKeyRequirementRequired,
					UserVerification:        protocol.VerificationRequired,
				},
				Timeouts: webauthn.TimeoutsConfig{
					Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: c.ceremonyTTL, TimeoutUVD: c.ceremonyTTL},
					Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: c.ceremonyTTL, TimeoutUVD: c.ceremonyTTL},
				},
			}
			if framed {
				// The same relying party, also accepting an assertion made in a frame: its signed topOrigin must be
				// one of the listed ancestors (explicit mode: never inferred, never "any").
				wc.RPAllowCrossOrigin = true
				wc.RPTopOrigins = cfg.FrameAncestors
				wc.RPTopOriginVerificationMode = protocol.TopOriginExplicitVerificationMode
			}
			return webauthn.New(wc)
		}
		wa, err := build(false)
		if err != nil {
			return nil, fmt.Errorf("console: webauthn for %s: %w", o.URL, err)
		}
		rp := &relyingParty{Origin: o, host: host, wa: wa}
		// Only the server's own origin serves framable pages; the phone origin's relying party never accepts a framed passkey.
		if len(cfg.FrameAncestors) > 0 && o.RPID == LocalOrigin.RPID {
			if rp.waFramed, err = build(true); err != nil {
				return nil, fmt.Errorf("console: framed webauthn for %s: %w", o.URL, err)
			}
		}
		c.rps[host] = rp
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	c.pages = pages
	return c, nil
}

func (c *Console) emit(e Event) {
	if c.emitFn != nil {
		c.emitFn(e)
	}
}

// Handler returns the console's HTTP handler, guard included. It answers only
// requests whose Host is a configured origin's host, so the same listener can
// carry other routes (the API, the git proxy) for other Hosts in front of it.
func (c *Console) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /{$}", c.home)
	mux.HandleFunc("GET /login", c.loginPage)
	mux.HandleFunc("POST /login/begin", c.loginBegin)
	mux.HandleFunc("POST /login/finish", c.loginFinish)
	mux.HandleFunc("POST /logout", c.logout)
	mux.HandleFunc("GET /enroll", c.enrollPage)
	mux.HandleFunc("POST /enroll/begin", c.enrollBegin)
	mux.HandleFunc("POST /enroll/finish", c.enrollFinish)
	c.approvalRoutes(mux) // L1-12: only when UseApprovals was called
	c.screenRoutes(mux)   // L1-20: only when UseScreens was called
	c.phoneRoutes(mux)    // L1-22: only when UsePhone was called
	return c.guard(c.withNotFoundPage(mux))
}

// withNotFoundPage answers a GET or HEAD for a path no route knows, under any
// method, with the error page instead of the router's one line of plain text.
// A path that exists for another method keeps the router's 405.
func (c *Console) withNotFoundPage(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			probe := r.Clone(r.Context())
			probe.Method = http.MethodPost
			_, getPattern := mux.Handler(r)
			_, postPattern := mux.Handler(probe)
			if getPattern == "" && postPattern == "" && !strings.HasPrefix(r.URL.Path, "/static/") {
				p := page{Title: "Page not found", Message: "There is no page at this address."}
				if st := stateOf(r); st.user != nil {
					p.Approver = st.user.Name
				}
				c.render(w, r, http.StatusNotFound, "error", p)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// IssueEnrollment creates a one-time enrolment token and returns it. The
// plaintext is not stored: only its SHA-256. approverID nil enrols the first
// approver (refused if one exists); otherwise it adds a credential to that
// approver (the phone passkey, ADR-004 section 5).
func IssueEnrollment(ctx context.Context, db *store.DB, approverID *int64, ttl time.Duration, now time.Time) (string, error) {
	var token string
	err := db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) (err error) {
		token, err = issueEnrollmentTx(ctx, tx, approverID, ttl, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// IssueFirstEnrollment is the one-time address of a scratch console's first
// passkey (`chapd quickstart`). In one transaction it first spends every
// earlier first-approver token that was never used (a restarted quickstart
// leaves only the address it printed last alive, not the ones still in the
// terminal's history), and then
//
//   - returns "" and issues nothing when an approver already exists, so the
//     caller offers sign-in and no enrolment address exists at all, or
//   - issues a new token.
//
// The token is single use (saveEnrollment) and dies at now+ttl.
func IssueFirstEnrollment(ctx context.Context, db *store.DB, ttl time.Duration, now time.Time) (string, error) {
	var token string
	err := db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE console_enrollments SET used_at = ? WHERE approver_id IS NULL AND used_at IS NULL`,
			now.UTC().Format(timeFormat)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approvers`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		var err error
		token, err = issueEnrollmentTx(ctx, tx, nil, ttl, now)
		return err
	})
	return token, err
}

// issueEnrollmentTx is [IssueEnrollment] inside the caller's transaction, so an
// approval can be spent in the same commit that issues the address.
func issueEnrollmentTx(ctx context.Context, tx *store.Tx, approverID *int64, ttl time.Duration, now time.Time) (string, error) {
	token := b64.EncodeToString(randBytes(16))
	if approverID == nil {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approvers`).Scan(&n); err != nil {
			return "", err
		}
		if n > 0 {
			return "", errApproverExists
		}
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO console_enrollments (token_sha256, approver_id, created_at, expires_unix) VALUES (?, ?, ?, ?)`,
		sum([]byte(token)), approverID, now.UTC().Format(timeFormat), now.Add(ttl).Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

// ---- pages ----

type page struct {
	Title       string
	CSRF        string
	Origin      string
	NoApprover  bool
	Approver    string
	Credentials []credView
	Message     string
	Phone       bool // the page is served at a phone origin (wording only; the guard decides nothing from it)
	Roaming     bool // Config.Authenticators allows a security key or a phone (wording only)
	Framed      bool // see Console.framed: no header, no nav
}

type credView struct {
	Label, RPID, Origin, Created, LastUsed string
}

// newTemplate is the template every page set starts from. `timezone` is the zone the pages show times in (CHAP_TIMEZONE, UTC by
// default); web/static/localtime.js reads it from the layout. It is looked up at each render, so it follows localtime.Configure.
func newTemplate() *template.Template {
	return template.New("").Funcs(template.FuncMap{"timezone": localtime.Label})
}

func parsePages() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, name := range []string{"home", "login", "enroll", "error", "signedout"} {
		t, err := newTemplate().ParseFS(web.Templates(), "layout.html", "fragments.html", name+".html")
		if err != nil {
			return nil, fmt.Errorf("console: parse template %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

// render executes a page into a buffer first so a template error is a clean
// 500 and never a half page.
func (c *Console) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	st := stateOf(r)
	p.CSRF = c.csrfToken(st)
	p.Origin = st.rp.URL
	p.Phone = st.rp.RPID != LocalOrigin.RPID
	p.Roaming = c.authn == AuthenticatorsAny
	p.Framed = st.framed
	var buf bytes.Buffer
	if err := c.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		c.log.Error("render", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (c *Console) home(w http.ResponseWriter, r *http.Request) {
	if c.scr != nil {
		c.scr.home(w, r)
		return
	}
	st := stateOf(r)
	if st.user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	creds, err := c.credentialsOf(r.Context(), st.user.ID)
	if err != nil {
		c.log.Error("list credentials", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p := page{Title: "Console", Approver: st.user.Name}
	for _, cr := range creds {
		p.Credentials = append(p.Credentials, credView{cr.Label, cr.RPID, cr.Origin, cr.Created, cr.LastUsed})
	}
	c.render(w, r, http.StatusOK, "home", p)
}

func (c *Console) loginPage(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	if st.user != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	n, err := c.approverCount(r.Context())
	if err != nil {
		c.log.Error("count approvers", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	c.render(w, r, http.StatusOK, "login", page{Title: "Sign in", NoApprover: n == 0})
}

func (c *Console) enrollPage(w http.ResponseWriter, r *http.Request) {
	c.render(w, r, http.StatusOK, "enroll", page{Title: "Enrol a passkey"})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	st := stateOf(r)
	if st.sess != nil {
		if err := c.endSession(r.Context(), st.sess.TokenSum); err != nil {
			c.log.Error("end session", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, c.cookie(st.rp, sessionCookie, "", -1))
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusNoContent)
}

// csrfToken is the value a page embeds and a POST must send back.
func (c *Console) csrfToken(st *reqState) string {
	m := hmac.New(sha256.New, c.csrfKey[:])
	m.Write([]byte("chap-csrf-v1\x00"))
	m.Write([]byte(st.csrfCookie))
	m.Write([]byte{0})
	if st.sess != nil {
		m.Write(st.sess.TokenSum)
	}
	return b64.EncodeToString(m.Sum(nil))
}
