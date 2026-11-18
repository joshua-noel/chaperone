package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

var (
	pcOrigin    = LocalOrigin
	phoneOrigin = Origin{RPID: "pc.tail1234.ts.net", URL: "https://pc.tail1234.ts.net"}
)

// rig is a console over a fresh database plus the events it emitted.
type rig struct {
	t   *testing.T
	db  *store.DB
	con *Console
	now time.Time
	mu  sync.Mutex
	evs []Event
}

func newRig(t *testing.T, origins ...Origin) *rig { return newRigCfg(t, nil, origins...) }

// newRigCfg is newRig with a hook that may change the console's Config before it is built (frame ancestors, say).
func newRigCfg(t *testing.T, mut func(*Config), origins ...Origin) *rig {
	t.Helper()
	if len(origins) == 0 {
		origins = []Origin{pcOrigin}
	}
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ms); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, db: db, now: time.Now()}
	cfg := Config{
		DB: db, Origins: origins,
		Now:     func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
		OnEvent: func(e Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() },
	}
	if mut != nil {
		mut(&cfg)
	}
	r.con, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

func (r *rig) events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.evs...)
}

// last returns the newest event or fails.
func (r *rig) last() Event {
	r.t.Helper()
	e := r.events()
	if len(e) == 0 {
		r.t.Fatal("no events emitted")
	}
	return e[len(e)-1]
}

func (r *rig) token() string {
	r.t.Helper()
	tok, err := IssueEnrollment(context.Background(), r.db, nil, 10*time.Minute, r.now)
	if err != nil {
		r.t.Fatal(err)
	}
	return tok
}

// browser is a cookie-keeping client that talks to the handler directly and
// behaves like a same-origin page of one configured origin.
type browser struct {
	t       *testing.T
	h       http.Handler
	host    string // Host header
	origin  string // Origin header on POST
	cookies map[string]string
}

func (r *rig) browser(o Origin) *browser {
	return &browser{t: r.t, h: r.con.Handler(), host: strings.TrimPrefix(strings.TrimPrefix(o.URL, "https://"), "http://"),
		origin: o.URL, cookies: map[string]string{}}
}

func (b *browser) do(method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = b.host
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if method == http.MethodPost {
		req.Header.Set("Origin", b.origin)
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range b.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return rec
}

var metaCSRF = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

// csrf fetches the CSRF token the way a page would receive it.
func (b *browser) csrf() string {
	b.t.Helper()
	rec := b.do("GET", "/enroll", nil, nil)
	m := metaCSRF.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		b.t.Fatalf("GET /enroll: %d %q", rec.Code, rec.Body.String())
	}
	return m[1]
}

// post sends JSON with the CSRF header (and the ceremony id, if any).
func (b *browser) post(path string, body []byte, ceremony string) (int, map[string]json.RawMessage) {
	b.t.Helper()
	h := map[string]string{"X-CSRF-Token": b.csrf()}
	if ceremony != "" {
		h["X-Ceremony-ID"] = ceremony
	}
	rec := b.do("POST", path, body, h)
	var out map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func str(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// begin runs a Begin step and returns the ceremony id and the options.
func (b *browser) begin(path string, body []byte) (string, json.RawMessage) {
	b.t.Helper()
	code, out := b.post(path, body, "")
	if code != 200 {
		b.t.Fatalf("POST %s: %d %v", path, code, out)
	}
	return str(out["ceremony"]), out["options"]
}

// enrol runs a whole registration and returns the authenticator.
func (b *browser) enrol(r *rig, token string, o opts) (*authenticator, int, map[string]json.RawMessage) {
	b.t.Helper()
	req, _ := json.Marshal(map[string]string{"token": token, "name": "operator", "label": "Hello"})
	cer, options := b.begin("/enroll/begin", req)
	a := newAuthenticator(b.t, strings.Split(strings.TrimPrefix(strings.TrimPrefix(b.origin, "https://"), "http://"), ":")[0])
	code, out := b.post("/enroll/finish", a.create(options, b.origin, o), cer)
	return a, code, out
}

// login runs a whole sign-in.
func (b *browser) login(a *authenticator, o opts) (int, map[string]json.RawMessage) {
	b.t.Helper()
	cer, options := b.begin("/login/begin", nil)
	return b.post("/login/finish", a.get(options, b.origin, o), cer)
}

func mustEnrolled(t *testing.T, r *rig, b *browser) *authenticator {
	t.Helper()
	a, code, out := b.enrol(r, r.token(), opts{})
	if code != 200 {
		t.Fatalf("enrol: %d %v events=%+v", code, out, r.events())
	}
	return a
}
