package google

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
	"github.com/joshua-noel/chaperone/internal/vault"
)

type aesWrap struct{ aead cipher.AEAD }

func newAESWrap(t testing.TB) vault.KeyWrapper {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	return aesWrap{g}
}

func (aesWrap) Name() string { return "test-aesgcm" }
func (w aesWrap) Wrap(p []byte) ([]byte, error) {
	n := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return w.aead.Seal(n, n, p, nil), nil
}
func (w aesWrap) Unwrap(b []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	return w.aead.Open(nil, b[:ns], b[ns:], nil)
}

// alerts records the alerts a Source raises.
type alerts struct {
	mu   sync.Mutex
	keys []string
}

func (a *alerts) RaiseGoogleAlert(_ context.Context, key, _ string) {
	a.mu.Lock()
	a.keys = append(a.keys, key)
	a.mu.Unlock()
}

func (a *alerts) count(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, k := range a.keys {
		if k == key {
			n++
		}
	}
	return n
}

// clock is a settable clock shared by the connector and the fake.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const testProject = "acme-shop"

// rig is a vault, a fake Google and the connector objects over them.
type rig struct {
	t      *testing.T
	fake   *googletest.Server
	vault  *vault.Vault
	reg    *redact.Registry
	clock  *clock
	alerts *alerts
	ep     Endpoints
	src    *Source
	pol    *policy.Google
	atts   map[string][]byte
	gmail  *Gmail
	drive  *Drive
}

func (r *rig) Get(sum string) ([]byte, error) {
	if b, ok := r.atts[sum]; ok {
		return b, nil
	}
	return nil, ErrNoAttachment
}

// stage puts content in the attachment store and returns its SHA-256.
func (r *rig) stage(data []byte) string {
	sum := SumHex(data)
	r.atts[sum] = data
	return sum
}

func fakeEndpoints(s *googletest.Server) Endpoints {
	return Endpoints{Auth: s.URL + "/auth", Token: s.URL + "/token", Revoke: s.URL + "/revoke", Gmail: s.URL, Drive: s.URL}
}

// newRig builds the rig and, when connect is true, signs in once with the
// scopes asked.
func newRig(t *testing.T, connect bool, scopes ...string) *rig {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reg := redact.NewRegistry()
	vcfg := vault.Config{Dir: filepath.Join(dir, "vault"), KeyDir: filepath.Join(dir, "keys"), DB: db, Wrapper: newAESWrap(t), Registry: reg}
	if err := vault.Init(ctx, vcfg, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(ctx, vcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)

	r := &rig{t: t, fake: googletest.New(t), vault: v, reg: v.Registry(), alerts: &alerts{}, atts: map[string][]byte{}}
	r.clock = &clock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	r.fake.Now = r.clock.Now
	r.ep = fakeEndpoints(r.fake)
	r.pol = &policy.Google{}
	r.pol.Mail.AllowRecipients = []string{"gilliano@example.com", "@acme.example"}
	r.pol.Drive.AllowRecipients = []string{"gilliano@example.com"}
	r.pol.Drive.MaxRole = "commenter"

	r.src, err = NewSource(SourceConfig{Secrets: v, Registry: r.reg, Endpoints: r.ep, Alert: r.alerts, Now: r.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	polf := func(p string) *policy.Google {
		if p != testProject {
			return nil
		}
		return r.pol
	}
	r.gmail, err = NewGmail(GmailConfig{Source: r.src, Policy: polf, Attachments: r, Redactor: r.reg, Endpoints: r.ep})
	if err != nil {
		t.Fatal(err)
	}
	r.drive, err = NewDrive(DriveConfig{Source: r.src, Policy: polf, Endpoints: r.ep})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveClient(ctx, v, ClientCreds{ClientID: googletest.ClientID, ClientSecret: googletest.ClientSecret}); err != nil {
		t.Fatal(err)
	}
	if connect {
		if len(scopes) == 0 {
			scopes = []string{ScopeGmailSend, ScopeDrive}
		}
		r.connect(scopes...)
	}
	return r
}

// connect runs the sign-in against the fake and stores the result.
func (r *rig) connect(scopes ...string) *TokenSet {
	r.t.Helper()
	ts, err := Connect(context.Background(), ConnectConfig{
		Client: ClientCreds{ClientID: googletest.ClientID, ClientSecret: googletest.ClientSecret}, Scopes: scopes,
		Endpoints: r.ep, Now: r.clock.Now, Timeout: 10 * time.Second,
		OpenURL: func(u string) error { return r.fake.Approve(u, nil) },
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.src.Connected(context.Background(), ts); err != nil {
		r.t.Fatal(err)
	}
	return ts
}

func req(op, adapter, ref string, params map[string]any) *ops.Request {
	return &ops.Request{ID: "q-abc123", Op: op, Project: testProject, Target: spec.Target{Adapter: adapter, Ref: ref}, Params: params, ExecutionID: "x-1"}
}

func mailReq(params map[string]any) *ops.Request {
	return req("mail.send", "google", "operator@example.com", params)
}

func okMail() map[string]any {
	return map[string]any{"to": []any{"gilliano@example.com"}, "subject": "Demo follow-up", "body": "Hello from the demo.\nSecond line."}
}

func wantRefusal(t *testing.T, err error, code string) *ops.Refusal {
	t.Helper()
	ref, ok := err.(*ops.Refusal)
	if !ok {
		t.Fatalf("got %v (%T), want refusal %s", err, err, code)
	}
	if ref.Code != code {
		t.Fatalf("code %s (%s), want %s", ref.Code, ref.Why, code)
	}
	return ref
}
