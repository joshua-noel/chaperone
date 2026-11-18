package gh_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

var ctx = context.Background()

func TestMintNarrowedToken(t *testing.T) {
	for name, style := range map[string]ghtest.TokenStyle{"stateless": ghtest.Stateless, "legacy": ghtest.Legacy} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.s.SetTokenStyle(style)
			f.r.Branch("agent/r1", base)
			tok := f.mint(t, gh.PermsEvaluateMerge())
			if got := tok.Repositories; len(got) != 1 || got[0] != "storefront" {
				t.Fatalf("repositories = %v", got)
			}
			if tok.Permissions["contents"] != "read" || tok.Permissions["workflows"] != "" {
				t.Fatalf("permissions = %v", tok.Permissions)
			}
			if want := f.s.Now().Add(time.Hour); !tok.ExpiresAt().Equal(want) {
				t.Fatalf("expires %v, want %v", tok.ExpiresAt(), want)
			}
			// Opaque: 40 or ~520 characters both work; neither length is assumed.
			if n := len(tok.Reveal()); name == "legacy" && n != 40 || name == "stateless" && n < 400 {
				t.Fatalf("fake produced a %d-char token for style %s", n, name)
			}
			if _, err := f.c.Compare(ctx, tok, f.repo, base, "agent/r1"); err != nil {
				t.Fatalf("a %d-char token must work: %v", len(tok.Reveal()), err)
			}
			// the request carried the narrowing
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			for _, r := range f.s.Requests() {
				if strings.HasSuffix(r.Path, "/access_tokens") {
					if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(body.Repositories) != 1 || body.Permissions["checks"] != "read" || len(body.Permissions) != 4 {
				t.Fatalf("mint body = %+v", body)
			}
		})
	}
}

func TestNarrowedTokenCannotTouchOtherRepo(t *testing.T) {
	f := newFixture(t)
	tok := f.all(t) // storefront only
	_, err := f.c.Compare(ctx, tok, f.orepo, "main", "main")
	if !errors.Is(err, gh.ErrNotFound) {
		t.Fatalf("other repo: %v", err)
	}
	if _, err := f.c.Compare(ctx, tok, f.repo, base, base); err != nil {
		t.Fatalf("own repo: %v", err)
	}
}

func TestPermissionsAreEnforced(t *testing.T) {
	f := newFixture(t)
	n, head := f.pr(t, "agent/p")
	ro := f.mint(t, gh.PermsEvaluateMerge())
	if _, err := f.c.GetPull(ctx, ro, f.repo, n); err != nil {
		t.Fatalf("read with read token: %v", err)
	}
	_, err := f.c.MergePull(ctx, ro, f.repo, n, gh.MergeRequest{SHA: head})
	if !errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("merge with a read token: %v", err)
	}
	if _, err := f.c.CreateDeployment(ctx, ro, f.repo, gh.DeploymentRequest{Ref: base, Environment: "pilot"}); !errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("deployment with a read token: %v", err)
	}
	var apiErr *gh.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Message == "" {
		t.Fatalf("APIError details: %#v", apiErr)
	}
}

func TestMintRefusesUnnarrowedRequests(t *testing.T) {
	f := newFixture(t)
	cases := map[string]gh.TokenRequest{
		"no repositories": {Permissions: gh.PermsFetch()},
		"no permissions":  {Repositories: []string{"storefront"}},
		"owner/name form": {Repositories: []string{"example-org/storefront"}, Permissions: gh.PermsFetch()},
		"duplicate":       {Repositories: []string{"a", "a"}, Permissions: gh.PermsFetch()},
		"bad level":       {Repositories: []string{"a"}, Permissions: map[string]string{"contents": "owner"}},
		"bad permission":  {Repositories: []string{"a"}, Permissions: map[string]string{"Contents": "read"}},
		"too many repos":  {Repositories: make([]string, 501), Permissions: gh.PermsFetch()},
	}
	for name, req := range cases {
		if _, err := f.c.MintToken(ctx, 7, req); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.c.MintToken(ctx, 0, gh.TokenRequest{Repositories: []string{"a"}, Permissions: gh.PermsFetch()}); !errors.Is(err, gh.ErrInvalidArgument) {
		t.Errorf("installation 0: %v", err)
	}
	if n := f.s.Count("POST", "access_tokens"); n != 0 {
		t.Fatalf("%d requests were sent for invalid mints", n)
	}
}

func TestMintRefusals(t *testing.T) {
	f := newFixture(t)
	// permission the App was never granted (workflows is not granted in Phase 1)
	_, err := f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: map[string]string{"workflows": "write"}})
	if !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("workflows: %v", err)
	}
	// a level above the grant
	_, err = f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: map[string]string{"checks": "write"}})
	if !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("checks:write: %v", err)
	}
	// repository outside the installation
	_, err = f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"runner"}, Permissions: gh.PermsFetch()})
	if !errors.Is(err, gh.ErrUnprocessable) {
		t.Errorf("foreign repo: %v", err)
	}
	// unknown installation
	_, err = f.c.MintToken(ctx, 99, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsFetch()})
	if !errors.Is(err, gh.ErrNotFound) {
		t.Errorf("unknown installation: %v", err)
	}
	if f.s.LiveTokens() != 0 {
		t.Fatal("a refused mint left a token alive")
	}
}

func TestMintDetectsUnnarrowedAnswerAndRevokes(t *testing.T) {
	f := newFixture(t)
	f.s.MintAnswersAll()
	tok, err := f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsFetch()})
	if !errors.Is(err, gh.ErrNotNarrowed) || tok != nil {
		t.Fatalf("tok=%v err=%v", tok, err)
	}
	if f.s.LiveTokens() != 0 {
		t.Fatal("the too-broad token was not revoked")
	}
	if f.s.Count("DELETE", "/installation/token") != 1 {
		t.Fatal("expected one revoke call")
	}
}

func TestAppJWTRefusals(t *testing.T) {
	f := newFixture(t)
	req := gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsFetch()}
	mk := func(keys gh.KeySource, now func() time.Time, appID string) *gh.Client {
		c, err := gh.New(gh.Config{AppID: appID, Keys: keys, BaseURL: f.s.URL(), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*gh.Client{
		"wrong key":       mk(gh.StaticKey{Key: other}, f.s.Now, f.s.AppID()),
		"wrong app id":    mk(gh.StaticKey{Key: f.s.Key()}, f.s.Now, "1"),
		"clock 1h behind": mk(gh.StaticKey{Key: f.s.Key()}, func() time.Time { return f.s.Now().Add(-time.Hour) }, f.s.AppID()),
		"clock 1h ahead":  mk(gh.StaticKey{Key: f.s.Key()}, func() time.Time { return f.s.Now().Add(time.Hour) }, f.s.AppID()),
	}
	for name, c := range cases {
		if _, err := c.MintToken(ctx, 7, req); !errors.Is(err, gh.ErrUnauthorized) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := mk(gh.StaticKey{Key: f.s.Key()}, f.s.Now, f.s.AppID()).MintToken(ctx, 7, req); err != nil {
		t.Errorf("good client: %v", err)
	}
}

func TestFindInstallation(t *testing.T) {
	f := newFixture(t)
	in, err := f.c.FindInstallation(ctx, f.repo)
	if err != nil || in.ID != 7 || in.Account != "example-org" {
		t.Fatalf("%+v %v", in, err)
	}
	if _, err := f.c.FindInstallation(ctx, gh.Repo{Owner: "example-org", Name: "runner"}); !errors.Is(err, gh.ErrNotFound) {
		t.Fatalf("uninstalled repo: %v", err)
	}
}

func TestRevokeMakesTokenFail401(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/r")
	tok := f.all(t)
	if _, err := f.c.GetPull(ctx, tok, f.repo, n); err != nil {
		t.Fatal(err)
	}
	if err := f.c.RevokeToken(ctx, tok); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !f.s.TokenRevoked(tok.Reveal()) {
		t.Fatal("fake did not record the revoke")
	}
	if _, err := f.c.GetPull(ctx, tok, f.repo, n); !errors.Is(err, gh.ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	if err := f.c.RevokeToken(ctx, tok); !errors.Is(err, gh.ErrUnauthorized) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestWipeAndExpiry(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/w")
	tok := f.all(t)
	f.s.Advance(time.Hour) // exactly the expiry
	before := f.s.Count("GET", "/pulls/")
	if _, err := f.c.GetPull(ctx, tok, f.repo, n); !errors.Is(err, gh.ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	if f.s.Count("GET", "/pulls/") != before {
		t.Fatal("an expired token was sent to GitHub")
	}
	tok2 := f.all(t)
	tok2.Wipe()
	tok2.Wipe() // idempotent
	if tok2.Reveal() != "" {
		t.Fatal("Reveal after Wipe")
	}
	if _, err := f.c.GetPull(ctx, tok2, f.repo, n); !errors.Is(err, gh.ErrTokenWiped) {
		t.Fatalf("wiped: %v", err)
	}
	if _, err := f.c.GetPull(ctx, nil, f.repo, n); err == nil {
		t.Fatal("nil token must fail")
	}
}

func TestTokenNeverPrinted(t *testing.T) {
	f := newFixture(t)
	n, _ := f.pr(t, "agent/s")
	tok := f.all(t)
	secret := tok.Reveal()
	check := func(what, s string) {
		if strings.Contains(s, secret) || strings.Contains(s, secret[len(secret)/2:]) {
			t.Errorf("%s leaks the token", what)
		}
	}
	check("%v", fmt.Sprintf("%v", tok))
	check("%+v", fmt.Sprintf("%+v", tok))
	check("%#v", fmt.Sprintf("%#v", tok))
	check("%s", fmt.Sprintf("%s", tok))
	j, err := json.Marshal(map[string]any{"t": tok})
	if err != nil {
		t.Fatal(err)
	}
	check("json", string(j))

	// A server that echoes the credential in its error text must not get it into our errors.
	f.s.Inject("GET", "/pulls/", ghtest.Fault{Status: 422, Message: "bad credential " + secret})
	_, err = f.c.GetPull(ctx, tok, f.repo, n)
	if err == nil {
		t.Fatal("want error")
	}
	check("APIError", err.Error())
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("expected a redaction marker: %v", err)
	}
}

func TestNewConfigValidation(t *testing.T) {
	keys := gh.StaticKey{Key: ghtest.TestKey()}
	bad := map[string]gh.Config{
		"no app id":     {Keys: keys},
		"no keys":       {AppID: "1"},
		"http remote":   {AppID: "1", Keys: keys, BaseURL: "http://api.github.com"},
		"ftp":           {AppID: "1", Keys: keys, BaseURL: "ftp://x"},
		"query in base": {AppID: "1", Keys: keys, BaseURL: "https://x/?a=b"},
		"userinfo":      {AppID: "1", Keys: keys, BaseURL: "https://u:p@x"},
	}
	for name, cfg := range bad {
		if _, err := gh.New(cfg); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, u := range []string{"", "https://ghe.example/api/v3", "http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"} {
		if _, err := gh.New(gh.Config{AppID: "1", Keys: keys, BaseURL: u}); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
}

func TestParseRepo(t *testing.T) {
	for _, ok := range []string{"example-org/storefront", "a/b.c_d"} {
		if _, err := gh.ParseRepo(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "a/", "/b", "a/b/c", "a/..", "../b", "a b/c", "a/b?x=1", "a/b#"} {
		if _, err := gh.ParseRepo(bad); !errors.Is(err, gh.ErrInvalidArgument) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
