package linear

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
	"github.com/joshua-noel/chaperone/internal/redact"
)

func TestTokenIsMintedFromTheVaultSecretsAndKept(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	tok, err := r.toks.Token(ctx, false)
	if err != nil || tok == "" {
		t.Fatalf("token: %q %v", tok, err)
	}
	if again, _ := r.toks.Token(ctx, false); again != tok || r.fake.Mints() != 1 {
		t.Fatalf("a held token was not reused: mints=%d", r.fake.Mints())
	}
	// The fake accepted HTTP Basic authentication with the trimmed vault values
	// (the secrets were stored with a trailing newline) and the fixed scope set.
	if sc := r.fake.Scopes(); len(sc) != 1 || sc[0] != "read,write" {
		t.Errorf("scopes asked: %v", sc)
	}
}

func TestTokenIsRefreshedWhenItEnds(t *testing.T) {
	r := newRig(t)
	r.fake.TokenTTL = 10 * time.Minute
	ctx := context.Background()
	first, err := r.toks.Token(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(7 * time.Minute) // inside its life minus the skew
	if tok, _ := r.toks.Token(ctx, false); tok != first {
		t.Fatal("a token still valid was replaced")
	}
	r.clock.Advance(2 * time.Minute) // 9 minutes: inside the 2-minute skew before the end
	second, err := r.toks.Token(ctx, false)
	if err != nil || second == first || r.fake.Mints() != 2 {
		t.Fatalf("token not refreshed: %q %v mints=%d", second, err, r.fake.Mints())
	}
}

func TestTokenIsNeverKeptLongerThanTheCap(t *testing.T) {
	r := newRig(t) // the fake says 30 days; chapd keeps a token one hour
	ctx := context.Background()
	if _, err := r.toks.Token(ctx, false); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(59 * time.Minute)
	if _, err := r.toks.Token(ctx, false); err != nil || r.fake.Mints() != 1 {
		t.Fatalf("mints=%d %v", r.fake.Mints(), err)
	}
	r.clock.Advance(2 * time.Minute)
	if _, err := r.toks.Token(ctx, false); err != nil || r.fake.Mints() != 2 {
		t.Fatalf("a token older than an hour was kept: mints=%d %v", r.fake.Mints(), err)
	}
}

func TestACallRefetchesTheTokenAfter401(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	if _, err := r.client.TeamStates(ctx, "SHOP"); err != nil {
		t.Fatal(err)
	}
	r.fake.RevokeTokens() // Linear does this when the client secret is rotated
	team, err := r.client.TeamStates(ctx, "SHOP")
	if err != nil || team.Key != "SHOP" {
		t.Fatalf("after the token was revoked: %v %v", team, err)
	}
	if r.fake.Mints() != 2 {
		t.Errorf("mints = %d, want a second token after the 401", r.fake.Mints())
	}
	// The first call of the second round carried the dead token, the retry the new one.
	reqs := r.fake.Requests()
	last, prev := reqs[len(reqs)-1], reqs[len(reqs)-2]
	if !prev.Errors || last.Errors || prev.Token == last.Token {
		t.Errorf("requests: %+v / %+v", prev, last)
	}
}

func TestARevokedClientSecretIsASurfacedError(t *testing.T) {
	r := newRig(t)
	r.secrets.set(SecretClientSecret, "lin-client-secret-ROTATED-0123456789abcdef0123456789")
	_, err := r.toks.Token(context.Background(), false)
	var te *TokenError
	if !errors.As(err, &te) || te.Status != 401 || te.Code != "invalid_client" {
		t.Fatalf("error: %v", err)
	}
	if strings.Contains(err.Error(), "ROTATED") || strings.Contains(err.Error(), lineartest.ClientSecret) {
		t.Errorf("the error quotes a secret: %v", err)
	}
	// A failed call is a definite no-op for the op, not an unconfirmed write.
	_, gerr := r.client.TeamStates(context.Background(), "SHOP")
	if gerr == nil || !Definite(gerr) {
		t.Errorf("a call that never left should be definite: %v", gerr)
	}
}

func TestNotConnectedWithoutTheTwoSecrets(t *testing.T) {
	for _, missing := range []string{SecretClientID, SecretClientSecret} {
		r := newRig(t)
		delete(r.secrets.m, missing)
		if _, err := r.toks.Token(context.Background(), false); !errors.Is(err, ErrNotConnected) {
			t.Errorf("without %s: %v", missing, err)
		}
	}
	r := newRig(t)
	r.secrets.set(SecretClientID, " \n")
	if _, err := r.toks.Token(context.Background(), false); !errors.Is(err, ErrNotConnected) {
		t.Errorf("a blank id: %v", err)
	}
}

// The token is registered with the redaction registry while it is held, so a
// log line or an op result that holds it is masked or blocked, and it is
// removed with the token.
func TestTheTokenIsRegisteredForRedaction(t *testing.T) {
	r := newRig(t)
	tok, err := r.toks.Token(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	line := "calling linear with " + tok
	masked, res := r.reg.Redact(line)
	if !holds(res, redactID) || strings.Contains(masked, tok) {
		t.Fatalf("the token passed the redactor: %q %+v", masked, res)
	}
	r.toks.Invalidate()
	if _, res := r.reg.Redact(line); holds(res, redactID) {
		t.Error("an invalidated token is still registered")
	}
}

// holds reports whether an exact match of the registry id fired.
func holds(res redact.Result, id string) bool {
	for _, h := range res.Hits {
		if h.SecretID == id {
			return true
		}
	}
	return false
}

func TestEndpointsMustBeHTTPSOrLoopback(t *testing.T) {
	ok := Endpoints{API: "https://api.linear.app/graphql", Token: "https://api.linear.app/oauth/token"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]Endpoints{
		"plain http, other host": {API: "http://api.example.com/graphql", Token: ok.Token},
		"loopback http":          {API: "http://127.0.0.1:1/graphql", Token: "http://127.0.0.1:1/oauth/token"},
		"no token endpoint":      {API: ok.API},
		"ftp":                    {API: "ftp://x/y", Token: ok.Token},
	} {
		err := e.Validate()
		if name == "loopback http" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestADefaultTokenSourceNeedsTheVault(t *testing.T) {
	if _, err := NewTokenSource(TokenConfig{Endpoints: DefaultEndpoints()}); err == nil {
		t.Error("a token source without a vault")
	}
}
