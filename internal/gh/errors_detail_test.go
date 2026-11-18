package gh_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
)

// First the runner runs, 25 Oct: POST /pulls answered 422 "Validation Failed" and
// the reason was in errors[], which the client dropped.

// A token without contents:read cannot read the head ref, so GitHub refuses the
// pull request. The reason must reach the caller.
func TestCreatePullWithoutContentsReadSaysWhy(t *testing.T) {
	f := newFixture(t)
	f.r.Branch("agent/new", base)
	f.r.Commit("agent/new")
	in := gh.NewPull{Title: "feat: new", Head: "agent/new", Base: base}

	_, err := f.c.CreatePull(ctx, f.mint(t, map[string]string{"pull_requests": gh.Write, "metadata": gh.Read}), f.repo, in)
	var ae *gh.APIError
	if !errors.As(err, &ae) || !errors.Is(err, gh.ErrUnprocessable) {
		t.Fatalf("want a 422 APIError, got %v", err)
	}
	if ae.Message != "Validation Failed" || len(ae.Errors) != 1 {
		t.Fatalf("message %q errors %+v", ae.Message, ae.Errors)
	}
	if e := ae.Errors[0]; e.Resource != "PullRequest" || e.Code != "custom" || e.Message != "not all refs are readable" {
		t.Errorf("error entry %+v", e)
	}
	want := "Validation Failed (PullRequest custom: not all refs are readable)"
	if ae.Detail() != want || !strings.Contains(err.Error(), want) {
		t.Errorf("detail %q, error text %q", ae.Detail(), err)
	}

	// The set pr.open mints opens it.
	if _, err := f.c.CreatePull(ctx, f.mint(t, gh.PermsOpenPull()), f.repo, in); err != nil {
		t.Fatalf("with PermsOpenPull: %v", err)
	}
}

func TestAPIErrorKeepsFieldErrorsClippedAndScrubbed(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(t, gh.PermsOpenPull())
	secret := tok.Reveal()
	long := strings.Repeat("x", 2000)
	answers := map[string]string{
		"objects": fmt.Sprintf(`{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"head","code":"invalid"},{"resource":"PullRequest","code":"custom","message":"A pull request already exists for a:b."}]}`),
		"strings": `{"message":"Validation Failed","errors":["head is invalid","base is invalid"]}`,
		"hostile": fmt.Sprintf(`{"message":"bad %s","errors":[{"resource":"R\u0000","field":"f\n","code":"%s","message":"token %s \u001b[2J %s"}]}`, secret, long, secret, long),
		"many":    `{"message":"Validation Failed","errors":[{"code":"1"},{"code":"2"},{"code":"3"},{"code":"4"},{"code":"5"},{"code":"6"},{"code":"7"}]}`,
		"none":    `{"message":"Validation Failed"}`,
		"html":    `<html>bad gateway</html>`,
	}
	for name, body := range answers {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(422)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c, err := gh.New(gh.Config{AppID: f.s.AppID(), Keys: gh.StaticKey{Key: f.s.Key()}, BaseURL: srv.URL, Now: f.s.Now})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.CreatePull(ctx, tok, f.repo, gh.NewPull{Title: "t", Head: "h", Base: "main"})
			var ae *gh.APIError
			if !errors.As(err, &ae) {
				t.Fatalf("got %v", err)
			}
			text := ae.Detail() + "|" + err.Error()
			if strings.Contains(text, secret) {
				t.Errorf("the token is in %q", text)
			}
			if strings.ContainsAny(text, "\x00\x1b\n") {
				t.Errorf("control characters in %q", text)
			}
			if len(ae.Detail()) > 1200 {
				t.Errorf("detail is %d bytes", len(ae.Detail()))
			}
			switch name {
			case "objects":
				if got := ae.Detail(); got != "Validation Failed (PullRequest.head invalid; PullRequest custom: A pull request already exists for a:b.)" {
					t.Errorf("detail %q", got)
				}
			case "strings":
				if got := ae.Detail(); got != "Validation Failed (head is invalid; base is invalid)" {
					t.Errorf("detail %q", got)
				}
			case "hostile":
				if len(ae.Errors) != 1 || !strings.Contains(ae.Detail(), "[redacted]") {
					t.Errorf("errors %+v", ae.Errors)
				}
			case "many":
				if len(ae.Errors) != 5 {
					t.Errorf("%d errors kept, want 5", len(ae.Errors))
				}
			case "none", "html":
				if len(ae.Errors) != 0 {
					t.Errorf("errors %+v", ae.Errors)
				}
			}
		})
	}
}
