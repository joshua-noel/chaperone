package gh_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
)

// Every refusal is returned after one request. The client has no retry, and
// these tests are the proof for each kind of refusal GitHub gives.
func TestRefusalsAreReturnedNeverRetried(t *testing.T) {
	type tc struct {
		name  string
		fault func(f *fixture) ghtest.Fault
		check func(t *testing.T, err error, ae *gh.APIError)
	}
	notRL := func(t *testing.T, err error) {
		t.Helper()
		if errors.Is(err, gh.ErrRateLimited) {
			t.Error("not a rate limit")
		}
	}
	cases := []tc{
		{"primary rate limit", func(f *fixture) ghtest.Fault { return f.s.PrimaryRateLimit(10 * time.Minute) },
			func(t *testing.T, err error, ae *gh.APIError) {
				if !errors.Is(err, gh.ErrRateLimited) || errors.Is(err, gh.ErrSecondaryRateLimited) || errors.Is(err, gh.ErrForbidden) {
					t.Fatalf("classification: %v", err)
				}
				rl := ae.RateLimit
				if rl.Secondary || rl.Remaining != 0 || rl.Limit != 5000 || rl.Resource != "core" || rl.Reset.Unix() != time.Date(2026, 10, 24, 12, 10, 0, 0, time.UTC).Unix() {
					t.Fatalf("%+v", rl)
				}
				if !strings.Contains(err.Error(), "primary rate limit") {
					t.Fatalf("message: %v", err)
				}
			}},
		{"secondary rate limit", func(f *fixture) ghtest.Fault { return ghtest.SecondaryRateLimit(90 * time.Second) },
			func(t *testing.T, err error, ae *gh.APIError) {
				if !errors.Is(err, gh.ErrRateLimited) || !errors.Is(err, gh.ErrSecondaryRateLimited) || errors.Is(err, gh.ErrForbidden) {
					t.Fatalf("classification: %v", err)
				}
				if !ae.RateLimit.Secondary || ae.RateLimit.RetryAfter != 90*time.Second {
					t.Fatalf("%+v", ae.RateLimit)
				}
			}},
		{"secondary by message only", func(f *fixture) ghtest.Fault {
			return ghtest.Fault{Status: 403, Message: "You have exceeded a secondary rate limit."}
		}, func(t *testing.T, err error, ae *gh.APIError) {
			if !errors.Is(err, gh.ErrSecondaryRateLimited) {
				t.Fatal(err)
			}
		}},
		{"429", func(f *fixture) ghtest.Fault { return ghtest.TooManyRequests(30 * time.Second) },
			func(t *testing.T, err error, ae *gh.APIError) {
				if !errors.Is(err, gh.ErrRateLimited) || ae.Status != 429 || ae.RateLimit.RetryAfter != 30*time.Second {
					t.Fatalf("%v %+v", err, ae.RateLimit)
				}
			}},
		{"plain 403 is not a rate limit", func(f *fixture) ghtest.Fault {
			return ghtest.Fault{Status: 403, Message: "Resource not accessible by integration"}
		}, func(t *testing.T, err error, ae *gh.APIError) {
			notRL(t, err)
			if !errors.Is(err, gh.ErrForbidden) || ae.RateLimit != nil {
				t.Fatal(err)
			}
		}},
		{"503", func(f *fixture) ghtest.Fault { return ghtest.Unavailable() },
			func(t *testing.T, err error, ae *gh.APIError) {
				notRL(t, err)
				if !errors.Is(err, gh.ErrServer) {
					t.Fatal(err)
				}
			}},
		{"redirect is not followed", func(f *fixture) ghtest.Fault {
			h := http.Header{}
			h.Set("Location", "https://evil.example/steal")
			return ghtest.Fault{Status: 301, Message: "Moved Permanently", Header: h}
		}, func(t *testing.T, err error, ae *gh.APIError) {
			if ae.Status != 301 {
				t.Fatal(err)
			}
		}},
	}
	calls := map[string]func(f *fixture, tok *gh.Token, head string) error{
		"merge": func(f *fixture, tok *gh.Token, head string) error {
			_, err := f.c.MergePull(ctx, tok, f.repo, 1, gh.MergeRequest{SHA: head})
			return err
		},
		"get pull": func(f *fixture, tok *gh.Token, head string) error {
			_, err := f.c.GetPull(ctx, tok, f.repo, 1)
			return err
		},
		"check runs": func(f *fixture, tok *gh.Token, head string) error {
			_, err := f.c.ListCheckRuns(ctx, tok, f.repo, head, gh.CheckRunQuery{CheckName: "verify"})
			return err
		},
		"update branch": func(f *fixture, tok *gh.Token, head string) error {
			_, err := f.c.UpdatePullBranch(ctx, tok, f.repo, 1, head)
			return err
		},
		"mint": func(f *fixture, tok *gh.Token, head string) error {
			_, err := f.c.MintToken(ctx, 7, gh.TokenRequest{Repositories: []string{"storefront"}, Permissions: gh.PermsFetch()})
			return err
		},
	}
	for _, c := range cases {
		for callName, call := range calls {
			t.Run(c.name+"/"+callName, func(t *testing.T) {
				f := newFixture(t)
				_, head := f.pr(t, "agent/rl")
				tok := f.all(t)
				fault := c.fault(f)
				method, sub := "GET", "/pulls/"
				switch callName {
				case "merge":
					method, sub = "PUT", "/merge"
				case "check runs":
					sub = "/check-runs"
				case "update branch":
					method, sub = "PUT", "/update-branch"
				case "mint":
					method, sub = "POST", "/access_tokens"
				}
				f.s.Inject(method, sub, fault) // Times 0: every request, so a retry would also be refused
				before := len(f.s.Requests())
				err := call(f, tok, head)
				var ae *gh.APIError
				if !errors.As(err, &ae) {
					t.Fatalf("not an APIError: %v", err)
				}
				if n := len(f.s.Requests()) - before; n != 1 {
					t.Fatalf("%d requests sent, want 1", n)
				}
				c.check(t, err, ae)
			})
		}
	}
}

func TestRateLimitedRevokeStillOnePerCall(t *testing.T) {
	f := newFixture(t)
	tok := f.all(t)
	f.s.Inject("DELETE", "/installation/token", f.s.PrimaryRateLimit(time.Minute))
	if err := f.c.RevokeToken(ctx, tok); !errors.Is(err, gh.ErrRateLimited) {
		t.Fatal(err)
	}
	if f.s.Count("DELETE", "/installation/token") != 1 {
		t.Fatal("revoke retried")
	}
	if tok.Reveal() == "" {
		t.Fatal("a failed revoke must not wipe the token; the caller still needs to revoke it")
	}
}

func TestErrorTextCarriesRequestPathNotCredentials(t *testing.T) {
	f := newFixture(t)
	tok := f.all(t)
	_, err := f.c.GetPull(ctx, tok, f.repo, 404)
	if err == nil {
		t.Fatal("want error")
	}
	s := err.Error()
	if !strings.Contains(s, "/repos/example-org/storefront/pulls/404") || !strings.Contains(s, "404") {
		t.Fatalf("unhelpful: %s", s)
	}
	if strings.Contains(s, tok.Reveal()) || strings.Contains(s, "Bearer") {
		t.Fatalf("credential in error: %s", s)
	}
}

func TestLongAndOddErrorBodiesAreBounded(t *testing.T) {
	f := newFixture(t)
	tok := f.all(t)
	f.s.Inject("GET", "/pulls/", ghtest.Fault{Status: 422, Message: strings.Repeat("x", 5000) + "\n\x1b[31mred"})
	_, err := f.c.GetPull(ctx, tok, f.repo, 1)
	var ae *gh.APIError
	if !errors.As(err, &ae) || len(ae.Message) > 520 || strings.ContainsAny(ae.Message, "\n\x1b") {
		t.Fatalf("%d bytes, %q", len(ae.Message), ae.Message)
	}
}

func TestNetworkErrorPassesThrough(t *testing.T) {
	f := newFixture(t)
	tok := f.all(t)
	f.s.Close()
	_, err := f.c.GetPull(ctx, tok, f.repo, 1)
	var ae *gh.APIError
	if err == nil || errors.As(err, &ae) {
		t.Fatalf("want a transport error, got %v", err)
	}
}
