package gitproxy_test

// Tests of the 404 repeat: GitHub answers 404 on a private repository while a
// just-minted installation token is not yet valid everywhere, and the proxy
// repeats the request with the same token. No test sleeps: Handler.Wait records
// the pause it is asked for and returns at once. The token is kept for the run
// (tokens_test.go), so a test ends the run before it asks what is still live.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/gitproxy"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// openGate lets every request through; only the forwarding is under test.
type openGate struct{}

func (openGate) GitRead(context.Context, *ops.Caller, string) error          { return nil }
func (openGate) GitPushDiscovery(context.Context, *ops.Caller, string) error { return nil }
func (openGate) BeginGitPush(context.Context, *ops.Caller, ops.GitPush) (*ops.GitPushOp, error) {
	return nil, errors.New("not used here")
}

// seen is what the fake upstream got in one request.
type seen struct {
	method, path string
	password     string // the installation token, from Basic auth
	body         []byte
	contentLen   int64
}

type retryRig struct {
	t   *testing.T
	gh  *ghtest.Server
	h   *gitproxy.Handler
	log *bytes.Buffer

	mu     sync.Mutex
	reqs   []seen
	status func(n int) int // answer for the n-th request (1-based)
	waits  []time.Duration
	onWait func() // runs inside Wait, before it returns
}

// newRetryRig starts an upstream that answers status(n) to request n, with 200
// and "pack" when status returns 0.
func newRetryRig(t *testing.T, status func(n int) int) *retryRig {
	t.Helper()
	s := ghtest.New(t)
	c, err := gh.New(gh.Config{AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	in := s.AddInstallation(7, "acme", map[string]string{"contents": "write", "metadata": "read", "pull_requests": "write"})
	in.AddRepo("shop", "main")
	in.AddRepo("other", "main")

	f := &retryRig{t: t, gh: s, log: &bytes.Buffer{}, status: status}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, pw, _ := r.BasicAuth()
		f.mu.Lock()
		f.reqs = append(f.reqs, seen{r.Method, r.URL.Path, pw, b, r.ContentLength})
		code := f.status(len(f.reqs))
		f.mu.Unlock()
		if code == 0 {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			_, _ = io.WriteString(w, "pack")
			return
		}
		http.Error(w, "Repository not found.", code)
	}))
	t.Cleanup(up.Close)

	f.h = &gitproxy.Handler{
		Gate: openGate{}, Tokens: &ops.InstallationMinter{Client: c}, Revoker: c, Upstream: up.URL,
		Now: s.Now,
		Log: slog.New(slog.NewTextHandler(f.log, nil)),
		Wait: func(ctx context.Context, d time.Duration) error {
			f.mu.Lock()
			f.waits = append(f.waits, d)
			f.mu.Unlock()
			if f.onWait != nil {
				f.onWait()
			}
			return ctx.Err()
		},
	}
	return f
}

func (f *retryRig) minted() int {
	n := 0
	for _, r := range f.gh.Requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/access_tokens") {
			n++
		}
	}
	return n
}

// get serves a discovery GET.
func (f *retryRig) get(ctx context.Context) (*httptest.ResponseRecorder, error) {
	req := httptest.NewRequest("GET", "/git/acme/shop.git/info/refs?service=git-upload-pack", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	return rec, f.h.ServeGit(rec, req, runCaller("r-1"))
}

// post serves an upload-pack POST; length is the Content-Length the client
// announced (-1 for chunked).
func (f *retryRig) post(body []byte, length int64) (*httptest.ResponseRecorder, error) {
	req := httptest.NewRequest("POST", "/git/acme/shop.git/git-upload-pack", bytes.NewReader(body))
	req.ContentLength = length
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	rec := httptest.NewRecorder()
	return rec, f.h.ServeGit(rec, req, runCaller("r-1"))
}

func (f *retryRig) requireOneToken() {
	f.t.Helper()
	if n := f.minted(); n != 1 {
		f.t.Errorf("%d tokens minted, want 1 for the whole request, repeats included", n)
	}
	f.h.EndRun("r-1")
	f.h.WaitRevokes()
	if n := f.gh.LiveTokens(); n != 0 {
		f.t.Errorf("%d installation tokens still live after the run ended", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.reqs {
		if r.password == "" || r.password != f.reqs[0].password {
			f.t.Errorf("request %d carried another token than request 1", i+1)
		}
		if strings.Contains(f.log.String(), r.password) {
			f.t.Fatal("the log holds the token")
		}
	}
}

func wantWaits(t *testing.T, got []time.Duration, want ...time.Duration) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("pauses %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pauses %v, want %v", got, want)
		}
	}
}

func TestDiscoveryIsRepeatedAfter404WithTheSameToken(t *testing.T) {
	f := newRetryRig(t, func(n int) int {
		if n <= 2 {
			return 404
		}
		return 0
	})
	rec, err := f.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || rec.Body.String() != "pack" {
		t.Fatalf("answer %d %q, want 200 pack", rec.Code, rec.Body.String())
	}
	if len(f.reqs) != 3 {
		t.Errorf("upstream got %d requests, want 3 (two 404, one 200)", len(f.reqs))
	}
	wantWaits(t, f.waits, 500*time.Millisecond, time.Second)
	if n := strings.Count(f.log.String(), "repeating the request"); n != 2 {
		t.Errorf("%d Info lines for the repeats, want 2:\n%s", n, f.log)
	}
	f.requireOneToken()
}

func TestPersistent404IsStillNotFoundAfterTheCap(t *testing.T) {
	f := newRetryRig(t, func(int) int { return 404 })
	rec, err := f.get(context.Background())
	var nf *ops.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v, want *ops.NotFoundError", err)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("something was written to the client: %q", rec.Body)
	}
	if len(f.reqs) != 4 {
		t.Errorf("upstream got %d requests, want 1 + 3 repeats", len(f.reqs))
	}
	wantWaits(t, f.waits, 500*time.Millisecond, time.Second, 2*time.Second) // 3.5 s in all
	f.requireOneToken()
}

func TestPostBodyIsReplayedByteForByte(t *testing.T) {
	f := newRetryRig(t, func(n int) int {
		if n <= 2 {
			return 404
		}
		return 0
	})
	body := make([]byte, 5000)
	_, _ = rand.Read(body) // includes NUL, CR, LF and every other byte value
	rec, err := f.post(body, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 {
		t.Fatalf("answer %d", rec.Code)
	}
	if len(f.reqs) != 3 {
		t.Fatalf("upstream got %d requests, want 3", len(f.reqs))
	}
	for i, r := range f.reqs {
		if !bytes.Equal(r.body, body) || r.contentLen != int64(len(body)) {
			t.Errorf("request %d: %d body bytes (Content-Length %d), want the %d bytes of the client's body",
				i+1, len(r.body), r.contentLen, len(body))
		}
	}
	f.requireOneToken()
}

func TestBodyThatCannotBeReplayedIsNotRetried(t *testing.T) {
	body := bytes.Repeat([]byte("want 0123\n"), 100)
	for name, tc := range map[string]struct {
		body   []byte
		length int64
	}{
		"chunked":          {body, -1},
		"over the cap":     {make([]byte, 1<<20+1), 1<<20 + 1},
		"known but absent": {nil, 2000}, // a client that promises 2000 bytes and sends none
	} {
		t.Run(name, func(t *testing.T) {
			f := newRetryRig(t, func(int) int { return 404 })
			_, err := f.post(tc.body, tc.length)
			if name == "known but absent" {
				var ue *ops.UnavailableError
				if !errors.As(err, &ue) || len(f.reqs) != 0 {
					t.Fatalf("error %v after %d upstream requests, want UnavailableError and none", err, len(f.reqs))
				}
				return
			}
			var nf *ops.NotFoundError
			if !errors.As(err, &nf) {
				t.Fatalf("error %v, want *ops.NotFoundError", err)
			}
			if len(f.reqs) != 1 || len(f.waits) != 0 {
				t.Errorf("%d upstream requests and %d pauses, want 1 and 0: a body read once cannot be sent twice", len(f.reqs), len(f.waits))
			}
			f.h.EndRun("r-1")
			f.h.WaitRevokes()
			if n := f.gh.LiveTokens(); n != 0 {
				t.Errorf("%d tokens still live", n)
			}
		})
	}
}

func TestCancelDuringThePauseStopsTheRepeats(t *testing.T) {
	f := newRetryRig(t, func(int) int { return 404 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onWait = cancel // the client goes away while chapd waits
	_, err := f.get(ctx)
	var nf *ops.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v, want the 404 GitHub gave", err)
	}
	if len(f.reqs) != 1 || len(f.waits) != 1 {
		t.Errorf("%d upstream requests and %d pauses, want 1 and 1", len(f.reqs), len(f.waits))
	}
	f.h.EndRun("r-1")
	f.h.WaitRevokes()
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens still live", n)
	}
}

func TestOtherAnswersAreNotRepeated(t *testing.T) {
	for _, code := range []int{0, 401, 403, 500, 502} {
		f := newRetryRig(t, func(int) int { return code })
		_, _ = f.get(context.Background())
		if len(f.reqs) != 1 || len(f.waits) != 0 {
			t.Errorf("status %d: %d upstream requests and %d pauses, want 1 and 0", code, len(f.reqs), len(f.waits))
		}
	}
}

func TestEmptyRetryDelaysTurnRepeatingOff(t *testing.T) {
	f := newRetryRig(t, func(int) int { return 404 })
	f.h.RetryDelays = []time.Duration{}
	_, err := f.get(context.Background())
	var nf *ops.NotFoundError
	if !errors.As(err, &nf) || len(f.reqs) != 1 {
		t.Fatalf("error %v after %d requests, want one 404", err, len(f.reqs))
	}
}
