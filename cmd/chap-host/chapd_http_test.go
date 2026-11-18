package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedPost struct {
	path, auth, ctype, body string
}

type sseServer struct {
	*httptest.Server
	mu    sync.Mutex
	posts []recordedPost
	auths []string
	body  string // what the next event stream sends before closing
	code  int
}

func newSSEServer(t *testing.T) *sseServer {
	s := &sseServer{code: 200}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v0/host/events":
			s.auths = append(s.auths, r.Header.Get("Authorization"))
			if s.code != 200 {
				http.Error(w, "no", s.code)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, s.body)
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			s.posts = append(s.posts, recordedPost{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func tokenFile(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "host.token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHTTPChapdEvents(t *testing.T) {
	s := newSSEServer(t)
	s.body = ": keep-alive\n\n" +
		"event: approvals.pending\ndata: {\"count\":3}\n\n" +
		"event: something.new\ndata: {}\n\n" +
		"event: grant\ndata: {\"grant\":\"lg1.a.b\",\"op_id\":\"op_7\"}\n\n"
	c := NewHTTPChapd(s.URL, tokenFile(t, "tok-123\n"), nil)
	ctx := context.Background()

	ev, err := c.Next(ctx)
	if err != nil || ev.Kind != EventApprovals || ev.Pending != 3 {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = c.Next(ctx)
	if err != nil || ev.Kind != EventGrant || ev.OpID != "op_7" || ev.Grant != "lg1.a.b" {
		t.Fatalf("%+v %v", ev, err)
	}
	if _, err = c.Next(ctx); err == nil { // stream closed
		t.Fatal("end of stream is an error")
	}
	// The next call reconnects.
	if ev, err = c.Next(ctx); err != nil || ev.Pending != 3 {
		t.Fatalf("reconnect: %+v %v", ev, err)
	}
	for _, a := range s.auths {
		if a != "Bearer tok-123" {
			t.Fatalf("Authorization %q", a)
		}
	}
}

func TestHTTPChapdBadEvents(t *testing.T) {
	for name, body := range map[string]string{
		"negative count": "event: approvals.pending\ndata: {\"count\":-1}\n\n",
		"missing count":  "event: approvals.pending\ndata: {}\n\n",
		"extra field":    "event: approvals.pending\ndata: {\"count\":1,\"x\":1}\n\n",
		"not json":       "event: approvals.pending\ndata: three\n\n",
		"bad op id":      "event: grant\ndata: {\"grant\":\"g\",\"op_id\":\"../x\"}\n\n",
		"no grant":       "event: grant\ndata: {\"op_id\":\"op1\"}\n\n",
	} {
		s := newSSEServer(t)
		s.body = body
		if _, err := NewHTTPChapd(s.URL, tokenFile(t, "t"), nil).Next(context.Background()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHTTPChapdRefusals(t *testing.T) {
	s := newSSEServer(t)
	s.code = 401
	if _, err := NewHTTPChapd(s.URL, tokenFile(t, "t"), nil).Next(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("got %v", err)
	}
	// No token, no request.
	s2 := newSSEServer(t)
	for _, f := range []string{filepath.Join(t.TempDir(), "missing"), tokenFile(t, " \n")} {
		if _, err := NewHTTPChapd(s2.URL, f, nil).Next(context.Background()); err == nil {
			t.Errorf("connected with token file %q", f)
		}
	}
	if len(s2.auths) != 0 {
		t.Fatal("a request was sent without a token")
	}
}

func TestHTTPChapdReports(t *testing.T) {
	s := newSSEServer(t)
	c := NewHTTPChapd(s.URL, tokenFile(t, "tok"), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Output(ctx, "op_7", []byte("line\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.Done(ctx, "op_7", Result{Status: "refused", Code: "GRANT_EXPIRED", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := c.Done(ctx, "../x", Result{}); err == nil {
		t.Fatal("bad op id accepted")
	}
	if len(s.posts) != 2 {
		t.Fatalf("posts: %+v", s.posts)
	}
	out, res := s.posts[0], s.posts[1]
	if out.path != "/v0/host/runs/op_7/output" || out.body != "line\n" || out.ctype != "application/octet-stream" || out.auth != "Bearer tok" {
		t.Fatalf("%+v", out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(res.body), &got); err != nil {
		t.Fatal(err)
	}
	if res.path != "/v0/host/runs/op_7/result" || got["outcome"] != "refused" || got["code"] != "GRANT_EXPIRED" || got["exit_code"] != float64(0) || len(got) != 3 {
		t.Fatalf("%+v", res)
	}
}
