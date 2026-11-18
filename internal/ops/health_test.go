package ops

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/spec"
)

type readyServer struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	body    string
	methods []string
	hosts   []string
	protos  []string
	paths   []string
}

func newReadyServer(t *testing.T, status int, body string) *readyServer {
	t.Helper()
	rs := &readyServer{status: status, body: body}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.methods = append(rs.methods, r.Method)
		rs.hosts = append(rs.hosts, r.Host)
		rs.protos = append(rs.protos, r.Header.Get("X-Forwarded-Proto"))
		rs.paths = append(rs.paths, r.URL.Path)
		st, b := rs.status, rs.body
		rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *readyServer) health(t *testing.T) *PilotHealth {
	t.Helper()
	h, err := NewPilotHealth(PilotHealthConfig{URL: rs.URL + "/api/health/ready"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const readyOK = `{"checks":{"auth":true,"database":true},"service":"web","status":"ok"}`

func TestPilotHealthSendsTheHeadersTheFenceNeeds(t *testing.T) {
	rs := newReadyServer(t, 200, readyOK)
	st := rs.health(t).Check(context.Background())
	if !st.OK() || st.HTTPStatus != 200 {
		t.Fatalf("status = %+v", st)
	}
	if len(rs.methods) != 1 || rs.methods[0] != http.MethodGet || rs.paths[0] != "/api/health/ready" ||
		rs.hosts[0] != "pilot.storefront.net" || rs.protos[0] != "https" {
		t.Errorf("request = %v %v host %v proto %v", rs.methods, rs.paths, rs.hosts, rs.protos)
	}
}

func TestPilotHealthReadsTheAnswer(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"ok", 200, readyOK, HealthOK},
		{"ok with NUL bytes from wsl.exe", 200, "{\x00\"status\":\"ok\"}\x00", HealthOK},
		{"not ready", 503, `{"checks":{"auth":false,"database":true},"service":"web","status":"unavailable"}`, HealthUnavailable},
		{"503 with no body", 503, ``, HealthMalformed},
		{"status ok on a 503 is not trusted", 503, `{"status":"ok"}`, HealthMalformed},
		{"status ok on a 500 is not trusted", 500, `{"status":"ok"}`, HealthMalformed},
		{"html error page", 200, `<html>Cloudflare Access</html>`, HealthMalformed},
		{"status is not a string", 200, `{"status":true}`, HealthMalformed},
		{"other word", 200, `{"status":"degraded"}`, HealthMalformed},
		{"ok inside text only", 200, `"status":"ok"`, HealthMalformed},
		{"empty", 200, ``, HealthMalformed},
		{"404 from the fence", 404, `{"status":"ok"}`, HealthMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := newReadyServer(t, c.status, c.body)
			if got := rs.health(t).Check(context.Background()).Status; got != c.want {
				t.Errorf("status = %s, want %s", got, c.want)
			}
		})
	}
}

func TestPilotHealthNeverFollowsARedirect(t *testing.T) {
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere++
		_, _ = w.Write([]byte(readyOK))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	h, err := NewPilotHealth(PilotHealthConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if st := h.Check(context.Background()); st.OK() || elsewhere != 0 {
		t.Errorf("status = %+v, redirected calls = %d", st, elsewhere)
	}
}

func TestPilotHealthUnreachable(t *testing.T) {
	rs := newReadyServer(t, 200, readyOK)
	h := rs.health(t)
	rs.Close()
	if st := h.Check(context.Background()); st.Status != HealthUnreachable || st.HTTPStatus != 0 {
		t.Errorf("status = %+v", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if st := h.Check(ctx); st.Status != HealthUnreachable {
		t.Errorf("a cancelled context: %+v", st)
	}
}

func TestPilotHealthOnlyOnLoopback(t *testing.T) {
	for _, bad := range []string{
		"https://127.0.0.1:55350/api/health/ready", "http://example.com/api/health/ready", "http://10.0.0.5:55350/x",
		"http://user:pw@127.0.0.1:55350/x", "ftp://127.0.0.1/x", "/api/health/ready", "http://[2001:db8::1]/x", "http://127.0.0.1.evil.test/x",
	} {
		if _, err := NewPilotHealth(PilotHealthConfig{URL: bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	for _, good := range []string{DefaultPilotReadyURL, "http://localhost:55350/x", "http://[::1]:55350/x"} {
		if _, err := NewPilotHealth(PilotHealthConfig{URL: good}); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if _, err := NewPilotHealth(PilotHealthConfig{Host: "evil.test\r\nX: y"}); err == nil {
		t.Error("a Host value with a line break must be refused")
	}
}

func healthReq(adapter, ref string, params map[string]any) *Request {
	return &Request{ID: "q-000001", Op: "health", Project: "storefront",
		Target: spec.Target{Adapter: adapter, Ref: ref}, Params: params, Caller: &Caller{Kind: KindRun, RunID: "r-7f3a"}}
}

func TestHealthAdapter(t *testing.T) {
	rs := newReadyServer(t, 200, readyOK)
	a := NewHealthAdapter(rs.health(t))

	// Check never touches the pilot: a dry run, an approval request and a release
	// re-check would each make a call otherwise.
	for _, ref := range []string{"health", "readiness"} {
		if _, err := a.Check(context.Background(), healthReq("pilot", ref, map[string]any{})); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	if len(rs.methods) != 0 {
		t.Fatalf("Check made %d call(s) to the pilot", len(rs.methods))
	}

	out, err := a.Execute(context.Background(), healthReq("pilot", "health", map[string]any{}))
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v err = %v", out, err)
	}
	if out.Result["status"] != "ok" || out.Result["ok"] != true || out.Result["http_status"] != 200 || out.Result["checked_at"] == "" {
		t.Errorf("result = %v", out.Result)
	}
	if len(rs.methods) != 1 || rs.methods[0] != http.MethodGet {
		t.Errorf("calls = %v", rs.methods)
	}

	rs.mu.Lock()
	rs.status, rs.body = 503, `{"status":"unavailable"}`
	rs.mu.Unlock()
	out, _ = a.Execute(context.Background(), healthReq("pilot", "health", map[string]any{}))
	if out.Failed || out.Result["status"] != "unavailable" || out.Result["ok"] != false {
		t.Errorf("a pilot that says it is not ready is a successful read: %+v", out)
	}
	if _, leaked := out.Result["checks"]; leaked {
		t.Error("the pilot's body must not be echoed")
	}

	bad := []*Request{
		healthReq("pilot", "health", map[string]any{"url": "http://evil.test"}),
		healthReq("wsl-host", "pilot", map[string]any{}),
		healthReq("pilot", "other", map[string]any{}),
	}
	for i, r := range bad {
		_, err := a.Check(context.Background(), r)
		var ref *Refusal
		if !errors.As(err, &ref) || ref.Code != CodeParamsInvalid {
			t.Errorf("bad request %d: err = %v", i, err)
		}
	}
	if len(rs.methods) != 2 {
		t.Errorf("a refused request must not reach the pilot: %d calls", len(rs.methods))
	}
}
