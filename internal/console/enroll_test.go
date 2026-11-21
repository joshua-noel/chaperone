package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a bytes.Buffer that RunEnroll can write while the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// wire is an HTTP client that behaves like a browser at http://localhost:port
// while dialling 127.0.0.1, against the real listener RunEnroll opens.
type wire struct {
	t      *testing.T
	c      *http.Client
	origin string
}

func newWire(t *testing.T, port int) *wire {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &wire{t: t, c: &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		origin: fmt.Sprintf("http://localhost:%d", port)}
}

func (w *wire) csrf() string {
	w.t.Helper()
	res, err := w.c.Get(w.origin + "/enroll")
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	m := metaCSRF.FindStringSubmatch(string(b))
	if m == nil {
		w.t.Fatalf("no csrf token: %d %s", res.StatusCode, b)
	}
	return m[1]
}

func (w *wire) post(path string, body []byte, ceremony string) (int, map[string]json.RawMessage) {
	w.t.Helper()
	req, _ := http.NewRequest("POST", w.origin+path, bytes.NewReader(body))
	req.Header.Set("Origin", w.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", w.csrf())
	if ceremony != "" {
		req.Header.Set("X-Ceremony-ID", ceremony)
	}
	res, err := w.c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]json.RawMessage
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func waitForText(t *testing.T, out *syncBuf, re *regexp.Regexp, done <-chan error) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			return m
		}
		select {
		case err := <-done:
			t.Fatalf("RunEnroll ended early: %v\n%s", err, out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s in:\n%s", re, out.String())
	return nil
}

func TestRunEnrollEndToEnd(t *testing.T) {
	port := freePort(t)
	opt := EnrollOptions{
		DBPath: filepath.Join(t.TempDir(), "state.db"),
		Addr:   fmt.Sprintf("127.0.0.1:%d", port),
		Origin: Origin{RPID: "localhost", URL: fmt.Sprintf("http://localhost:%d", port)},
		TTL:    time.Minute,
	}
	out := &syncBuf{}
	opt.Out = out
	done := make(chan error, 1)
	go func() { done <- RunEnroll(context.Background(), opt) }()

	m := waitForText(t, out, regexp.MustCompile(`(?m)^\s+(http://localhost:\d+)/enroll#(\S+)$`), done)
	if m[1] != opt.Origin.URL {
		t.Fatalf("printed origin %q", m[1])
	}
	token := m[2]
	w := newWire(t, port)

	// A wrong Host on the real listener is refused (DNS rebinding).
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://evil.example:%d/enroll", port), nil)
	if res, err := w.c.Do(req); err != nil || res.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding probe: %v %v", res, err)
	}

	// Register.
	body, _ := json.Marshal(map[string]string{"token": token, "name": "operator", "label": "Hello"})
	code, begun := w.post("/enroll/begin", body, "")
	if code != 200 {
		t.Fatal(code, begun)
	}
	a := newAuthenticator(t, "localhost")
	code, fin := w.post("/enroll/finish", a.create(begun["options"], w.origin, opts{}), str(begun["ceremony"]))
	if code != 200 {
		t.Fatal(code, fin)
	}
	waitForText(t, out, regexp.MustCompile(`OK console\.enrolled credential_id=\S+ rp_id=localhost origin=\S+ uv=true`), done)

	// Assert.
	code, begun = w.post("/login/begin", nil, "")
	if code != 200 {
		t.Fatal(code, begun)
	}
	code, fin = w.post("/login/finish", a.get(begun["options"], w.origin, opts{}), str(begun["ceremony"]))
	if code != 200 {
		t.Fatal(code, fin)
	}
	if err := <-done; err != nil {
		t.Fatalf("RunEnroll: %v\n%s", err, out.String())
	}
	if !regexp.MustCompile(`OK console\.login credential_id=\S+ rp_id=localhost origin=\S+ uv=true sign_count=1`).MatchString(out.String()) {
		t.Fatalf("no login evidence line:\n%s", out.String())
	}
	if strings.Contains(out.String()[strings.Index(out.String(), "Done"):], token) {
		t.Fatal("token printed after use")
	}

	// The server is gone, and a second enrolment is refused.
	if c, err := net.DialTimeout("tcp", opt.Addr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener still open after RunEnroll returned")
	}
	err := RunEnroll(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("second enrolment: %v", err)
	}

	// --check works against the stored credential.
	opt2 := opt
	opt2.CheckOnly = true
	out2 := &syncBuf{}
	opt2.Out = out2
	go func() { done <- RunEnroll(context.Background(), opt2) }()
	waitForText(t, out2, regexp.MustCompile(`Now test the assertion`), done)
	w2 := newWire(t, port)
	code, begun = w2.post("/login/begin", nil, "")
	if code != 200 {
		t.Fatal(code, begun)
	}
	code, fin = w2.post("/login/finish", a.get(begun["options"], w2.origin, opts{}), str(begun["ceremony"]))
	if code != 200 {
		t.Fatal(code, fin)
	}
	if err := <-done; err != nil {
		t.Fatalf("--check: %v\n%s", err, out2.String())
	}
}

func TestRunEnrollRefusals(t *testing.T) {
	dir := t.TempDir()
	// --check with nobody enrolled.
	err := RunEnroll(context.Background(), EnrollOptions{DBPath: filepath.Join(dir, "a.db"), CheckOnly: true})
	if err == nil || !strings.Contains(err.Error(), "no approver") {
		t.Fatalf("check on empty db: %v", err)
	}
	// Port already taken.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	err = RunEnroll(context.Background(), EnrollOptions{DBPath: filepath.Join(dir, "b.db"), Addr: ln.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "cannot listen") {
		t.Fatalf("busy port: %v", err)
	}
	// Timeout.
	port := freePort(t)
	err = RunEnroll(context.Background(), EnrollOptions{
		DBPath: filepath.Join(dir, "c.db"), Addr: fmt.Sprintf("127.0.0.1:%d", port),
		Origin: Origin{RPID: "localhost", URL: fmt.Sprintf("http://localhost:%d", port)}, TTL: 150 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout: %v", err)
	}
}

// The browser is sent to localhost, which may mean ::1: `chapd enroll` holds
// [::1]:PORT too, and refuses to start when another program is on it.
func TestRunEnrollHoldsIPv6Loopback(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	probe.Close()
	var port int
	var squatter net.Listener
	for range 50 { // a port free on both stacks
		port = freePort(t)
		if squatter, err = net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port)); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	err = RunEnroll(context.Background(), EnrollOptions{
		DBPath: filepath.Join(t.TempDir(), "a.db"), Addr: fmt.Sprintf("127.0.0.1:%d", port),
		Origin: Origin{RPID: "localhost", URL: fmt.Sprintf("http://localhost:%d", port)},
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("[::1]:%d", port)) || !strings.Contains(err.Error(), "Another program") {
		t.Fatalf("started with another program on [::1]: %v", err)
	}
	squatter.Close()

	// Free again: the console answers on both addresses, to Host localhost only.
	opt := EnrollOptions{
		DBPath: filepath.Join(t.TempDir(), "b.db"), Addr: fmt.Sprintf("127.0.0.1:%d", port),
		Origin: Origin{RPID: "localhost", URL: fmt.Sprintf("http://localhost:%d", port)}, TTL: time.Minute,
	}
	out := &syncBuf{}
	opt.Out = out
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunEnroll(ctx, opt) }()
	waitForText(t, out, regexp.MustCompile(`/enroll#\S+`), done)
	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port)} {
		req, _ := http.NewRequest("GET", "http://"+addr+"/enroll", nil)
		req.Host = fmt.Sprintf("localhost:%d", port)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("%s: %v %v", addr, res, err)
		}
		if res != nil {
			res.Body.Close()
		}
	}
	cancel()
	<-done
}
