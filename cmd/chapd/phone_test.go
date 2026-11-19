package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

const testPhoneHost = "pc.tail1234.ts.net"

func getAt(t *testing.T, base, host, path string) (int, string, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Host = host
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, resp.Header.Get("Location"), b.String()
}

// -phone-host puts the phone origin on the console: it answers at that Host only,
// the phone page exists there and not at the PC's, and the sign-in page is the phone's.
func TestPhoneHostTurnsOnThePhoneOrigin(t *testing.T) {
	e := newApprE2E(t, func(cfg *Config, _, _ string) { cfg.PhoneHost = testPhoneHost })

	if code, loc, _ := getAt(t, e.srv.URL, testPhoneHost, "/phone"); code != http.StatusSeeOther || loc != "/login" {
		t.Fatalf("GET /phone at the phone host: %d %q, want a redirect to /login", code, loc)
	}
	if code, _, body := getAt(t, e.srv.URL, testPhoneHost, "/login"); code != 200 || !strings.Contains(body, "Sign in with your passkey") {
		t.Fatalf("GET /login at the phone host: %d", code)
	}
	if code, loc, _ := getAt(t, e.srv.URL, testPhoneHost, "/approvals"); code != http.StatusSeeOther || loc != "/login" {
		t.Fatalf("GET /approvals signed out at the phone host: %d %q", code, loc)
	}
	if code, _, _ := getAt(t, e.srv.URL, "localhost:55398", "/phone"); code != http.StatusNotFound {
		t.Fatalf("GET /phone at the PC: %d, want 404", code)
	}
	if code, _, body := getAt(t, e.srv.URL, "localhost:55398", "/login"); code != 200 || !strings.Contains(body, "Sign in with a passkey") {
		t.Fatalf("GET /login at the PC: %d", code)
	}
	for _, host := range []string{"pc.tail1234.ts.net.evil.example", "other.tail1234.ts.net", "pc.tail1234.ts.net:8443"} {
		if code, _, _ := getAt(t, e.srv.URL, host, "/login"); code != http.StatusForbidden {
			t.Fatalf("Host %s: %d, want 403", host, code)
		}
	}
}

// Without -phone-host there is no phone: its Host is refused and the page is absent.
func TestNoPhoneHostNoPhone(t *testing.T) {
	e := newApprE2E(t)
	if code, _, _ := getAt(t, e.srv.URL, testPhoneHost, "/login"); code != http.StatusForbidden {
		t.Fatalf("the phone host answered without -phone-host: %d", code)
	}
	if code, _, _ := getAt(t, e.srv.URL, "localhost:55398", "/phone"); code != http.StatusNotFound {
		t.Fatalf("GET /phone: %d, want 404", code)
	}
}

// A phone host that is not a full tailnet name stops chapd at start.
func TestBadPhoneHostStopsChapd(t *testing.T) {
	for _, bad := range []string{"localhost", "pc", "127.0.0.1", "https://pc.tail1234.ts.net", "pc.tail1234.ts.net/x"} {
		dir := t.TempDir()
		_, err := Build(context.Background(), Config{
			DBPath: filepath.Join(dir, "state.db"), KeysPath: writeKeys(t, dir), Instance: "test", PhoneHost: bad,
		})
		if err == nil || !strings.Contains(err.Error(), "-phone-host") {
			t.Errorf("-phone-host %q: %v", bad, err)
		}
	}
}
