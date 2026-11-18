package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/api"
	"github.com/joshua-noel/chaperone/internal/runtoken"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// ctlSigner is one pinned the runner key: the test holds the private half.
type ctlSigner struct {
	priv        ed25519.PrivateKey
	kid, issuer string
}

func (s ctlSigner) pub() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

func newCtlSigner(t *testing.T, kid, issuer string) ctlSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ctlSigner{priv: priv, kid: kid, issuer: issuer}
}

func (s ctlSigner) sign(t *testing.T, typ string, claims any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": s.kid, "typ": typ})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload)
	return in + "." + enc.EncodeToString(ed25519.Sign(s.priv, []byte(in)))
}

// control mints a control JWT for act about runID, valid for 60 s, with a fresh jti.
func (s ctlSigner) control(t *testing.T, act, runID string) string {
	t.Helper()
	var raw [12]byte
	_, _ = rand.Read(raw[:])
	now := time.Now().Unix()
	return s.sign(t, "factory-ctl+jwt", map[string]any{
		"iss": s.issuer, "aud": "chaperone", "iat": now, "exp": now + 60,
		"jti": "ctl-" + base64.RawURLEncoding.EncodeToString(raw[:]), "act": act, "run_id": runID,
	})
}

// runToken makes the golden code-run token for runID under the golden profile.
func (s ctlSigner) runToken(t *testing.T, runID, jti string) string {
	t.Helper()
	now := time.Now().Unix()
	return s.sign(t, "factory-run+jwt", spec.RunTokenClaims{
		Iss: s.issuer, Sub: "run:" + runID, Aud: "chaperone",
		Iat: now, Exp: now + 90*60,
		JTI: jti, RunID: runID, Project: "acme-shop",
		Profile:   spec.TokenProfile{Name: "code", Version: "1.0.0", Digest: goldenDigest},
		BriefSHA:  "sha256:7ed2358fdd424519b90502f453c9ab84266b75d6c17db83fdb89511dd61d67c1",
		Isolation: "gvisor",
		TaskScope: spec.TaskScope{Repo: "acme/shop", Base: "main", Branch: "agent/" + runID,
			Paths: []string{"services/sync/src/**"}, Ops: []string{"pr.open", "branch.push"}},
		Budget: spec.Budget{Minutes: 90, Tokens: 2000000},
	})
}

type statusRig struct {
	t       *testing.T
	e       *e2e
	far     ctlSigner // the the runner that registers runs
	other   ctlSigner // a second pinned the runner that registers nothing
	orchTok string
}

func newStatusRig(t *testing.T) *statusRig {
	t.Helper()
	dir := t.TempDir()
	r := &statusRig{t: t,
		far:   newCtlSigner(t, "runner-1", "runner.test"),
		other: newCtlSigner(t, "runner-2", "runner.other"),
	}
	keys := map[string]any{"version": 1, "allow_interim": false, "keys": []any{
		map[string]any{"kid": r.far.kid, "issuer": r.far.issuer, "public_key": base64.RawURLEncoding.EncodeToString(r.far.pub())},
		map[string]any{"kid": r.other.kid, "issuer": r.other.issuer, "public_key": base64.RawURLEncoding.EncodeToString(r.other.pub())},
	}}
	b, _ := json.Marshal(keys)
	keysPath := filepath.Join(dir, "run-keys.json")
	if err := os.WriteFile(keysPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	profiles := filepath.Join(dir, "profiles")
	var out, errb bytes.Buffer
	if code := profileCmd([]string{"add", "-file", goldenProfileFile(t, dir), "-profiles-dir", profiles}, &out, &errb); code != 0 {
		t.Fatalf("profile add: %d %s", code, errb.String())
	}
	db := filepath.Join(dir, "state.db")
	tokenFile := filepath.Join(dir, "home", "orchestrator.token")
	if code := orchCmd([]string{"issue", "-db", db, "-project", "acme-shop", "-ops", "pr.merge,health", "-token-file", tokenFile, "-days", "7"}, &out, &errb); code != 0 {
		t.Fatalf("orch issue: %d %s", code, errb.String())
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	r.orchTok = strings.TrimSpace(string(raw))
	app, err := Build(context.Background(), Config{DBPath: db, KeysPath: keysPath, Instance: "test", ProfilesDir: profiles})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	r.e = &e2e{t: t, app: app, srv: srv, db: db, token: r.orchTok}
	return r
}

// register registers a run of r.far and returns its run token.
func (r *statusRig) register(runID, jti string) (runTok string, body map[string]any) {
	r.t.Helper()
	runTok = r.far.runToken(r.t, runID, jti)
	st, body := r.e.call("POST", "/v0/runs", "", map[string]string{
		"control": r.far.control(r.t, "run.start", runID), "token": runTok})
	if st != 201 {
		r.t.Fatalf("register %s: %d %v", runID, st, body)
	}
	return runTok, body
}

// get is GET /v0/runs/{id} with the given Authorization header values.
func (r *statusRig) get(runID string, query string, auth ...string) (int, http.Header, map[string]any, string) {
	r.t.Helper()
	path := r.e.srv.URL + "/v0/runs/" + runID
	if query != "" {
		path += "?" + query
	}
	req, _ := http.NewRequest("GET", path, nil)
	req.Host = "127.0.0.1:55398"
	for _, a := range auth {
		req.Header.Add("Authorization", a)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return resp.StatusCode, resp.Header, m, string(data)
}

func (r *statusRig) read(s ctlSigner, runID string) (int, map[string]any, string) {
	r.t.Helper()
	st, _, m, raw := r.get(runID, "", "Bearer "+s.control(r.t, "run.status", runID))
	return st, m, raw
}

// LF-2 end to end: a pinned the runner key reads its own run, nothing else
// reads it, and a revoked run shows state ended with its cause.
func TestRunStatusHTTP(t *testing.T) {
	r := newStatusRig(t)
	runTok, reg := r.register("r-lf2a", "n8Gf3kQ2xV7bTz1LwA9cYd")
	r.register("r-lf2b", "p4Hq7mR1yW8cUa2MxB0dZe")

	t.Run("the owner reads an active run: four members", func(t *testing.T) {
		st, h, m, raw := r.get("r-lf2a", "", "Bearer "+r.far.control(t, "run.status", "r-lf2a"))
		if st != 200 || h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v %s", st, h, raw)
		}
		want := map[string]any{"state": "active", "ended_at": nil, "cause_code": nil, "expires_at": reg["expires_at"]}
		if !reflect.DeepEqual(m, want) {
			t.Fatalf("body %s, want %v", raw, want)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		goodCtl := func(act, id string) string { return r.far.control(t, act, id) }
		type try struct {
			name   string
			id     string // the run in the path
			query  string
			auth   []string
			status int
			code   string // cause_code of an auth_error, "" for a 404
		}
		replayed := goodCtl("run.status", "r-lf2a")
		if st, _, _, raw := r.get("r-lf2a", "", "Bearer "+replayed); st != 200 {
			t.Fatalf("first use of the token: %d %s", st, raw)
		}
		const a, n = "r-lf2a", "r-nope1"
		for _, c := range []try{
			{"no credential", a, "", nil, 401, "TOKEN_INVALID"},
			{"the run token of the run", a, "", []string{"Bearer " + runTok}, 401, "TOKEN_INVALID"},
			{"the orchestrator token", a, "", []string{"Bearer " + r.orchTok}, 401, "TOKEN_INVALID"},
			{"a control JWT for run.start", a, "", []string{"Bearer " + goodCtl("run.start", a)}, 401, "TOKEN_INVALID"},
			{"a control JWT for run.end", a, "", []string{"Bearer " + goodCtl("run.end", a)}, 401, "TOKEN_INVALID"},
			{"a control JWT for another run", a, "", []string{"Bearer " + goodCtl("run.status", "r-lf2b")}, 401, "TOKEN_INVALID"},
			{"a used control JWT", a, "", []string{"Bearer " + replayed}, 401, "TOKEN_INVALID"},
			{"two Authorization headers", a, "", []string{"Bearer " + goodCtl("run.status", a), "Bearer " + goodCtl("run.status", a)}, 401, "TOKEN_INVALID"},
			{"a comma-joined pair", a, "", []string{"Bearer " + goodCtl("run.status", a) + ", Bearer " + r.orchTok}, 401, "TOKEN_INVALID"},
			{"a credential in the query", a, "access_token=" + goodCtl("run.status", a), []string{"Bearer " + goodCtl("run.status", a)}, 401, "TOKEN_INVALID"},
			{"basic auth", a, "", []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+goodCtl("run.status", a)))}, 401, "TOKEN_INVALID"},
			{"another pinned the runner's control JWT for this run", a, "", []string{"Bearer " + r.other.control(t, "run.status", a)}, 404, ""},
			{"a run that does not exist", n, "", []string{"Bearer " + goodCtl("run.status", n)}, 404, ""},
		} {
			st, _, m, raw := r.get(c.id, c.query, c.auth...)
			if st != c.status {
				t.Errorf("%s: status %d, want %d (%s)", c.name, st, c.status, raw)
				continue
			}
			switch {
			case c.code != "" && (m["type"] != "auth_error" || m["cause_code"] != c.code):
				t.Errorf("%s: body %s", c.name, raw)
			case c.code == "" && m["type"] != "not_found":
				t.Errorf("%s: body %s", c.name, raw)
			}
			// A refusal never carries a run's data.
			for _, leak := range []string{"acme-shop", "acme/shop", "profile", "n8Gf3kQ2xV7bTz1LwA9cYd", runTok} {
				if strings.Contains(raw, leak) {
					t.Errorf("%s: body leaks %q: %s", c.name, leak, raw)
				}
			}
		}
		// The other the runner's run is not readable by the first either, and
		// answers exactly like an unknown run.
		_, _, notYours, _ := r.get(a, "", "Bearer "+r.other.control(t, "run.status", a))
		_, _, unknown, _ := r.get(n, "", "Bearer "+r.other.control(t, "run.status", n))
		if !reflect.DeepEqual(notYours, unknown) {
			t.Errorf("another issuer's run and an unknown run differ: %v vs %v", notYours, unknown)
		}
		// A refused read left the run as it was.
		if st, m, raw := r.read(r.far, "r-lf2a"); st != 200 || m["state"] != "active" {
			t.Fatalf("run changed: %d %s", st, raw)
		}
	})

	t.Run("a revoked run shows state ended with its cause", func(t *testing.T) {
		st, body := r.e.call("POST", "/v0/runs/r-lf2a/revoke", r.orchTok, nil)
		if st != 200 {
			t.Fatalf("revoke: %d %v", st, body)
		}
		st, m, raw := r.read(r.far, "r-lf2a")
		if st != 200 || m["state"] != "ended" || m["cause_code"] != "OPERATOR_STOP_RUN" || m["expires_at"] != reg["expires_at"] {
			t.Fatalf("status %d %s", st, raw)
		}
		ended, _ := m["ended_at"].(string)
		if at, err := time.Parse(time.RFC3339, ended); err != nil || time.Since(at) > time.Minute || time.Until(at) > time.Minute {
			t.Fatalf("ended_at %q: %v", ended, err)
		}
		// Only these four members, still.
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"cause_code", "ended_at", "expires_at", "state"}) {
			t.Fatalf("members %v", keys)
		}
		// The run's own token is revoked too.
		if st, body := r.e.call("GET", "/v0/status", runTok, nil); st != 401 || body["cause_code"] != "TOKEN_REVOKED" {
			t.Fatalf("run token after revoke: %d %v", st, body)
		}
		// The other the runner still cannot see it.
		if st, _, _, raw := r.get("r-lf2a", "", "Bearer "+r.other.control(t, "run.status", "r-lf2a")); st != 404 {
			t.Fatalf("other issuer: %d %s", st, raw)
		}
	})

	t.Run("a run the runner ended itself has no cause", func(t *testing.T) {
		st, body := r.e.call("POST", "/v0/runs/r-lf2b/end", "", map[string]any{"control": r.far.control(t, "run.end", "r-lf2b")})
		if st != 200 {
			t.Fatalf("end: %d %v", st, body)
		}
		st, m, raw := r.read(r.far, "r-lf2b")
		if st != 200 || m["state"] != "ended" || m["cause_code"] != nil || m["ended_at"] == nil {
			t.Fatalf("status %d %s", st, raw)
		}
	})

	t.Run("the other routes are untouched", func(t *testing.T) {
		// The orchestrator still lists runs, and a control JWT does not.
		if st, body := r.e.call("GET", "/v0/runs", r.orchTok, nil); st != 200 || len(body["items"].([]any)) != 2 {
			t.Fatalf("list: %d %v", st, body)
		}
		if st, body := r.e.call("GET", "/v0/runs", r.far.control(t, "run.status", "r-lf2a"), nil); st != 401 {
			t.Fatalf("a control JWT listed runs: %d %v", st, body)
		}
	})
}

// The golden bodies in api/examples are byte for byte what chapd renders.
func TestRunStatusGolden(t *testing.T) {
	exp := time.Date(2026, 10, 24, 22, 5, 0, 0, time.UTC)
	cases := map[string]runtoken.RunStatus{
		"examples/run-status-active.json": {State: "active", ExpiresAt: exp},
		"examples/run-status-ended-operator-stop.json": {State: "ended", ExpiresAt: exp,
			EndedAt: time.Date(2026, 10, 24, 21, 12, 30, 0, time.UTC), CauseCode: "OPERATOR_STOP_RUN"},
		"examples/run-status-ended-normal.json": {State: "ended", ExpiresAt: exp,
			EndedAt: time.Date(2026, 10, 24, 21, 40, 0, 0, time.UTC)},
	}
	for name, st := range cases {
		golden, err := api.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(runStatusView(st))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, bytes.TrimSpace(golden)) {
			t.Errorf("%s\n got  %s\n want %s", name, got, bytes.TrimSpace(golden))
		}
	}
}
