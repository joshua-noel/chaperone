package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	v    *Verifier
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pub: pub, priv: priv, now: t0}
	f.v, err = NewVerifier(pub, NewMemoryNonces())
	if err != nil {
		t.Fatal(err)
	}
	f.v.Now = func() time.Time { return f.now }
	return f
}

func (f *fixture) grant(t *testing.T) Grant {
	t.Helper()
	n, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return Grant{
		Op:           "deploy",
		OpHash:       HashBytes([]byte("op")),
		RunID:        "r-abc123",
		Runbook:      "deploy",
		ScriptSHA256: HashBytes([]byte("script")),
		Args:         map[string]string{"sha": strings.Repeat("ab", 20)},
		Nonce:        n,
		IssuedAt:     f.now.Unix(),
		ExpiresAt:    f.now.Add(MaxLifetime).Unix(),
	}
}

func (f *fixture) sign(t *testing.T, g Grant) string {
	t.Helper()
	tok, err := Sign(f.priv, g)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// signRaw signs an arbitrary payload the way Sign does, bypassing Validate,
// to prove the verifier does not rely on the signer being well behaved.
func (f *fixture) signRaw(payload []byte) string {
	sig := ed25519.Sign(f.priv, signedBytes(payload))
	return tokenPrefix + "." + b64.EncodeToString(payload) + "." + b64.EncodeToString(sig)
}

func (f *fixture) signGrantRaw(t *testing.T, g Grant) string {
	t.Helper()
	g.Version = Version
	if g.Args == nil {
		g.Args = map[string]string{}
	}
	p, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return f.signRaw(p)
}

func wantRefusal(t *testing.T, err error, want *Refusal) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %s", err, want.Code)
	}
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	got, err := f.v.Verify(f.sign(t, g))
	if err != nil {
		t.Fatal(err)
	}
	if got.Runbook != "deploy" || got.Args["sha"] != g.Args["sha"] || got.Nonce != g.Nonce || got.Requester() != "run:r-abc123" {
		t.Fatalf("round trip changed the grant: %+v", got)
	}
	// Orchestrator form.
	g = f.grant(t)
	g.RunID, g.OrchestratorID = "", "main"
	got, err = f.v.Verify(f.sign(t, g))
	if err != nil || got.Requester() != "orchestrator:main" {
		t.Fatalf("orchestrator grant: %v %+v", err, got)
	}
	// logs.pilot with an enum argument.
	g = f.grant(t)
	g.Op, g.Runbook, g.Args = "logs", "logs.pilot", map[string]string{"source": "worker"}
	if _, err := f.v.Verify(f.sign(t, g)); err != nil {
		t.Fatal(err)
	}
}

func TestNoGrantRefused(t *testing.T) {
	f := newFixture(t)
	for name, tok := range map[string]string{
		"empty":       "",
		"garbage":     "hello",
		"json":        `{"runbook":"deploy"}`,
		"prefix only": "lg1..",
		"two parts":   "lg1.abc",
		"four parts":  "lg1.a.b.c",
		"wrong tag":   "lg2.e30.AAAA",
		"bad base64":  "lg1.!!!.!!!",
		"short sig":   "lg1.e30.AAAA",
		"too big":     "lg1." + strings.Repeat("A", MaxTokenBytes) + ".AAAA",
	} {
		if _, err := f.v.Verify(tok); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want %s", name, err, ErrMalformed.Code)
		}
	}
}

func TestWrongKeyAndTamper(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	tok := other.sign(t, f.grant(t))
	_, err := f.v.Verify(tok)
	wantRefusal(t, err, ErrSignature)

	// Flip the sha argument inside a genuine token: signature must fail.
	g := f.grant(t)
	tok = f.sign(t, g)
	parts := strings.Split(tok, ".")
	payload, _ := b64.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), g.Args["sha"], strings.Repeat("cd", 20), 1))
	parts[1] = b64.EncodeToString(payload)
	_, err = f.v.Verify(strings.Join(parts, "."))
	wantRefusal(t, err, ErrSignature)

	// A signature over the bare payload (no domain prefix) is not a grant.
	g = f.grant(t)
	g.Version = Version
	p, _ := json.Marshal(g)
	sig := ed25519.Sign(f.priv, p)
	_, err = f.v.Verify(tokenPrefix + "." + b64.EncodeToString(p) + "." + b64.EncodeToString(sig))
	wantRefusal(t, err, ErrSignature)
}

func TestExpiry(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	g.ExpiresAt = f.now.Add(time.Minute).Unix()
	tok := f.sign(t, g)

	f.now = f.now.Add(time.Minute - time.Second)
	if _, err := f.v.Verify(tok); err != nil {
		t.Fatalf("one second before exp: %v", err)
	}

	g = f.grant(t)
	g.IssuedAt, g.ExpiresAt = f.now.Add(-2*time.Minute).Unix(), f.now.Add(time.Minute).Unix()
	tok = f.sign(t, g)
	f.now = f.now.Add(time.Minute) // exactly exp: expired
	_, err := f.v.Verify(tok)
	wantRefusal(t, err, ErrExpired)
	f.now = f.now.Add(time.Hour)
	_, err = f.v.Verify(tok)
	wantRefusal(t, err, ErrExpired)
}

func TestExpiredGrantDoesNotBurnNonce(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	g.IssuedAt, g.ExpiresAt = f.now.Add(-time.Minute).Unix(), f.now.Add(-time.Second).Unix()
	_, err := f.v.Verify(f.sign(t, g))
	wantRefusal(t, err, ErrExpired)
	if err := f.v.nonces.Consume(g.Nonce, f.now.Add(time.Minute), f.now); err != nil {
		t.Fatalf("an expired grant recorded its nonce: %v", err)
	}
}

func TestIssuedInFuture(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	g.IssuedAt, g.ExpiresAt = f.now.Add(time.Minute).Unix(), f.now.Add(2*time.Minute).Unix()
	_, err := f.v.Verify(f.sign(t, g))
	wantRefusal(t, err, ErrNotYet)

	g = f.grant(t)
	g.IssuedAt, g.ExpiresAt = f.now.Add(MaxClockSkew).Unix(), f.now.Add(time.Minute).Unix()
	if _, err := f.v.Verify(f.sign(t, g)); err != nil {
		t.Fatalf("iat within skew: %v", err)
	}
}

func TestLifetimeCap(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	g.ExpiresAt = f.now.Add(MaxLifetime + time.Second).Unix()
	if _, err := Sign(f.priv, g); err == nil {
		t.Fatal("Sign accepted a lifetime over five minutes")
	}
	_, err := f.v.Verify(f.signGrantRaw(t, g)) // a signer that skips Validate
	wantRefusal(t, err, ErrInvalid)

	g.ExpiresAt = g.IssuedAt
	_, err = f.v.Verify(f.signGrantRaw(t, g))
	wantRefusal(t, err, ErrInvalid)
}

func TestReplay(t *testing.T) {
	f := newFixture(t)
	tok := f.sign(t, f.grant(t))
	if _, err := f.v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err := f.v.Verify(tok)
		wantRefusal(t, err, ErrReplay)
	}
	// The same nonce in a freshly signed grant is a replay too.
	g := f.grant(t)
	first := f.sign(t, g)
	g.Args = map[string]string{"sha": strings.Repeat("cd", 20)}
	second := f.sign(t, g)
	if _, err := f.v.Verify(first); err != nil {
		t.Fatal(err)
	}
	_, err := f.v.Verify(second)
	wantRefusal(t, err, ErrReplay)
}

func TestReplayConcurrent(t *testing.T) {
	f := newFixture(t)
	tok := f.sign(t, f.grant(t))
	var ok, replay atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.v.Verify(tok)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrReplay):
				replay.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || replay.Load() != 31 {
		t.Fatalf("accepted %d, replayed %d; want 1 and 31", ok.Load(), replay.Load())
	}
}

func TestSchemaRefusals(t *testing.T) {
	f := newFixture(t)
	sha := strings.Repeat("ab", 20)
	cases := map[string]func(g *Grant){
		"unknown runbook":     func(g *Grant) { g.Runbook = "shell" },
		"free-form runbook":   func(g *Grant) { g.Runbook = "deploy; rm -rf /" },
		"op for other book":   func(g *Grant) { g.Op = "logs" },
		"sha upper case":      func(g *Grant) { g.Args["sha"] = strings.ToUpper(sha) },
		"sha short":           func(g *Grant) { g.Args["sha"] = sha[:39] },
		"sha long":            func(g *Grant) { g.Args["sha"] = sha + "a" },
		"sha ref name":        func(g *Grant) { g.Args["sha"] = "main" },
		"sha injection":       func(g *Grant) { g.Args["sha"] = sha[:30] + "; reboot" },
		"extra arg":           func(g *Grant) { g.Args["cmd"] = "id" },
		"missing arg":         func(g *Grant) { delete(g.Args, "sha"); g.Args["other"] = sha },
		"no args":             func(g *Grant) { g.Args = map[string]string{} },
		"run and orch":        func(g *Grant) { g.OrchestratorID = "main" },
		"no requester":        func(g *Grant) { g.RunID = "" },
		"bad run id":          func(g *Grant) { g.RunID = "run 1" },
		"bad orchestrator":    func(g *Grant) { g.RunID, g.OrchestratorID = "", "Main!" },
		"op hash untagged":    func(g *Grant) { g.OpHash = strings.TrimPrefix(g.OpHash, "sha256:") },
		"script hash upper":   func(g *Grant) { g.ScriptSHA256 = strings.ToUpper(g.ScriptSHA256) },
		"script hash missing": func(g *Grant) { g.ScriptSHA256 = "" },
		"short nonce":         func(g *Grant) { g.Nonce = "abc" },
		"nonce bad char":      func(g *Grant) { g.Nonce = strings.Repeat("a", 21) + "!" },
	}
	for name, mutate := range cases {
		g := f.grant(t)
		mutate(&g)
		if _, err := Sign(f.priv, g); err == nil {
			t.Errorf("%s: Sign accepted it", name)
		}
		_, err := f.v.Verify(f.signGrantRaw(t, g))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Verify got %v, want %s", name, err, ErrInvalid.Code)
		}
	}
	// logs.pilot: a source outside the fixed set.
	g := f.grant(t)
	g.Op, g.Runbook, g.Args = "logs", "logs.pilot", map[string]string{"source": "../../etc/shadow"}
	_, err := f.v.Verify(f.signGrantRaw(t, g))
	wantRefusal(t, err, ErrInvalid)
}

func TestPayloadStrictness(t *testing.T) {
	f := newFixture(t)
	g := f.grant(t)
	g.Version = Version
	good, _ := json.Marshal(g)

	var m map[string]any
	_ = json.Unmarshal(good, &m)
	m["shell"] = "id"
	extra, _ := json.Marshal(m)

	for name, p := range map[string][]byte{
		"unknown field": extra,
		"trailing json": append(append([]byte{}, good...), []byte(`{}`)...),
		"not an object": []byte(`[]`),
		"wrong type":    []byte(`{"v":"1"}`),
		"version 2":     []byte(strings.Replace(string(good), `"v":1`, `"v":2`, 1)),
	} {
		_, err := f.v.Verify(f.signRaw(p))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want %s", name, err, ErrInvalid.Code)
		}
	}
}

func TestNewVerifierArgs(t *testing.T) {
	if _, err := NewVerifier(make([]byte, 5), NewMemoryNonces()); err == nil {
		t.Error("short key accepted")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewVerifier(pub, nil); err == nil {
		t.Error("nil store accepted")
	}
}

func TestRunbookAllowlist(t *testing.T) {
	want := []string{"deploy", "logs.pilot"}
	got := Names()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("allowlist %v, want %v", got, want)
	}
	spec, _ := Lookup("deploy")
	if v := spec.Ordered(map[string]string{"sha": "x"}); len(v) != 1 || v[0] != "x" {
		t.Fatalf("Ordered: %v", v)
	}
}

func TestRefusalCodes(t *testing.T) {
	err := error(Refuse(ErrExpired, "x"))
	if CodeOf(err) != "GRANT_EXPIRED" || CodeOf(errors.New("plain")) != "" {
		t.Fatal("CodeOf")
	}
	if errors.Is(err, ErrReplay) {
		t.Fatal("distinct codes matched")
	}
}

func TestSameHash(t *testing.T) {
	h := HashBytes([]byte("a"))
	if !SameHash(h, h) || SameHash(h, HashBytes([]byte("b"))) || SameHash("", "") || SameHash("x", "x") {
		t.Fatal("SameHash")
	}
}
