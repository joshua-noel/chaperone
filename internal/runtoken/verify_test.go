package runtoken

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// The spec's golden run-token vectors are claims, not signed tokens: sign each
// with the key pinned for its issuer, register its run, set the clock to the
// vector's `now`, and check the verdict and the cause code.
func TestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/specdata/vectors/v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RunTokens []struct {
			Name    string               `json:"name"`
			Now     string               `json:"now"`
			Revoked []string             `json:"revoked"`
			Profile *spec.GenericProfile `json:"profile"`
			Claims  spec.RunTokenClaims  `json:"claims"`
			Expect  string               `json:"expect"`
		} `json:"run_tokens"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// Cause code per failing vector. A vector this table lacks fails the test:
	// a spec bump that adds one must say what the verifier answers.
	want := map[string]string{
		"valid run token":                    "",
		"valid vm (T0) run token":            "",
		"interim host token (no profile)":    "",
		"expired":                            CauseTokenExpired,
		"revoked":                            CauseTokenRevoked,
		"branch equals base":                 CauseScopeBranch,
		"branch outside the profile prefix":  CauseScopeBranch,
		"op outside the profile":             CauseOpNotInToken,
		"iat in the future":                  CauseTokenInvalid,
		"host token claiming a sandbox tier": CauseTokenInvalid,
	}
	if len(doc.RunTokens) == 0 {
		t.Fatal("no run_tokens in the vectors")
	}
	for _, v := range doc.RunTokens {
		t.Run(v.Name, func(t *testing.T) {
			code, known := want[v.Name]
			if !known {
				t.Fatalf("vector %q has no expected cause code in this test", v.Name)
			}
			if (code == "") != (v.Expect == "pass") {
				t.Fatalf("table says %q but the vector expects %s", code, v.Expect)
			}
			e := newEnv(t)
			now, err := time.Parse(time.RFC3339Nano, v.Now)
			if err != nil {
				t.Fatal(err)
			}
			e.clock = now
			profiles := func(string) (*spec.GenericProfile, bool) { return v.Profile, v.Profile != nil }
			e.ver.profiles = profiles
			e.runs.cfg.Profiles = profiles
			signer := e.far
			if strings.HasPrefix(v.Claims.Iss, "chaperone.") {
				signer = e.intr
			}
			tok := signer.sign(t, typRun, v.Claims)
			// Seed the registry the way a registration would, skipping the
			// clock checks (some vectors are expired or from the future).
			if rt, perr := parseRunToken(tok, e.keys, profiles); perr == nil {
				mustNil(t, e.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
					_, err := e.runs.insertRun(ctx, tx, rt)
					return err
				}))
				for _, jti := range v.Revoked {
					if _, err := e.db.SQL().Exec(`INSERT INTO revoked_jti (jti, run_id, exp, revoked_at, reason) VALUES (?, ?, ?, ?, 'run_end')`,
						jti, v.Claims.RunID, v.Claims.Exp, now.Unix()); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := e.verify(tok)
			if code == "" {
				if err != nil {
					t.Fatalf("golden token refused: %v", err)
				}
				if got.Claims.RunID != v.Claims.RunID || got.Interim != strings.HasPrefix(v.Claims.Iss, "chaperone.") {
					t.Fatalf("verified %+v", got)
				}
				return
			}
			wantCode(t, err, code)
		})
	}
}

func TestVerifyAccepts(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	rt, err := e.verify(tok)
	mustNil(t, err)
	if rt.Claims.JTI != c.JTI || rt.KID != "runner-1" || rt.Interim || rt.Profile == nil {
		t.Fatalf("verified token %+v", rt)
	}
	// Step 8: ops are token ∩ profile ∩ catalog; nil catalog enables nothing.
	if got := rt.EffectiveOps(nil); len(got) != 0 {
		t.Fatalf("nil catalog enabled %v", got)
	}
	if got := rt.EffectiveOps([]string{"pr.open", "deploy"}); len(got) != 1 || got[0] != "pr.open" {
		t.Fatalf("effective ops %v", got)
	}
	mustNil(t, rt.CheckOp("pr.open"))
	wantCode(t, rt.CheckOp("deploy"), CauseOpNotInToken)
	mustNil(t, rt.CheckBranch("agent/r-7f3a"))
	wantCode(t, rt.CheckBranch("main"), CauseScopeBranch)
	wantCode(t, rt.CheckRepo("evil/repo"), CauseScopeBranch)
	// The lifetime limit is budget + exactly 300 s: this claim is at it.
	if c.Exp-c.Iat != int64(c.Budget.Minutes)*60+spec.TokenGraceSeconds {
		t.Fatal("fixture is not at the grace limit")
	}
}

func TestVerifyNegatives(t *testing.T) {
	type tc struct {
		name string
		code string
		stop string
		tok  func(e *env) string
	}
	// good registers the base run and returns its claims.
	good := func(e *env) spec.RunTokenClaims { c := e.claims(); e.register(c); return c }
	header := func(e *env, mod func(h map[string]any)) map[string]any {
		h := map[string]any{"alg": "EdDSA", "typ": typRun, "kid": e.far.kid}
		if mod != nil {
			mod(h)
		}
		return h
	}
	signedWith := func(e *env, h map[string]any, c any) string {
		return rawJWS(t, h, c, func(in []byte) []byte { s, _ := e.far.sig(in); return s })
	}
	withClaims := func(e *env, mod func(m map[string]any)) any {
		c := good(e)
		b, _ := json.Marshal(c)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mod(m)
		return m
	}
	headerCase := func(name string, mod func(h map[string]any)) tc {
		return tc{name: name, code: CauseTokenInvalid, tok: func(e *env) string {
			return signedWith(e, header(e, mod), good(e))
		}}
	}
	cases := []tc{
		{name: "alg none, empty signature", code: CauseTokenInvalid, tok: func(e *env) string {
			return rawJWS(t, header(e, func(h map[string]any) { h["alg"] = "none" }), good(e), nil)
		}},
		{name: "alg none, with a signature", code: CauseTokenInvalid, tok: func(e *env) string {
			return signedWith(e, header(e, func(h map[string]any) { h["alg"] = "none" }), good(e))
		}},
		{name: "HS256 keyed with the public key bytes", code: CauseTokenInvalid, tok: func(e *env) string {
			return rawJWS(t, header(e, func(h map[string]any) { h["alg"] = "HS256" }), good(e), func(in []byte) []byte {
				m := hmac.New(sha256.New, e.far.pub)
				m.Write(in)
				return m.Sum(nil)
			})
		}},
		{name: "RS256", code: CauseTokenInvalid, tok: func(e *env) string {
			return rawJWS(t, header(e, func(h map[string]any) { h["alg"] = "RS256" }), good(e), func([]byte) []byte {
				b := make([]byte, 256)
				_, _ = rand.Read(b)
				return b
			})
		}},
		headerCase("alg ES256", func(h map[string]any) { h["alg"] = "ES256" }),
		headerCase("alg Ed25519 (RFC 9864 name)", func(h map[string]any) { h["alg"] = "Ed25519" }),
		headerCase("alg eddsa lower case", func(h map[string]any) { h["alg"] = "eddsa" }),
		headerCase("no alg", func(h map[string]any) { delete(h, "alg") }),
		headerCase("typ JWT", func(h map[string]any) { h["typ"] = "JWT" }),
		headerCase("typ of a control token", func(h map[string]any) { h["typ"] = typCtl }),
		headerCase("typ in upper case", func(h map[string]any) { h["typ"] = strings.ToUpper(typRun) }),
		headerCase("no typ", func(h map[string]any) { delete(h, "typ") }),
		headerCase("unknown kid", func(h map[string]any) { h["kid"] = "nobody" }),
		headerCase("no kid", func(h map[string]any) { delete(h, "kid") }),
		headerCase("kid not a string", func(h map[string]any) { h["kid"] = 7 }),
		headerCase("jku header", func(h map[string]any) { h["jku"] = "https://evil.example/keys" }),
		headerCase("jwk header", func(h map[string]any) { h["jwk"] = map[string]any{"kty": "OKP"} }),
		headerCase("x5u header", func(h map[string]any) { h["x5u"] = "https://evil.example/c" }),
		headerCase("x5c header", func(h map[string]any) { h["x5c"] = []string{"AAAA"} }),
		headerCase("crit header", func(h map[string]any) { h["crit"] = []string{"exp"} }),
		headerCase("zip header", func(h map[string]any) { h["zip"] = "DEF" }),
		headerCase("unlisted header member", func(h map[string]any) { h["cty"] = "x" }),
		{name: "duplicate header member", code: CauseTokenInvalid, tok: func(e *env) string {
			good(e)
			hdr := `{"alg":"none","alg":"EdDSA","typ":"` + typRun + `","kid":"` + e.far.kid + `"}`
			return rawText(t, hdr, e.claims(), e.far)
		}},
		{name: "wrong aud", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["aud"] = "someone-else" }))
		}},
		{name: "extra claim", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["admin"] = true }))
		}},
		{name: "missing claim", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { delete(m, "task_scope") }))
		}},
		{name: "sub not run:<run_id>", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["sub"] = "run:r-other" }))
		}},
		{name: "iss differs from the issuer pinned for the kid", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["iss"] = "runner.other" }))
		}},
		{name: "runner claims signed by the interim key", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.intr.sign(t, typRun, good(e))
		}},
		{name: "host isolation claimed by a runner token", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["isolation"] = "host" }))
		}},
		{name: "profile digest not admitted", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) {
				m["profile"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("ab", 32)
			}))
		}},
		{name: "exp in the past", code: CauseTokenExpired, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			e.clock = time.Unix(c.Exp, 0).UTC() // now >= exp
			return e.far.sign(t, typRun, c)
		}},
		{name: "exp - iat beyond budget + 300 s", code: CauseTokenExpired, stop: StopTokenMisuse, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["exp"] = m["exp"].(float64) + 1 }))
		}},
		{name: "exp not after iat", code: CauseTokenExpired, stop: StopTokenMisuse, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["exp"] = m["iat"] }))
		}},
		{name: "iat in the future", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) {
				m["iat"] = m["iat"].(float64) + 31
				m["exp"] = m["exp"].(float64) + 31
			}))
		}},
		{name: "jti revoked", code: CauseTokenRevoked, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			if _, err := e.db.SQL().Exec(`INSERT INTO revoked_jti (jti, run_id, exp, revoked_at, reason) VALUES (?, ?, ?, 1, 'operator')`, c.JTI, c.RunID, c.Exp); err != nil {
				t.Fatal(err)
			}
			return e.far.sign(t, typRun, c)
		}},
		// Revocation wins over expiry: a stopped run must never get TOKEN_EXPIRED (and its restart step).
		{name: "jti revoked and exp in the past", code: CauseTokenRevoked, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			if _, err := e.db.SQL().Exec(`INSERT INTO revoked_jti (jti, run_id, exp, revoked_at, reason) VALUES (?, ?, ?, 1, 'operator')`, c.JTI, c.RunID, c.Exp); err != nil {
				t.Fatal(err)
			}
			e.clock = time.Unix(c.Exp, 0).UTC() // now >= exp
			return e.far.sign(t, typRun, c)
		}},
		{name: "run ended and exp in the past", code: CauseTokenRevoked, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			mustNil(t, e.end(c.RunID))
			e.clock = time.Unix(c.Exp, 0).UTC() // now >= exp
			return e.far.sign(t, typRun, c)
		}},
		{name: "run ended", code: CauseTokenRevoked, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			mustNil(t, e.end(c.RunID))
			return e.far.sign(t, typRun, c)
		}},
		{name: "run not registered", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, e.claims())
		}},
		{name: "a second token for a registered run", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) { m["jti"] = "AAAAAAAAAAAAAAAAAAAAAA" }))
		}},
		{name: "scope differs from the recorded grant", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, withClaims(e, func(m map[string]any) {
				m["task_scope"].(map[string]any)["ops"] = []any{"pr.open", "branch.push", "logs"}
			}))
		}},
		{name: "bad signature (payload changed)", code: CauseTokenInvalid, stop: StopTokenMisuse, tok: func(e *env) string {
			tok := e.far.sign(t, typRun, good(e))
			parts := strings.Split(tok, ".")
			c2 := e.claims()
			c2.Project = "other-proj"
			parts[1] = strings.Split(e.far.sign(t, typRun, c2), ".")[1]
			return strings.Join(parts, ".")
		}},
		{name: "bad signature (wrong key)", code: CauseTokenInvalid, stop: StopTokenMisuse, tok: func(e *env) string {
			c := good(e)
			other := newIssuer(t, e.far.kid, e.far.iss)
			return other.sign(t, typRun, c)
		}},
		{name: "signature too short", code: CauseTokenInvalid, stop: StopTokenMisuse, tok: func(e *env) string {
			tok := e.far.sign(t, typRun, good(e))
			return tok[:len(tok)-8]
		}},
		{name: "two segments", code: CauseTokenInvalid, tok: func(e *env) string {
			tok := e.far.sign(t, typRun, good(e))
			return tok[:strings.LastIndex(tok, ".")]
		}},
		{name: "four segments", code: CauseTokenInvalid, tok: func(e *env) string {
			return e.far.sign(t, typRun, good(e)) + ".AAAA"
		}},
		{name: "empty", code: CauseTokenInvalid, tok: func(*env) string { return "" }},
		{name: "Bearer prefix left on", code: CauseTokenInvalid, tok: func(e *env) string {
			return "Bearer " + e.far.sign(t, typRun, good(e))
		}},
		{name: "newline inside a segment", code: CauseTokenInvalid, tok: func(e *env) string {
			tok := e.far.sign(t, typRun, good(e))
			return tok[:10] + "\n" + tok[10:]
		}},
		{name: "padded base64url", code: CauseTokenInvalid, tok: func(e *env) string {
			parts := strings.Split(e.far.sign(t, typRun, good(e)), ".")
			parts[1] += "="
			return strings.Join(parts, ".")
		}},
		{name: "token over the size limit", code: CauseTokenInvalid, tok: func(*env) string {
			return strings.Repeat("A", maxTokenBytes+1)
		}},
		{name: "orchestrator token given to the run verifier", code: CauseTokenInvalid, tok: func(*env) string {
			return OrchPrefix + strings.Repeat("A", orchSecretChars)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			tok := c.tok(e)
			_, err := e.verify(tok)
			re := wantCode(t, err, c.code)
			if re.Stop != c.stop {
				t.Fatalf("stop %q, want %q (%s)", re.Stop, c.stop, re.Detail)
			}
			if strings.Contains(re.Error(), tok) && len(tok) > 0 {
				t.Fatal("the refusal quotes the token")
			}
		})
	}
}

// rawText builds a token whose header text is exactly hdr (for members a map
// cannot repeat).
func rawText(t *testing.T, hdr string, claims any, signer issuer) string {
	t.Helper()
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := b64(hdr) + "." + b64(string(p))
	sig, _ := signer.sig([]byte(in))
	return in + "." + b64(string(sig))
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// A refused run token still names the run when its signature held, so the
// denial body can carry run_id, project and profile.
func TestRefusalNamesTheRun(t *testing.T) {
	e := newEnv(t)
	c := e.claims()
	tok := e.register(c)
	mustNil(t, e.end(c.RunID))
	_, err := e.verify(tok)
	re := wantCode(t, err, CauseTokenRevoked)
	if re.Run == nil || re.Run.RunID != c.RunID || re.Run.Project != c.Project || re.Run.Profile != "code" {
		t.Fatalf("Run = %+v", re.Run)
	}
	// A token that could not be identified names nothing.
	_, err = e.verify("a.b.c")
	if re := wantCode(t, err, CauseTokenInvalid); re.Run != nil {
		t.Fatalf("Run = %+v for an unreadable token", re.Run)
	}
}

func TestVerifyFailsClosedWhenTheDatabaseIsGone(t *testing.T) {
	e := newEnv(t)
	tok := e.register(e.claims())
	e.db.Close()
	_, err := e.verify(tok)
	if err == nil || CodeOf(err) != "" {
		t.Fatalf("got %v, want a plain (non-denial) database error", err)
	}
}

func TestInterimTokenAtVerify(t *testing.T) {
	e := newEnv(t)
	mk := func(mod func(c *spec.RunTokenClaims)) spec.RunTokenClaims {
		iat := e.clock.Unix()
		c := spec.RunTokenClaims{
			Iss: e.intr.iss, Sub: "run:r-9a9a", Aud: "chaperone", Iat: iat, Exp: iat + 3600,
			JTI: "iiiiiiiiiiiiiiiiiiiiii", RunID: "r-9a9a", Project: "acme-shop",
			Profile:  spec.TokenProfile{Name: InterimProfile, Version: "0.0.0"},
			BriefSHA: "sha256:" + strings.Repeat("00", 32), Isolation: "host",
			TaskScope: spec.TaskScope{Repo: "acme/shop", Base: "main", Branch: "agent/x", Paths: []string{"**"}, Ops: []string{"pr.open", "pr.merge"}},
			Budget:    spec.Budget{Minutes: 120, Tokens: 1},
		}
		if mod != nil {
			mod(&c)
		}
		return c
	}
	insert := func(c spec.RunTokenClaims) string {
		tok := e.intr.sign(t, typRun, c)
		rt, perr := parseRunToken(tok, e.keys, nil)
		if perr != nil {
			return tok
		}
		mustNil(t, e.db.Immediate(context.Background(), func(ctx context.Context, tx *store.Tx) error {
			_, err := e.runs.insertRun(ctx, tx, rt)
			return err
		}))
		return tok
	}
	if _, err := e.verify(insert(mk(nil))); err != nil {
		t.Fatalf("interim token refused: %v", err)
	}
	for _, c := range []struct {
		name string
		code string
		mod  func(c *spec.RunTokenClaims)
	}{
		{"above 2 hours", CauseTokenInvalid, func(c *spec.RunTokenClaims) { c.Exp = c.Iat + MaxInterimSeconds + 1; c.Budget.Minutes = 200 }},
		{"op outside the host-interim ceiling", CauseOpNotInToken, func(c *spec.RunTokenClaims) { c.TaskScope.Ops = []string{"approvers.enroll"} }},
		{"secrets op", CauseOpNotInToken, func(c *spec.RunTokenClaims) { c.TaskScope.Ops = []string{"secrets.read"} }},
		{"branch outside agent/", CauseScopeBranch, func(c *spec.RunTokenClaims) { c.TaskScope.Branch = "feature/x" }},
		{"sandbox isolation from the chaperone issuer", CauseTokenInvalid, func(c *spec.RunTokenClaims) { c.Isolation = "gvisor" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := mk(c.mod)
			cl.RunID, cl.Sub, cl.JTI = "r-"+strings.ToLower(strings.ReplaceAll(c.name[:2], " ", "x"))+"zz", "", "jjjjjjjjjjjjjjjjjjjjj"+c.name[:1]
			cl.Sub = "run:" + cl.RunID
			_, err := e.verify(insert(cl))
			wantCode(t, err, c.code)
		})
	}
	// allow_interim=false rejects every interim token, including a good one.
	good := insert(mk(func(c *spec.RunTokenClaims) { c.RunID, c.Sub, c.JTI = "r-okok", "run:r-okok", "kkkkkkkkkkkkkkkkkkkkkk" }))
	if _, err := e.verify(good); err != nil {
		t.Fatal(err)
	}
	e.rebuild(false)
	_, err := e.verify(good)
	re := wantCode(t, err, CauseTokenInvalid)
	if !strings.Contains(re.Detail, "allow_interim") {
		t.Fatalf("detail %q", re.Detail)
	}
}
