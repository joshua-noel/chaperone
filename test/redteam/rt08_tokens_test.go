package redteam

// RT-08 (forged, altered and cross-run tokens), RT-09 (reuse after the run
// ends) and RT-52 (interim host token: misuse). Red-team list:
// docs/manual-crosswalk.md. Threat model: TB3-S1, TB3-S2, TB3-S4.
//
// Phase 1 verifies interim run tokens only (chapd gives the verifier no profile
// source), so a runner.* token is refused here by construction; the matrix
// still tries it, because that is the refusal the issuer ties require.

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

func split3(t *testing.T, tok string) (hdr, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	return dec(parts[0]), dec(parts[1])
}

// compact joins a header, claims and a signature function into a compact JWS.
func compact(t *testing.T, hdr, claims map[string]any, sign func(input []byte) []byte) string {
	t.Helper()
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64(hb) + "." + b64(cb)
	return input + "." + b64(sign([]byte(input)))
}

func edSign(key ed25519.PrivateKey) func([]byte) []byte {
	return func(in []byte) []byte { return ed25519.Sign(key, in) }
}

func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// forgery is one row of the RT-08 table.
type forgery struct {
	name string
	// build returns the forged token from the valid one's header and claims.
	build func(t *testing.T, g *rig, hdr, claims map[string]any, valid string) string
	// want lists the accepted causes.
	want []string
}

func (g *rig) statusWith(tok string) (int, map[string]any) {
	return g.call("GET", "/v0/status", tok, nil)
}

func TestRT08ForgedAlteredAndCrossRunTokens(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.merge", "deploy", "health", "mail.send"}})
	valid, runID := g.mint("pr.merge", "health")

	// A valid control token works, so the table below is not vacuous.
	if st, body := g.statusWith(valid); st != 200 {
		t.Fatalf("control: the valid token is refused: %d %v", st, body)
	}
	hdr, claims := split3(t, valid)

	invalid := []string{"TOKEN_INVALID"}
	invalidOrScope := []string{"TOKEN_INVALID", "OP_NOT_IN_TOKEN", "SCOPE_BRANCH"}
	resignInterim := func(h, c map[string]any) string { return compact(t, h, c, edSign(g.interimKey)) }
	withClaims := func(mut func(c map[string]any)) func(*testing.T, *rig, map[string]any, map[string]any, string) string {
		return func(_ *testing.T, _ *rig, _ map[string]any, c map[string]any, valid string) string {
			c2 := clone(c)
			mut(c2)
			parts := strings.Split(valid, ".")
			cb, _ := json.Marshal(c2)
			return parts[0] + "." + b64(cb) + "." + parts[2] // altered, not re-signed
		}
	}
	withHeader := func(mut func(h map[string]any)) func(*testing.T, *rig, map[string]any, map[string]any, string) string {
		return func(_ *testing.T, g *rig, h, c map[string]any, _ string) string {
			h2 := clone(h)
			mut(h2)
			return compact(t, h2, c, edSign(g.interimKey)) // signed correctly, header is the forgery
		}
	}

	table := []forgery{
		{"claims altered: ops widened, signature kept", withClaims(func(c map[string]any) {
			ts := c["task_scope"].(map[string]any)
			ts["ops"] = []any{"pr.merge", "health", "deploy"}
		}), invalid},
		{"claims altered: run_id of another run, signature kept", withClaims(func(c map[string]any) { c["run_id"] = "r-zzzzzzzz" }), invalid},
		{"claims altered: expiry extended, signature kept", withClaims(func(c map[string]any) { c["exp"] = c["exp"].(float64) + 86400 }), invalid},
		{"claims altered: profile renamed, signature kept", withClaims(func(c map[string]any) { c["profile"] = map[string]any{"name": "code"} }), invalid},
		{"re-signed with a random key", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			return compact(t, h, c, edSign(g.AttackerKey))
		}, invalid},
		{"alg none, empty signature", func(t *testing.T, _ *rig, h, c map[string]any, _ string) string {
			h2 := clone(h)
			h2["alg"] = "none"
			return compact(t, h2, c, func([]byte) []byte { return nil })
		}, invalid},
		{"alg none, signature kept", func(t *testing.T, _ *rig, h, c map[string]any, valid string) string {
			h2 := clone(h)
			h2["alg"] = "none"
			hb, _ := json.Marshal(h2)
			parts := strings.Split(valid, ".")
			return b64(hb) + "." + parts[1] + "." + parts[2]
		}, invalid},
		{"HS256 keyed with the public key (confusion)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			h2 := clone(h)
			h2["alg"] = "HS256"
			pub := []byte(g.interimKey.Public().(ed25519.PublicKey))
			mac := func(in []byte) []byte {
				m := hmac.New(sha256.New, pub)
				m.Write(in)
				return m.Sum(nil)
			}
			return compact(t, h2, c, mac)
		}, invalid},
		{"RS256", withHeader(func(h map[string]any) { h["alg"] = "RS256" }), invalid},
		{"ES256", withHeader(func(h map[string]any) { h["alg"] = "ES256" }), invalid},
		{"alg Ed25519 (not the registered name)", withHeader(func(h map[string]any) { h["alg"] = "Ed25519" }), invalid},
		{"kid unknown", withHeader(func(h map[string]any) { h["kid"] = "interim-2" }), invalid},
		{"kid of the runner's key, signed by the interim key", withHeader(func(h map[string]any) { h["kid"] = "runner-1" }), invalid},
		{"kid missing", withHeader(func(h map[string]any) { delete(h, "kid") }), invalid},
		{"typ is the control token's", withHeader(func(h map[string]any) { h["typ"] = "factory-ctl+jwt" }), invalid},
		{"typ JWT", withHeader(func(h map[string]any) { h["typ"] = "JWT" }), invalid},
		{"header jku", withHeader(func(h map[string]any) { h["jku"] = "https://evil.test/keys" }), invalid},
		{"header jwk", withHeader(func(h map[string]any) { h["jwk"] = map[string]any{"kty": "OKP"} }), invalid},
		{"header crit", withHeader(func(h map[string]any) { h["crit"] = []any{"exp"} }), invalid},
		{"header x5c", withHeader(func(h map[string]any) { h["x5c"] = []any{"AAAA"} }), invalid},
		{"claims in an extra header (run_id, ops)", withHeader(func(h map[string]any) { h["run_id"] = "r-zzzzzzzz"; h["ops"] = []any{"deploy"} }), invalid},
		{"aud wrong", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["aud"] = "someone-else"
			return resignInterim(h, c2)
		}, invalid},
		{"jti missing", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			delete(c2, "jti")
			return resignInterim(h, c2)
		}, invalid},
		{"unknown extra claim", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["admin"] = true
			return resignInterim(h, c2)
		}, invalid},
		// Issuer matrix: Chaperone must apply the issuer ties, not only the schema.
		{"chaperone.* token with a sandbox tier (container)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["isolation"] = "container"
			return resignInterim(h, c2)
		}, invalid},
		{"chaperone.* token with a sandbox tier (microvm)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["isolation"] = "microvm"
			return resignInterim(h, c2)
		}, invalid},
		{"host token naming a real profile kind (code)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["profile"] = map[string]any{"name": "code"}
			return resignInterim(h, c2)
		}, invalid},
		{"host token carrying a profile digest", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["profile"] = map[string]any{"name": "host-interim", "digest": "sha256:" + strings.Repeat("a", 64)}
			return resignInterim(h, c2)
		}, invalid},
		{"runner.* token with isolation host, signed with the runner's key", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			h2, c2 := clone(h), clone(c)
			h2["kid"], c2["iss"] = "runner-1", "runner.test"
			return compact(t, h2, c2, edSign(g.RunnerKey))
		}, invalid},
		{"host token signed with the runner's key (chaperone.* iss)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			h2 := clone(h)
			h2["kid"] = "runner-1"
			return compact(t, h2, c, edSign(g.RunnerKey))
		}, invalid},
		{"runner.* token signed with the interim key", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["iss"] = "runner.test"
			c2["isolation"] = "container"
			c2["profile"] = map[string]any{"name": "code", "digest": "sha256:" + strings.Repeat("a", 64)}
			return resignInterim(h, c2)
		}, invalid},
		{"token of an unpinned chaperone.<other-instance>", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["iss"] = "chaperone.other"
			return resignInterim(h, c2)
		}, invalid},
		{"token of an unpinned runner.<other-instance>", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["iss"] = "runner.other"
			return resignInterim(h, c2)
		}, invalid},
		{"interim token with an op outside the interim key's ceiling", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["task_scope"].(map[string]any)["ops"] = []any{"secrets.write"}
			return resignInterim(h, c2)
		}, []string{"TOKEN_INVALID", "OP_NOT_IN_TOKEN"}},
		{"interim token on a branch outside agent/", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["task_scope"].(map[string]any)["branch"] = "main"
			return resignInterim(h, c2)
		}, invalidOrScope},
		{"validly signed, never registered (a run Chaperone did not mint)", func(t *testing.T, g *rig, h, c map[string]any, _ string) string {
			c2 := clone(c)
			c2["run_id"], c2["jti"] = "r-unknown1", "jtijtijtijtijtijtijtij"
			return resignInterim(h, c2)
		}, []string{"TOKEN_INVALID", "TOKEN_REVOKED"}},
		{"a token cut to two segments", func(t *testing.T, _ *rig, _, _ map[string]any, valid string) string {
			return valid[:strings.LastIndex(valid, ".")]
		}, invalid},
		{"padding added to a segment", func(t *testing.T, _ *rig, _, _ map[string]any, valid string) string {
			return valid + "="
		}, invalid},
		{"an orchestrator token with a flipped character", func(t *testing.T, g *rig, _, _ map[string]any, _ string) string {
			tok := g.OrchToken
			c := tok[len(tok)-1]
			repl := byte('A')
			if c == 'A' {
				repl = 'B'
			}
			return tok[:len(tok)-1] + string(repl)
		}, invalid},
	}

	type outcome struct{ name, status, cause string }
	var rows []outcome
	for _, f := range table {
		t.Run(f.name, func(t *testing.T) {
			forged := f.build(t, g, hdr, claims, valid)
			if forged == valid {
				t.Fatal("the forgery equals the valid token: the case tests nothing")
			}
			// Three surfaces: a read, an op request, and the op request as a body-claimed run.
			st, body := g.statusWith(forged)
			if st < 400 {
				t.Fatalf("status accepted a forged token: %d %v", st, body)
			}
			cause, _ := body["cause_code"].(string)
			if !contains(f.want, cause) {
				t.Fatalf("cause_code = %q, want one of %v (%v)", cause, f.want, body["why"])
			}
			st, body = g.call("POST", "/v0/ops", forged, mergeBody(sha1))
			if st < 400 {
				t.Fatalf("an op was accepted with a forged token: %d %v", st, body)
			}
			rows = append(rows, outcome{f.name, "refused", cause})
		})
	}
	if g.spy.executions() != 0 {
		t.Fatalf("an adapter ran %d time(s) for forged tokens", g.spy.executions())
	}
	if n := g.count(`SELECT COUNT(*) FROM ops`); n != 0 {
		t.Fatalf("%d op row(s) exist after forged requests: a denial must not create an op", n)
	}
	// A recognised run with a bad signature is TOKEN_MISUSE material; the
	// forgeries with no usable identity create no stop.
	g.mustLedgerOK()

	// The valid token still works after the whole matrix.
	if st, body := g.statusWith(valid); st != 200 {
		t.Fatalf("control after the matrix: %d %v", st, body)
	}
	t.Logf("RT-08: %d forgeries, 0 accepted (run %s)", len(rows), runID)

	// Late, because it moves the clock: the token far past its expiry.
	t.Run("replay far past expiry", func(t *testing.T) {
		g.advance(3 * time.Hour)
		st, body := g.statusWith(valid)
		if st != 401 {
			t.Fatalf("%d %v", st, body)
		}
		mustDenial(t, body, "TOKEN_EXPIRED")
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// RT-08, the orchestrator side: a run token is not an orchestrator, and an
// orchestrator token is not a run.
func TestRT08RunAndOrchestratorTokensAreNotInterchangeable(t *testing.T) {
	g := newRig(t, rigOpts{enable: []string{"pr.merge"}})
	run, _ := g.mint("pr.merge")

	// A run token on the orchestrator-only mint route.
	st, body := g.call("POST", "/v0/dev-tokens", run, map[string]any{
		"project": rigProject, "profile": "host-interim", "repo": rigRepo, "branch": rigBranch, "ops": []string{"pr.merge"}, "minutes": 30,
	})
	if st < 400 {
		t.Fatalf("a run token minted a token: %d %v", st, body)
	}
	// No auth at all on the mint route.
	if st, body = g.call("POST", "/v0/dev-tokens", "", map[string]any{
		"project": rigProject, "profile": "host-interim", "repo": rigRepo, "branch": rigBranch, "ops": []string{"pr.merge"}, "minutes": 30,
	}); st != 401 {
		t.Fatalf("no auth on the mint route: %d %v", st, body)
	}
	// A run token cannot revoke runs or read the ledger as an operator would.
	for _, p := range []struct{ m, path string }{{"POST", "/v0/runs/revoke-all"}, {"GET", "/v0/runs"}, {"POST", "/v0/ledger/verify"}} {
		if st, body := g.call(p.m, p.path, run, nil); st < 400 && p.path == "/v0/runs/revoke-all" {
			t.Fatalf("a run token reached %s %s: %d %v", p.m, p.path, st, body)
		}
	}
	if n := g.count(`SELECT COUNT(*) FROM runs WHERE state <> 'active'`); n != 0 {
		t.Fatalf("%d run(s) were ended by a run token", n)
	}
}

// ---- RT-09 -----------------------------------------------------------------

// controlToken signs a control JWT as the runner would.
func (g *rig) controlToken(t *testing.T, act, runID string) string {
	t.Helper()
	now := g.clock().Unix()
	hdr := map[string]any{"alg": "EdDSA", "kid": "runner-1", "typ": "factory-ctl+jwt"}
	c := map[string]any{"iss": "runner.test", "aud": "chaperone", "iat": now, "exp": now + 60, "jti": "ctl" + b64([]byte(act + runID + time.Now().String()))[:20], "act": act, "run_id": runID}
	return compact(t, hdr, c, edSign(g.RunnerKey))
}

func TestRT09ReuseAfterRunEnds(t *testing.T) {
	ctx := context.Background()
	for _, how := range []string{"ended normally", "stopped by the operator", "crashed (reaped past exp)"} {
		t.Run(how, func(t *testing.T) {
			g := newRig(t, rigOpts{enable: []string{"health", "pr.merge"}})
			tok, runID := g.mint("health", "pr.merge")
			health := opBody("health", "readiness", map[string]any{})
			// While the run lives the token works: a read and a write op.
			if st, body := g.call("POST", "/v0/ops", tok, health); st >= 400 {
				t.Fatalf("control: a live run is refused: %d %v", st, body)
			}
			before := g.spy.executions()

			switch how {
			case "ended normally":
				st, body := g.call("POST", "/v0/runs/"+runID+"/end", "", map[string]any{"control": g.controlToken(t, "run.end", runID), "outcome": "done"})
				if st != 200 {
					t.Fatalf("end: %d %v", st, body)
				}
			case "stopped by the operator":
				if err := g.runs.Revoke(ctx, runID, runtoken.StopOperatorStopRun); err != nil {
					t.Fatal(err)
				}
			case "crashed (reaped past exp)":
				g.advance(32 * time.Minute) // past exp (30 minutes), inside the 5 minute grace
				if n, err := g.runs.Reap(ctx); err != nil || n != 1 {
					t.Fatalf("reap: %d %v", n, err)
				}
			}
			for _, req := range []map[string]any{health, mergeBody(sha1)} {
				st, body := g.call("POST", "/v0/ops", tok, req)
				if st < 400 {
					t.Fatalf("a dead run's token worked: %d %v", st, body)
				}
				if how != "crashed (reaped past exp)" {
					mustDenial(t, body, "TOKEN_REVOKED")
				} else if c := body["cause_code"]; c != "TOKEN_REVOKED" && c != "TOKEN_EXPIRED" {
					t.Fatalf("cause_code %v", c)
				}
			}
			if g.spy.executions() != before {
				t.Fatal("an adapter ran for a dead run's token")
			}
			// The run-end event precedes the refused call in the ledger.
			if n := g.count(`SELECT COUNT(*) FROM ledger_events WHERE event_name IN ('run.end','stop.raise','token.revoke')`); n == 0 {
				t.Fatal("no run.end, token.revoke or stop.raise event before the refused calls")
			}
			g.mustLedgerOK()

			// Revocation survives a restart: a verifier built on the same database refuses again.
			g.restart()
			for _, req := range []map[string]any{health, mergeBody(sha1)} {
				st, body := g.call("POST", "/v0/ops", tok, req)
				if st < 400 {
					t.Fatalf("after a restart a dead run's token worked: %d %v", st, body)
				}
			}
			if g.spy.executions() != before {
				t.Fatal("an adapter ran after the restart")
			}
		})
	}
}
