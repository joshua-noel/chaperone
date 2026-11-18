package runtoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pubB64(b byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('A'+b)), ed25519.PublicKeySize)))
}

func TestKeySetLoadsFromDisk(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, e.keyJSON(true), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeySet(path)
	mustNil(t, err)
	k, ok := ks.Lookup("runner-1")
	if !ok || k.Issuer != "runner.host-1" || k.Interim != nil || !k.Public.Equal(e.far.pub) {
		t.Fatalf("runner key %+v", k)
	}
	i, ok := ks.Lookup("interim-1")
	if !ok || i.Interim == nil || i.Interim.MaxSeconds != MaxInterimSeconds || len(i.Interim.Ops) != len(HostInterimCeiling) {
		t.Fatalf("interim key %+v", i)
	}
	if !ks.AllowInterim() || !strings.HasPrefix(ks.Digest(), "sha256:") || len(ks.Digest()) != 71 {
		t.Fatalf("allow %v digest %q", ks.AllowInterim(), ks.Digest())
	}
	if _, ok := ks.Lookup("nobody"); ok {
		t.Fatal("unknown kid found")
	}
	if _, err := LoadKeySet(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing file loaded")
	}
}

func TestKeySetRefusals(t *testing.T) {
	k1, k2 := pubB64(0), pubB64(1)
	entry := func(kid, iss, pub, extra string) string {
		return `{"kid":"` + kid + `","issuer":"` + iss + `","public_key":"` + pub + `"` + extra + `}`
	}
	doc := func(allow string, entries ...string) string {
		return `{"version":1,` + allow + `"keys":[` + strings.Join(entries, ",") + `]}`
	}
	yes := `"allow_interim":true,`
	for name, in := range map[string]string{
		"allow_interim absent":               doc("", entry("a", "runner.h", k1, "")),
		"version 2":                          `{"version":2,"allow_interim":true,"keys":[]}`,
		"no version":                         `{"allow_interim":true,"keys":[]}`,
		"unknown top-level member":           `{"version":1,"allow_interim":true,"keys":[],"extra":1}`,
		"unknown key member":                 doc(yes, entry("a", "runner.h", k1, `,"alg":"HS256"`)),
		"duplicate member":                   `{"version":1,"allow_interim":true,"allow_interim":false,"keys":[]}`,
		"duplicate kid":                      doc(yes, entry("a", "runner.h", k1, ""), entry("a", "runner.i", k2, "")),
		"the same public key twice":          doc(yes, entry("a", "runner.h", k1, ""), entry("b", "runner.i", k1, "")),
		"bad kid":                            doc(yes, entry("a b", "runner.h", k1, "")),
		"empty kid":                          doc(yes, entry("", "runner.h", k1, "")),
		"runner key with a chaperone issuer": doc(yes, entry("a", "chaperone.interim", k1, "")),
		"interim key with a runner issuer":   doc(yes, entry("a", "runner.h", k1, `,"interim":{}`)),
		"issuer without an instance":         doc(yes, entry("a", "runner.", k1, "")),
		"public key of 31 bytes":             doc(yes, entry("a", "runner.h", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), "")),
		"public key padded":                  doc(yes, entry("a", "runner.h", k1+"=", "")),
		"public key standard alphabet":       doc(yes, entry("a", "runner.h", "+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/8", "")),
		"interim over 2 hours":               doc(yes, entry("a", "chaperone.i", k1, `,"interim":{"max_seconds":7201}`)),
		"interim negative lifetime":          doc(yes, entry("a", "chaperone.i", k1, `,"interim":{"max_seconds":-1}`)),
		"interim op above the ceiling":       doc(yes, entry("a", "chaperone.i", k1, `,"interim":{"ops":["pr.open","approvers.enroll"]}`)),
		"interim wildcard op":                doc(yes, entry("a", "chaperone.i", k1, `,"interim":{"ops":["pr.*"]}`)),
		"not JSON":                           `{`,
		"empty":                              ``,
		"trailing content":                   doc(yes) + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if ks, err := ParseKeySet([]byte(in)); err == nil {
				t.Fatalf("accepted: %+v", ks)
			}
		})
	}
	if _, err := ParseKeySet(make([]byte, maxKeySetBytes+1)); err == nil {
		t.Fatal("an oversized file parsed")
	}
}

func TestKeySetNarrowsTheCeiling(t *testing.T) {
	in := `{"version":1,"allow_interim":false,"keys":[{"kid":"i","issuer":"chaperone.i","public_key":"` + pubB64(2) +
		`","interim":{"max_seconds":1800,"ops":["pr.open","logs"]}}]}`
	ks, err := ParseKeySet([]byte(in))
	mustNil(t, err)
	k, _ := ks.Lookup("i")
	if k.Interim.MaxSeconds != 1800 || len(k.Interim.Ops) != 2 || ks.AllowInterim() {
		t.Fatalf("%+v allow=%v", k.Interim, ks.AllowInterim())
	}
}

func TestHostInterimCeilingMatchesADR005(t *testing.T) {
	for _, op := range []string{"pr.open", "pr.update", "pr.merge", "branch.push", "health", "logs"} {
		if !contains(HostInterimCeiling, op) {
			t.Fatalf("ADR-005 names %s in the ceiling", op)
		}
	}
	for _, op := range []string{"approvers.enroll", "policy.activate"} {
		if contains(HostInterimCeiling, op) {
			t.Fatalf("critical op %s is in the ceiling", op)
		}
	}
}
