package runtoken

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// goldenDigest is sha256(JCS(golden profile)): the value the spec's overlay
// pins as extends.digest (the run-token vectors carry a placeholder digest).
const goldenDigest = "sha256:39581aa52a1ebd4d262dc34c0ad375c805af99d2ddd6b90d54c3fdf38e6a931f"

// goldenProfile is the spec's golden generic profile, the one the run-token
// vectors use, as the bytes of a profile file.
func goldenProfile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../spec/specdata/vectors/v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RunTokens []struct {
			Profile json.RawMessage `json:"profile"`
		} `json:"run_tokens"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.RunTokens[0].Profile
}

func profileFile(dir, digest string) string {
	return filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")+".json")
}

// profileEnv is an env whose profile source is a ProfileDir holding the golden
// profile, with claims that name it.
func profileEnv(t *testing.T) (*env, *ProfileDir, string, spec.RunTokenClaims) {
	t.Helper()
	e := newEnv(t)
	dir := t.TempDir()
	if d, err := AdmitProfile(dir, goldenProfile(t)); err != nil || d != goldenDigest {
		t.Fatalf("admit golden profile: %s, %v", d, err)
	}
	pd, n, err := OpenProfileDir(dir, nil)
	if err != nil || n != 1 {
		t.Fatalf("open: %d, %v", n, err)
	}
	e.ver.profiles = pd.Lookup
	e.runs.cfg.Profiles = pd.Lookup
	c := e.claims()
	c.Profile.Digest = goldenDigest
	return e, pd, dir, c
}

func TestProfileDirAdmitsKnownDigest(t *testing.T) {
	e, _, _, c := profileEnv(t)
	tok := e.register(c)
	rt, err := e.verify(tok)
	mustNil(t, err)
	if rt.Profile == nil || rt.Profile.Profile != "code" || rt.Profile.BranchPrefix != "agent/" {
		t.Fatalf("profile %+v", rt.Profile)
	}
	if got := rt.EffectiveOps([]string{"pr.open", "branch.push", "deploy"}); strings.Join(got, ",") != "pr.open,branch.push" {
		t.Fatalf("effective ops %v: the golden profile's allow list must apply", got)
	}
}

func TestProfileDirRefusesUnknownDigest(t *testing.T) {
	e, _, _, c := profileEnv(t)
	c.Profile.Digest = testDigest // a digest nobody admitted
	tok := e.far.sign(t, typRun, c)
	_, err := e.verify(tok)
	re := wantCode(t, err, CauseTokenInvalid)
	if !strings.Contains(re.Detail, "is not admitted") {
		t.Fatalf("detail %q", re.Detail)
	}
	// Registration refuses it too, so no run row exists for a profile Chaperone never admitted.
	_, err = e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: tok})
	wantCode(t, err, CauseTokenInvalid)
}

func TestProfileDirRefusesTamperedFile(t *testing.T) {
	e, pd, dir, c := profileEnv(t)
	tok := e.register(c)
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("verify before tamper: %v", err)
	}

	// Widen the profile in place: add deploy to ops.allow. The file is still a
	// valid profile, but it no longer hashes to its name.
	path := profileFile(dir, goldenDigest)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wide := bytes.Replace(data, []byte(`"pr.open"`), []byte(`"deploy","pr.open"`), 1)
	if bytes.Equal(wide, data) {
		t.Fatal("test edit did not change the profile")
	}
	if err := os.WriteFile(path, wide, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	pd.log = slog.New(slog.NewTextHandler(&logs, nil))
	_, err = e.verify(tok)
	wantCode(t, err, CauseTokenInvalid)
	if !strings.Contains(logs.String(), "tampered or misnamed") {
		t.Fatalf("the refusal reason is not logged: %q", logs.String())
	}

	// chapd refuses to start on it, rather than serve with a profile it cannot trust.
	if _, _, err := OpenProfileDir(dir, nil); err == nil || !strings.Contains(err.Error(), "tampered or misnamed") {
		t.Fatalf("open on a tampered folder: %v", err)
	}
}

func TestProfileDirRefusesMisnamedAndBadFiles(t *testing.T) {
	good := goldenProfile(t)
	mutate := func(f func(map[string]any)) []byte {
		var c map[string]any
		_ = json.Unmarshal(good, &c)
		f(c)
		b, _ := json.Marshal(c)
		return b
	}
	cases := map[string][]byte{
		"not json":       []byte("{"),
		"not a profile":  []byte(`{"hello":"world"}`),
		"no prefix":      mutate(func(c map[string]any) { delete(c, "branch_prefix") }),
		"overlay":        mutate(func(c map[string]any) { c["layer"] = "overlay" }),
		"duplicate name": []byte(strings.Replace(string(good), `"layer"`, `"layer":"generic","layer"`, 1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := AdmitProfile(t.TempDir(), data); err == nil {
				t.Fatal("admitted")
			}
			dir := t.TempDir()
			if err := os.WriteFile(profileFile(dir, goldenDigest), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenProfileDir(dir, nil); err == nil {
				t.Fatal("opened a folder with it")
			}
		})
	}
	t.Run("file name is not a digest", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "code.json"), good, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenProfileDir(dir, nil); err == nil || !strings.Contains(err.Error(), "<64 lowercase hex>.json") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("file under another digest", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(profileFile(dir, testDigest), good, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenProfileDir(dir, nil); err == nil {
			t.Fatal("a profile filed under the wrong digest opened")
		}
	})
	t.Run("missing folder", func(t *testing.T) {
		_, _, err := OpenProfileDir(filepath.Join(t.TempDir(), "nope"), nil)
		if err == nil || !strings.Contains(err.Error(), "profiles: read") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("lookup takes only a digest", func(t *testing.T) {
		pd, _, err := OpenProfileDir(t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"", "../x", "sha256:../../etc/passwd", strings.ToUpper(goldenDigest), goldenDigest[7:]} {
			if p, ok := pd.Lookup(d); ok || p != nil {
				t.Fatalf("lookup %q admitted", d)
			}
		}
	})
}

func TestNoProfileSourceIsAClearRefusal(t *testing.T) {
	e := newEnv(t)
	e.ver.profiles = nil
	e.runs.cfg.Profiles = nil
	c := e.claims()
	tok := e.far.sign(t, typRun, c)
	_, err := e.verify(tok)
	re := wantCode(t, err, CauseTokenInvalid)
	for _, want := range []string{"no profile source is configured", "-profiles-dir"} {
		if !strings.Contains(re.Detail, want) {
			t.Fatalf("detail %q lacks %q", re.Detail, want)
		}
	}
	_, err = e.runs.Register(context.Background(), RegisterRequest{Control: e.ctl(actRunStart, c.RunID), Token: tok})
	wantCode(t, err, CauseTokenInvalid)
}
