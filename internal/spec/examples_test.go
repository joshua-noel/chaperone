package spec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type expectation struct {
	Keyword      string         `json:"keyword"`
	InstancePath string         `json:"instancePath"`
	Params       map[string]any `json:"params"`
	Via          string         `json:"via"`
}

func jsonFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && e.Name() != "expect.json" {
			out = append(out, e.Name())
		}
	}
	return out
}

func readTree(t *testing.T, path string) (any, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ParseStrict(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return tree, data
}

func TestSchemaExamples(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	var valid, invalid int
	schemas, _ := filepath.Glob("specdata/examples/*")
	for _, dir := range schemas {
		name := filepath.Base(dir)
		var expects map[string]expectation
		raw, err := os.ReadFile(filepath.Join(dir, "invalid", "expect.json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := json.Unmarshal(raw, &expects); err != nil {
			t.Fatal(err)
		}
		for _, f := range jsonFiles(t, filepath.Join(dir, "valid")) {
			tree, _ := readTree(t, filepath.Join(dir, "valid", f))
			if err := v.Validate(name, tree); err != nil {
				t.Errorf("%s/valid/%s: %v", name, f, err)
			}
			valid++
		}
		invalidFiles := jsonFiles(t, filepath.Join(dir, "invalid"))
		for _, f := range invalidFiles {
			want, ok := expects[f]
			if !ok {
				t.Errorf("%s/invalid/%s has no entry in expect.json", name, f)
				continue
			}
			tree, _ := readTree(t, filepath.Join(dir, "invalid", f))
			err := v.validate(name, want.Via, tree)
			ve, isVE := err.(*ValidationError)
			if !isVE {
				t.Errorf("%s/invalid/%s: not refused (err %v)", name, f, err)
				continue
			}
			if want.Via != "" {
				if v.Validate(name, tree) == nil {
					t.Errorf("%s/invalid/%s: the full schema accepts what its layer rejects", name, f)
				}
			}
			found := false
			for _, is := range ve.Issues {
				if is.Path == want.InstancePath && is.Keyword == want.Keyword {
					found = true
				}
			}
			if !found {
				t.Errorf("%s/invalid/%s: want a %q issue at %q, got %v", name, f, want.Keyword, want.InstancePath, ve.Issues)
			}
			invalid++
		}
		for f := range expects {
			if !contains(invalidFiles, f) {
				t.Errorf("%s: expect.json lists %s, which is absent", name, f)
			}
		}
	}
	if valid == 0 || invalid == 0 {
		t.Fatal("found no examples")
	}
	t.Logf("schema examples: %d valid accepted, %d invalid refused for the recorded reason", valid, invalid)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestStopTableData(t *testing.T) {
	v, _ := Default()
	tree, _ := readTree(t, "specdata/data/stop-table.v0.json")
	if err := v.Validate(SchemaStopTable, tree); err != nil {
		t.Fatal(err)
	}
}

// Every valid example decodes into its Go type and encodes back to the same
// canonical bytes: the structs lose and invent nothing.
func TestTypesRoundTrip(t *testing.T) {
	cases := []struct {
		schema string
		decode func([]byte) (any, error)
	}{
		{SchemaRequest, func(b []byte) (any, error) { return Load[Request](SchemaRequest, b) }},
		{SchemaApproval, func(b []byte) (any, error) { return Load[Approval](SchemaApproval, b) }},
		{SchemaRunToken, func(b []byte) (any, error) { return Load[RunTokenClaims](SchemaRunToken, b) }},
		{SchemaEvent, func(b []byte) (any, error) { return Load[Event](SchemaEvent, b) }},
		{SchemaDenial, func(b []byte) (any, error) { return Load[Denial](SchemaDenial, b) }},
	}
	n := 0
	for _, c := range cases {
		dir := filepath.Join("specdata/examples", c.schema, "valid")
		for _, f := range jsonFiles(t, dir) {
			tree, data := readTree(t, filepath.Join(dir, f))
			typed, err := c.decode(data)
			if err != nil {
				t.Errorf("%s/%s: %v", c.schema, f, err)
				continue
			}
			again, err := Tree(typed)
			if err != nil {
				t.Errorf("%s/%s: %v", c.schema, f, err)
				continue
			}
			if a, b := mustJCS(t, tree), mustJCS(t, again); a != b {
				t.Errorf("%s/%s: round trip changed the document\n was %s\n now %s", c.schema, f, a, b)
			}
			n++
		}
	}
	t.Logf("%d valid examples round-trip through their Go types", n)
}

// The examples' own hashes are right: op_hash, challenge_sha256, the ledger chain.
func TestExampleHashes(t *testing.T) {
	dir := "specdata/examples/operation-request/valid"
	for _, f := range jsonFiles(t, dir) {
		_, data := readTree(t, filepath.Join(dir, f))
		req, err := Load[Request](SchemaRequest, data)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := OpHash(req); err != nil || got != req.OpHash {
			t.Errorf("%s: op_hash %s (%v), example says %s", f, got, err, req.OpHash)
		}
	}
	dir = "specdata/examples/operation-approval/valid"
	for _, f := range jsonFiles(t, dir) {
		_, data := readTree(t, filepath.Join(dir, f))
		a, err := Load[Approval](SchemaApproval, data)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ApprovalChallenge(a); err != nil || got != a.ChallengeSHA256 {
			t.Errorf("%s: challenge %s (%v), example says %s", f, got, err, a.ChallengeSHA256)
		}
	}
	// One chain per writer: group the ledger examples by chain.
	dir = "specdata/examples/ledger-event/valid"
	chains := map[string][]Event{}
	for _, f := range jsonFiles(t, dir) {
		_, data := readTree(t, filepath.Join(dir, f))
		e, err := Load[Event](SchemaEvent, data)
		if err != nil {
			t.Fatal(err)
		}
		chains[e.Chain] = append(chains[e.Chain], e)
	}
	for chain, events := range chains {
		if problems := VerifyChain(events); len(problems) > 0 {
			t.Errorf("chain %s: %v", chain, problems)
		}
	}
}

// Attributes are closed per event_name: a key the event does not name is refused
// for every event the spec's examples show.
func TestEventAttributesAreClosed(t *testing.T) {
	v, _ := Default()
	dir := "specdata/examples/ledger-event/valid"
	seen := map[string]bool{}
	for _, f := range jsonFiles(t, dir) {
		tree, _ := readTree(t, filepath.Join(dir, f))
		ev := tree.(map[string]any)
		name := ev["event_name"].(string)
		ev["attributes"].(map[string]any)["factory.smuggled"] = "x"
		err := v.Validate(SchemaEvent, tree)
		if err == nil {
			t.Errorf("%s (%s): an unknown attribute was accepted", f, name)
		}
		seen[name] = true
	}
	t.Logf("unknown attributes refused for %d event names", len(seen))
}

// A pattern's "$" is the end of the input, never "before a final newline".
func TestPatternsRejectTrailingNewline(t *testing.T) {
	v, _ := Default()
	tree, _ := readTree(t, "specdata/examples/run-token/valid/code-run.json")
	claims := tree.(map[string]any)
	claims["run_id"] = "r-7f3a\n"
	if v.Validate(SchemaRunToken, claims) == nil {
		t.Fatal("run_id with a trailing newline was accepted")
	}
	claims["run_id"] = "r-7f3a"
	claims["task_scope"].(map[string]any)["branch"] = "agent/r-7f3a\n"
	if v.Validate(SchemaRunToken, claims) == nil {
		t.Fatal("branch with a trailing newline was accepted")
	}
	if got := endAnchors(`^(?!x$)[a$\]$]+$|\$$`); got != `^(?!x\z)[a$\]$]+\z|\$\z` {
		t.Fatalf("endAnchors: %s", got)
	}
}

func TestSchemasCompile(t *testing.T) {
	if _, err := NewValidator(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{SchemaRequest, SchemaApproval, SchemaRunToken, SchemaEvent, SchemaDenial, SchemaProfile, SchemaStopTable} {
		v, _ := Default()
		if _, err := v.schema(name, ""); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// specdata is exactly what scripts/spec-manifest sealed: every file matches MANIFEST,
// no file is extra, and VERSION names the version the embedded copy reports.
func TestSpecdataMatchesManifest(t *testing.T) {
	manifest, err := os.ReadFile("specdata/MANIFEST")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad MANIFEST line %q", line)
		}
		listed[name] = sum
	}
	onDisk := map[string]bool{}
	err = filepath.WalkDir("specdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("specdata", p)
		rel = filepath.ToSlash(rel)
		if rel == "MANIFEST" {
			return nil
		}
		onDisk[rel] = true
		want, ok := listed[rel]
		if !ok {
			t.Errorf("specdata/%s is not in MANIFEST: run `go run ./scripts/spec-manifest`", rel)
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Errorf("specdata/%s differs from MANIFEST: edited since it was sealed? run `go run ./scripts/spec-manifest`", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for n := range listed {
		if !onDisk[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("MANIFEST lists files that are gone: %v", missing)
	}
	version, _ := os.ReadFile("specdata/VERSION")
	if v := Version(); v == "" || string(version) != v+"\n" {
		t.Errorf("Version() = %q does not match specdata/VERSION %q", v, version)
	}
	t.Logf("specdata: %d files match MANIFEST, contract %s", len(listed), Version())
}
