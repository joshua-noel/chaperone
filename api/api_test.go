package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/joshua-noel/chaperone/internal/spec"
)

func TestDenialExamplesValidate(t *testing.T) {
	names, err := fs.Glob(Files, "examples/denial-*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("no denial examples: %v", err)
	}
	for _, name := range names {
		data, err := Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spec.LoadTree(spec.SchemaDenial, data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOpSubmitExampleHash(t *testing.T) {
	data, err := Files.ReadFile("examples/op-submit-pr-merge.json")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := spec.ParseStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	m := tree.(map[string]any)
	doc := map[string]any{
		"spec_version": spec.SpecVersion,
		"project":      m["project"],
		"op":           m["op"],
		"target":       m["target"],
		"params":       m["params"],
	}
	got, err := spec.OpHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	if want := m["op_hash"]; got != want {
		t.Errorf("op_hash = %s, example says %v", got, want)
	}
}

// The routes the dependent tickets build on must stay in the contract.
func TestOpenAPIHasRoutes(t *testing.T) {
	data, err := Files.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, route := range []string{
		"/v0/ops:", "/v0/ops/{id}:", "/v0/ops/{id}/cancel:", "/v0/runs:", "/v0/runs/{id}:", "/v0/runs/{id}/end:",
		"/v0/runs/{id}/revoke:", "/v0/runs/revoke-all:", "/v0/dev-tokens:", "/v0/approvals:",
		"/v0/approvals/{id}:", "/v0/catalog:", "/v0/ledger:", "/v0/ledger/verify:", "/v0/status:",
		"/v0/vault/status:", "/v0/host/events:", "/v0/host/runs/{op_id}/output:",
		"/v0/host/runs/{op_id}/result:", "/git/{owner}/{repo}.git/info/refs:",
		"/git/{owner}/{repo}.git/git-upload-pack:", "/git/{owner}/{repo}.git/git-receive-pack:",
	} {
		if !strings.Contains(text, "\n  "+route+"\n") {
			t.Errorf("openapi.yaml has no path %s", route)
		}
	}
	for _, ref := range []string{"denial.schema.json", "operation-request.schema.json", "ledger-event.schema.json"} {
		if !strings.Contains(text, ref) {
			t.Errorf("openapi.yaml does not reference spec schema %s", ref)
		}
	}
}

// openapiDoc parses openapi.yaml.
func openapiDoc(t *testing.T) map[string]any {
	t.Helper()
	data, err := Files.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// dig walks nested maps by key.
func dig(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("openapi.yaml: no map before %q", k)
		}
		if v, ok = m[k]; !ok {
			t.Fatalf("openapi.yaml: no member %q (path %v)", k, keys)
		}
	}
	return v
}

// LF-2: GET /v0/runs/{id} is a control-JWT read of exactly four members.
func TestRunStatusContract(t *testing.T) {
	doc := openapiDoc(t)
	get := dig(t, doc, "paths", "/v0/runs/{id}", "get")
	if id := dig(t, get, "operationId"); id != "getRunStatus" {
		t.Errorf("operationId %v", id)
	}
	sec, _ := dig(t, get, "security").([]any)
	if len(sec) != 1 || !reflect.DeepEqual(sec[0], map[string]any{"controlJwt": []any{}}) {
		t.Errorf("security %v: the route takes the control JWT and nothing else", sec)
	}
	scheme := dig(t, doc, "components", "securitySchemes", "controlJwt")
	if dig(t, scheme, "type") != "http" || dig(t, scheme, "scheme") != "bearer" {
		t.Errorf("controlJwt scheme %v", scheme)
	}
	for _, code := range []string{"200", "401", "404"} {
		dig(t, get, "responses", code)
	}
	for _, code := range []string{"403", "409"} {
		if _, ok := dig(t, get, "responses").(map[string]any)[code]; ok {
			t.Errorf("response %s is not part of the contract", code)
		}
	}

	rs := dig(t, doc, "components", "schemas", "RunStatus")
	props, _ := dig(t, rs, "properties").(map[string]any)
	var names []string
	for k := range props {
		names = append(names, k)
	}
	if len(names) != 4 {
		t.Errorf("RunStatus members %v, want exactly state, ended_at, cause_code, expires_at", names)
	}
	for _, k := range []string{"state", "ended_at", "cause_code", "expires_at"} {
		if _, ok := props[k]; !ok {
			t.Errorf("RunStatus has no %s", k)
		}
	}
	if dig(t, rs, "additionalProperties") != false {
		t.Error("RunStatus must close additionalProperties")
	}
}

// The golden bodies are what chapd sends (cmd/chapd checks that) and must
// satisfy the RunStatus schema of openapi.yaml.
func TestRunStatusExamplesValidate(t *testing.T) {
	schema, err := json.Marshal(dig(t, openapiDoc(t), "components", "schemas", "RunStatus"))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	raw, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("mem:///run-status.json", raw); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("mem:///run-status.json")
	if err != nil {
		t.Fatal(err)
	}
	names, err := fs.Glob(Files, "examples/run-status-*.json")
	if err != nil || len(names) != 3 {
		t.Fatalf("run-status examples %v: %v", names, err)
	}
	for _, name := range names {
		data, err := Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := sch.Validate(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The schema is not vacuous: a fifth member and a bad state are refused.
	for _, bad := range []string{
		`{"cause_code":null,"ended_at":null,"expires_at":"2026-10-24T22:05:00Z","state":"active","project":"acme-shop"}`,
		`{"cause_code":null,"ended_at":null,"expires_at":"2026-10-24T22:05:00Z","state":"revoked"}`,
		`{"ended_at":null,"expires_at":"2026-10-24T22:05:00Z","state":"active"}`,
	} {
		v, _ := jsonschema.UnmarshalJSON(strings.NewReader(bad))
		if sch.Validate(v) == nil {
			t.Errorf("schema accepted %s", bad)
		}
	}
}

// manual.yaml is flat enough to read without a YAML parser: this pins its
// rules (every op disabled by default is a property of policy, the file only
// carries text and class).
func TestManualData(t *testing.T) {
	data, err := Files.ReadFile("manual.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opRe := regexp.MustCompile(`^  ([a-z][a-z0-9.]*):$`)
	fieldRe := regexp.MustCompile(`^    (class|reversibility|surface|summary|usage): (.+)$`)
	classes := map[string]bool{"routine": true, "gated": true, "high": true, "critical": true}
	revs := map[string]bool{"reversible": true, "compensable": true, "irreversible": true}
	surfaces := map[string]bool{"op": true, "git": true}

	type entry map[string]string
	ops := map[string]entry{}
	var cur entry
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	inOps := false
	for sc.Scan() {
		line := sc.Text()
		if line == "ops:" {
			inOps = true
			continue
		}
		if !inOps {
			continue
		}
		if m := opRe.FindStringSubmatch(line); m != nil {
			cur = entry{}
			ops[m[1]] = cur
			continue
		}
		if m := fieldRe.FindStringSubmatch(line); m != nil && cur != nil {
			cur[m[1]] = m[2]
		}
	}
	if len(ops) == 0 {
		t.Fatal("no ops in manual.yaml")
	}
	for name, e := range ops {
		for _, k := range []string{"class", "reversibility", "surface", "summary", "usage"} {
			if e[k] == "" {
				t.Errorf("%s: missing %s", name, k)
			}
		}
		if !classes[e["class"]] {
			t.Errorf("%s: bad class %q", name, e["class"])
		}
		if !revs[e["reversibility"]] {
			t.Errorf("%s: bad reversibility %q", name, e["reversibility"])
		}
		if !surfaces[e["surface"]] {
			t.Errorf("%s: bad surface %q", name, e["surface"])
		}
		if len(e["summary"]) > 60 {
			t.Errorf("%s: summary is %d characters, max 60", name, len(e["summary"]))
		}
		if len(e["usage"]) > 100 {
			t.Errorf("%s: usage is %d characters, max 100", name, len(e["usage"]))
		}
	}
	// Decisions #15 and #21: these are critical, never merely high.
	for _, name := range []string{"repo.settings", "secrets.write", "host.scripts.refresh"} {
		if ops[name]["class"] != "critical" {
			t.Errorf("%s must be class critical", name)
		}
	}
	// A typical docs profile (4 ops) must fit the 1 KB manual budget.
	size := 0
	for _, name := range []string{"pr.open", "branch.push", "health", "logs"} {
		e := ops[name]
		size += len(name) + len(e["summary"]) + len(e["usage"]) + 6
	}
	if size >= 1024 {
		t.Errorf("a four-op manual is %d bytes, want < 1024", size)
	}
}
