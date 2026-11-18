package mcpfront

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/joshua-noel/chaperone/api"
)

// manualOps lists the ops of api/manual.yaml with the given surface ("" for
// all), sorted.
func manualOps(t *testing.T, surface string) []string {
	t.Helper()
	data, err := api.Files.ReadFile("manual.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Ops map[string]struct {
			Surface string `yaml:"surface"`
		} `yaml:"ops"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var ops []string
	for op, e := range doc.Ops {
		if surface == "" || e.Surface == surface {
			ops = append(ops, op)
		}
	}
	sort.Strings(ops)
	return ops
}

// The ops the contract describes with a Params schema, and the ones it does
// not (yet). Each of the second kind gets an open object as its params and is
// checked by chapd alone. A new op must either get a Params component in
// api/openapi.yaml or be listed here on purpose; an op that gains one must
// leave this list.
var noParamsSchema = []string{
	"approvers.enroll", "data.apply", "drive.share", "host.scripts.refresh",
	"mail.send", "notion.write", "policy.activate", "repo.settings", "secrets.write",
}

func TestEveryCatalogOpHasASchemaOrIsListed(t *testing.T) {
	for _, op := range manualOps(t, "op") {
		_, _, has := paramsSchema(op)
		listed := slices.Contains(noParamsSchema, op)
		switch {
		case !has && !listed:
			t.Errorf("op %s has no Params schema in api/openapi.yaml (%s) and is not in noParamsSchema", op, paramsSchemaName(op))
		case has && listed:
			t.Errorf("op %s now has %s: remove it from noParamsSchema", op, paramsSchemaName(op))
		}
	}
	for _, op := range noParamsSchema {
		if !slices.Contains(manualOps(t, "op"), op) {
			t.Errorf("noParamsSchema lists %s, which is not an op of api/manual.yaml", op)
		}
	}
}

func TestEveryParamsSchemaBelongsToACatalogOp(t *testing.T) {
	names := map[string]string{}
	for _, op := range manualOps(t, "") {
		names[paramsSchemaName(op)] = op
	}
	got := paramsSchemaNames()
	if len(got) < 10 {
		t.Fatalf("only %d Params schemas were read from api/openapi.yaml", len(got))
	}
	for _, n := range got {
		if _, ok := names[n]; !ok {
			t.Errorf("api/openapi.yaml has %s, but no op of api/manual.yaml maps to it", n)
		}
	}
}

func TestParamsSchemasRejectUnknownProperties(t *testing.T) {
	for _, op := range manualOps(t, "") {
		s, _, ok := paramsSchema(op)
		if !ok {
			continue // listed in noParamsSchema
		}
		if s["additionalProperties"] != false {
			t.Errorf("%s: the params schema accepts unknown properties", op)
		}
		if s["type"] != "object" {
			t.Errorf("%s: params schema type = %v", op, s["type"])
		}
	}
}

func TestToolInputSchemaShape(t *testing.T) {
	s := inputSchema("pr.view", true)
	props := s["properties"].(map[string]any)
	want := []string{argTarget, argParams, argProject, argReason, argDryRun, argWait, argApprovalID, argRequestApproval}
	for _, k := range want {
		if props[k] == nil {
			t.Errorf("no %s property", k)
		}
	}
	if len(props) != len(want) {
		t.Errorf("properties = %d, want %d", len(props), len(want))
	}
	if s["additionalProperties"] != false {
		t.Error("unknown arguments are accepted")
	}
	// An op without a Params component gets an open object.
	open := inputSchema("mail.send", true)["properties"].(map[string]any)[argParams].(map[string]any)
	if open["type"] != "object" || strings.Contains(toJSON(open), "properties") {
		t.Errorf("params of an op with no schema = %v", open)
	}
}

// A tool description is read by a model, so it carries no ticket reference
// from the contract's prose.
func TestToolDescriptionsCarryNoTicketReferences(t *testing.T) {
	s := &server{}
	for _, op := range manualOps(t, "op") {
		d := s.opTool(catalogEntry{Op: op, Class: "routine", Reversibility: "reversible", Surface: "op", Enabled: true, Summary: "x"})["description"].(string)
		for _, junk := range []string{"L1-", "Phase 1", "ADR-"} {
			if strings.Contains(d, junk) {
				t.Errorf("%s: description mentions %q:\n%s", op, junk, d)
			}
		}
	}
}
