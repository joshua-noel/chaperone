package mcpfront

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/joshua-noel/chaperone/api"
)

// The input schema of an op tool comes from the contract itself: the
// `Params<Op>` component of api/openapi.yaml (`pr.view` is `ParamsPrView`).
// The file is embedded in the binary, so the schema a client sees is the one
// the server was reviewed with, and there is no second copy to drift. An op
// the contract has no Params schema for gets an open object. The schema is
// guidance for the client: this package does not check params against it
// (only argument names and JSON types are checked), and chapd validates every
// call, so chapd is the validator. The tool description says so.

type paramSchemas struct {
	byName map[string]map[string]any
}

var loadSchemas = sync.OnceValues(func() (*paramSchemas, error) {
	data, err := api.Files.ReadFile("openapi.yaml")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("api/openapi.yaml: %w", err)
	}
	out := &paramSchemas{byName: map[string]map[string]any{}}
	for name, s := range doc.Components.Schemas {
		if strings.HasPrefix(name, "Params") {
			out.byName[name] = s
		}
	}
	return out, nil
})

// paramsSchemaName is the component an op's params are described by:
// "pr.view" is "ParamsPrView", "health" is "ParamsHealth".
func paramsSchemaName(op string) string {
	var b strings.Builder
	b.WriteString("Params")
	for _, part := range strings.Split(op, ".") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// paramsSchema returns the schema of an op's params (without its prose
// description) and that description, which says what the target must be.
func paramsSchema(op string) (schema map[string]any, description string, ok bool) {
	ps, err := loadSchemas()
	if err != nil {
		return nil, "", false
	}
	raw, ok := ps.byName[paramsSchemaName(op)]
	if !ok {
		return nil, "", false
	}
	schema = make(map[string]any, len(raw))
	for k, v := range raw {
		if k == "description" {
			description, _ = v.(string)
			continue
		}
		schema[k] = v
	}
	return schema, description, true
}

// paramsSchemaNames lists every Params component, sorted.
func paramsSchemaNames() []string {
	ps, err := loadSchemas()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ps.byName))
	for n := range ps.byName {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Argument names every op tool takes besides the op's own params.
const (
	argTarget          = "target"
	argParams          = "params"
	argProject         = "project"
	argReason          = "reason"
	argDryRun          = "dry_run"
	argWait            = "wait"
	argApprovalID      = "approval_id"
	argRequestApproval = "request_approval"
)

// inputSchema is the JSON Schema of one op tool's arguments.
func inputSchema(op string, needsTarget bool) map[string]any {
	pschema, _, found := paramsSchema(op)
	if !found {
		pschema = map[string]any{"type": "object"}
	}
	props := map[string]any{
		argTarget: map[string]any{
			"type":        "object",
			"description": "What the op acts on. The tool description says what it must be.",
			"properties": map[string]any{
				"adapter": map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9-]{0,38}$"},
				"ref":     map[string]any{"type": "string", "minLength": 1, "maxLength": 300},
			},
			"required":             []string{"adapter", "ref"},
			"additionalProperties": false,
		},
		argParams: pschema,
		argProject: map[string]any{
			"type":        "string",
			"pattern":     "^[a-z][a-z0-9-]{1,38}$",
			"description": "Project slug. Needed with an orchestrator token; a run's project is its token's.",
		},
		argReason: map[string]any{
			"type":        "string",
			"minLength":   1,
			"maxLength":   500,
			"description": "Why. Shown to the approver on the card, as untrusted text; never used for authorization.",
		},
		argDryRun: map[string]any{
			"type":        "boolean",
			"description": "Check policy and preconditions only. Nothing runs and no card is created.",
		},
		argWait: map[string]any{
			"type": "integer", "minimum": 0, "maximum": 55,
			"description": "Seconds to wait for a final state (0 to 55). Default: Chaperone's own (20).",
		},
		argApprovalID: map[string]any{
			"type":        "string",
			"pattern":     "^a-[0-9a-z]{6,32}$",
			"description": "Run this op under an approval a human already gave (an id returned by an earlier call).",
		},
		argRequestApproval: map[string]any{
			"type":        "boolean",
			"description": "Create the approval card for this exact op instead of running it. Needs a reason. Use it after a refusal that says approval is required; the op runs by itself when a human approves.",
		},
	}
	required := []string{}
	if needsTarget {
		required = append(required, argTarget)
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             required,
		"additionalProperties": false,
	}
}
