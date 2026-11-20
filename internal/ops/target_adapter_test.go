package ops

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/spec"
)

type tagAdapter struct{ tag string }

func (a tagAdapter) Check(context.Context, *Request) (CheckResult, error) {
	return CheckResult{Checks: []Check{{Name: a.tag, Passed: true}}}, nil
}

func (a tagAdapter) Execute(context.Context, *Request) (Outcome, error) {
	return Outcome{ExternalRef: a.tag}, nil
}

func TestByTargetPicksTheConnectorTheTargetNames(t *testing.T) {
	m := ByTarget{"github": tagAdapter{"gh"}, "linear": tagAdapter{"lin"}}
	for adapter, want := range map[string]string{"github": "gh", "linear": "lin"} {
		req := &Request{Op: "issue.comment", Target: spec.Target{Adapter: adapter, Ref: "x"}}
		cr, err := m.Check(context.Background(), req)
		if err != nil || len(cr.Checks) != 1 || cr.Checks[0].Name != want {
			t.Errorf("%s Check: %+v %v", adapter, cr, err)
		}
		out, err := m.Execute(context.Background(), req)
		if err != nil || out.ExternalRef != want {
			t.Errorf("%s Execute: %+v %v", adapter, out, err)
		}
	}
}

func TestByTargetRefusesATargetNoConnectorServes(t *testing.T) {
	m := ByTarget{"github": tagAdapter{"gh"}, "linear": tagAdapter{"lin"}}
	req := &Request{Op: "issue.comment", Target: spec.Target{Adapter: "jira", Ref: "x"}}
	_, err := m.Check(context.Background(), req)
	ref, ok := err.(*Refusal)
	if !ok || ref.Code != CodeParamsInvalid || !strings.Contains(ref.Why, "github, linear") {
		t.Fatalf("Check: %v", err)
	}
	out, err := m.Execute(context.Background(), req)
	if err != nil || !out.Failed || !strings.Contains(out.Result["error"].(string), "jira") {
		t.Errorf("Execute: %+v %v", out, err)
	}
}
