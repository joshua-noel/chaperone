package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ByTarget is the [Adapter] of an op name that more than one connector
// implements (one name, one class, many adapters;
// `issue.comment` on GitHub and on Linear). It picks the connector's adapter by
// the request's `target.adapter` and refuses a target no connector serves. The
// policy (enabled, rate, token scope) is per op name and is applied before the
// adapter is reached, so each connector's adapter must still refuse a project
// that has no policy block for it, as the Linear adapters do.
type ByTarget map[string]Adapter

var _ Adapter = ByTarget(nil)

func (m ByTarget) pick(req *Request) (Adapter, error) {
	if ad, ok := m[req.Target.Adapter]; ok && ad != nil {
		return ad, nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return nil, &Refusal{Code: CodeParamsInvalid, Why: fmt.Sprintf("%s has no adapter for target.adapter %q; it serves %s", req.Op, clip(req.Target.Adapter, 40), strings.Join(names, ", "))}
}

// Check forwards to the connector the target names.
func (m ByTarget) Check(ctx context.Context, req *Request) (CheckResult, error) {
	ad, err := m.pick(req)
	if err != nil {
		return CheckResult{}, err
	}
	return ad.Check(ctx, req)
}

// Execute forwards to the connector the target names.
func (m ByTarget) Execute(ctx context.Context, req *Request) (Outcome, error) {
	ad, err := m.pick(req)
	if err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": err.(*Refusal).Why}}, nil
	}
	return ad.Execute(ctx, req)
}
