package main

import (
	"context"
	"slices"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// With a GitHub client, chapd installs an adapter for every GitHub operation
// that is declared, and for nothing else but health: kit.Bind refuses a
// difference at start-up, and this shows it from the outside. Without a
// client, no GitHub operation has an adapter, and the baseline cannot turn
// one on.
func TestGitHubAdaptersAreTheDeclaredOperations(t *testing.T) {
	d := newAdapterDeps(&gh.Client{}, nil)
	d.ciRun = func(context.Context, string) (ops.CIRun, error) { return ops.CIRun{}, nil }
	ads, err := adapters(d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"health"}
	for _, c := range githubspec.Connectors {
		want = append(want, c.Names()...)
	}
	var got []string
	for op := range ads {
		got = append(got, op)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("adapters %v, declared %v (and health)", got, want)
	}

	bare, err := adapters(adapterDeps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range githubspec.Connectors {
		for _, op := range c.Names() {
			if bare[op] != nil {
				t.Errorf("%s has an adapter with no GitHub client", op)
			}
		}
	}
}

// ci.report needs the run registry as well: without it the op has no adapter,
// and the github connector's adapters still bind.
func TestCIReportNeedsTheRunRegistry(t *testing.T) {
	ads, err := adapters(newAdapterDeps(&gh.Client{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if ads[githubspec.NameCIReport] != nil {
		t.Error("ci.report has an adapter with no run registry")
	}
	if ads[githubspec.NamePRMerge] == nil {
		t.Error("pr.merge has no adapter")
	}
}
