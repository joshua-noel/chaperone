package redteam

// fakeApprovals is the approvals engine as ops.Service sees it (ops.Approvals).
// chapd wires the real engine into ops (cmd/chapd/approvals.go, proved end to end
// in cmd/chapd/approvals_e2e_test.go); the rig is a copy of that wiring that
// cannot import package main, so the HTTP-level red-team tests use this
// stand-in. It is the same shape as internal/ops's own fake: a card is a row,
// and a decision is whatever the test sets, because the red-team tests attack
// what an agent can do over HTTP. The real engine's decision, binding and
// replay rules are attacked directly in rt11_approvals_engine_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

type fakeApprovals struct {
	mu   sync.Mutex
	n    int
	byID map[string]ops.ApprovalInfo
}

func (f *fakeApprovals) Create(_ context.Context, _ *store.Tx, in ops.ApprovalInput) (ops.ApprovalInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byID == nil {
		f.byID = map[string]ops.ApprovalInfo{}
	}
	f.n++
	info := ops.ApprovalInfo{
		ID: fmt.Sprintf("a-%06d", f.n), RequestID: in.RequestID, Op: in.Op, OpHash: in.OpHash, State: "pending",
		Class: in.Class, Critical: in.Critical, PolicyVersion: in.PolicyVer, CreatedAt: time.Unix(1790000000, 0).UTC(),
		ExpiresAt: in.ExpiresAt, OwnerKey: in.Caller.Key(),
	}
	f.byID[info.ID] = info
	return info, nil
}

func (f *fakeApprovals) Lookup(_ context.Context, id string) (ops.ApprovalInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byID[id]; ok {
		return a, nil
	}
	return ops.ApprovalInfo{}, ops.ErrApprovalNotFound
}

func (f *fakeApprovals) List(_ context.Context, owner, state string, _ int, _ string) ([]ops.ApprovalInfo, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ops.ApprovalInfo
	for _, a := range f.byID {
		if a.OwnerKey == owner && (state == "" || a.State == state) {
			out = append(out, a)
		}
	}
	return out, "", nil
}

func (f *fakeApprovals) CancelTx(_ context.Context, _ *store.Tx, id, _ string) error {
	f.set(id, "cancelled")
	return nil
}

// ConsumeTx spends a card once, as the real engine does: the second release
// of the same approval is refused.
func (f *fakeApprovals) ConsumeTx(_ context.Context, _ *store.Tx, id string, _ spec.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id]
	if a.State == "consumed" {
		return &ops.Refusal{Code: "APPROVAL_CONSUMED", Why: "this approval has already released an op"}
	}
	a.State = "consumed"
	f.byID[id] = a
	return nil
}

func (f *fakeApprovals) set(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id]
	a.State = state
	f.byID[id] = a
}

func (f *fakeApprovals) cards() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.byID)
}

// decide is what the console does after a WebAuthn assertion: the engine marks
// the card and calls Service.Decided in its own transaction, then releases.
func (g *rig) decide(t *testing.T, ap *fakeApprovals, opID, approvalID string, approved bool) {
	t.Helper()
	ctx := context.Background()
	if approved {
		ap.set(approvalID, "approved")
	} else {
		ap.set(approvalID, "denied")
	}
	if err := g.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		return g.svc.Decided(ctx, tx, opID, approvalID, ops.Decision{Approved: approved, Reason: "decided in the red-team rig"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.svc.Release(ctx, opID); err != nil {
		t.Fatal(err)
	}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// approvalReq is the body of POST /v0/approvals.
func approvalReq(op, ref string, params map[string]any) map[string]any {
	m := opBody(op, ref, params)
	m["kind"] = "op"
	m["reason"] = "red-team"
	return m
}

// waitOpState polls GET /v0/ops/{id} until the op reaches want.
func waitOpState(t *testing.T, g *rig, token, id, want string) {
	t.Helper()
	var got any
	for range 150 {
		_, body := g.call("GET", "/v0/ops/"+id, token, nil)
		if got = body["state"]; got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("op %s is %v, want %s", id, got, want)
}

// status sends a request and returns only the status: for probes where the
// answer (a mux's plain-text 404 or 405) need not be JSON.
func (g *rig) status(method, path, token string, body any) int {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			g.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, g.srv.URL+path, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
