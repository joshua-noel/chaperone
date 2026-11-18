package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type harness struct {
	t      *testing.T
	chapd  *fakeChapd
	toast  *fakeToaster
	s      *scratch
	cancel context.CancelFunc
	done   chan error
}

func startService(t *testing.T, script string) *harness {
	t.Helper()
	h := &harness{t: t, chapd: newFakeChapd(), toast: newFakeToaster(), s: newScratch(t, script, 30*time.Second), done: make(chan error, 1)}
	svc := &Service{
		Chapd: h.chapd, Toast: h.toast, Runner: h.s.runner,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Backoff: func(int) time.Duration { return time.Millisecond },
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- svc.Run(ctx) }()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	select {
	case err := <-h.done:
		if !errors.Is(err, context.Canceled) {
			h.t.Errorf("Run returned %v", err)
		}
		h.done <- err
	case <-time.After(20 * time.Second):
		h.t.Error("service did not stop")
	}
}

func (h *harness) nextToast() string {
	h.t.Helper()
	select {
	case c := <-h.toast.ch:
		return c
	case <-time.After(20 * time.Second):
		h.t.Fatal("no toast call")
		return ""
	}
}

func (h *harness) waitDone(id string) Result {
	h.t.Helper()
	select {
	case got := <-h.chapd.doneCh:
		if got != id {
			h.t.Fatalf("result for %q, want %q", got, id)
		}
		return h.chapd.result(id)
	case <-time.After(30 * time.Second):
		h.t.Fatal("no result reported")
		return Result{}
	}
}

func TestToastFollowsApprovalCount(t *testing.T) {
	h := startService(t, "echo x")
	pend := func(n int) Event { return Event{Kind: EventApprovals, Pending: n} }
	h.chapd.push(pend(0), pend(3), pend(3), pend(1), pend(2), pend(0), pend(0))
	for _, want := range []string{"show 3 approvals waiting", "show 1 approval waiting", "show 2 approvals waiting", "clear"} {
		if got := h.nextToast(); got != want {
			t.Fatalf("toast call %q, want %q", got, want)
		}
	}
	select {
	case extra := <-h.toast.ch:
		t.Fatalf("unexpected toast call %q (repeat counts and zero-at-start must be silent)", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestToastFailureIsRetried(t *testing.T) {
	h := startService(t, "echo x")
	h.toast.setFail(errors.New("no desktop"))
	h.chapd.push(Event{Kind: EventApprovals, Pending: 2})
	if got := h.nextToast(); got != "show 2 approvals waiting" {
		t.Fatal(got)
	}
	h.toast.setFail(nil)
	h.chapd.push(Event{Kind: EventApprovals, Pending: 2})
	if got := h.nextToast(); got != "show 2 approvals waiting" {
		t.Fatalf("a failed toast was not retried: %q", got)
	}
}

func TestGrantEventRunsAndReports(t *testing.T) {
	h := startService(t, "echo deployed")
	tok := h.s.token(h.s.grantFor("deploy"))
	h.chapd.push(Event{Kind: EventGrant, OpID: "op-1", Grant: tok})
	r := h.waitDone("op-1")
	if r.Status != "succeeded" {
		t.Fatalf("%+v", r)
	}
	if out := h.chapd.output("op-1"); !strings.Contains(out, "ran: deployed") {
		t.Fatalf("output sent to chapd: %q", out)
	}

	// The same grant delivered again is refused and runs nothing.
	h.chapd.push(Event{Kind: EventGrant, OpID: "op-2", Grant: tok})
	r = h.waitDone("op-2")
	if r.Status != "refused" || r.Code != "GRANT_REPLAYED" || h.chapd.output("op-2") != "" {
		t.Fatalf("replay: %+v %q", r, h.chapd.output("op-2"))
	}
	if h.s.launched.Load() != 1 {
		t.Fatalf("launched %d", h.s.launched.Load())
	}
}

func TestForgedGrantEventRefused(t *testing.T) {
	h := startService(t, "echo must-not-run")
	other := newScratch(t, "echo must-not-run", time.Second)
	h.chapd.push(Event{Kind: EventGrant, OpID: "op-9", Grant: other.token(h.s.grantFor("deploy"))})
	r := h.waitDone("op-9")
	if r.Status != "refused" || r.Code != "GRANT_SIGNATURE" || h.s.launched.Load() != 0 {
		t.Fatalf("%+v launched=%d", r, h.s.launched.Load())
	}
}

func TestOutputFailureDoesNotStopScript(t *testing.T) {
	h := startService(t, "echo still-runs")
	h.chapd.mu.Lock()
	h.chapd.nextErr = errTransient
	h.chapd.mu.Unlock()
	h.chapd.push(Event{Kind: EventGrant, OpID: "op-3", Grant: h.s.token(h.s.grantFor("deploy"))})
	if r := h.waitDone("op-3"); r.Status != "succeeded" {
		t.Fatalf("%+v", r)
	}
}

func TestStreamErrorsReconnect(t *testing.T) {
	h := startService(t, "echo x")
	h.chapd.push(errTransient, errTransient, Event{Kind: "mystery"}, Event{Kind: EventApprovals, Pending: 4})
	if got := h.nextToast(); got != "show 4 approvals waiting" {
		t.Fatal(got)
	}
}

func TestDefaultBackoff(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := defaultBackoff(i + 1); got != w {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
}

func TestShutdownKillsRunningScript(t *testing.T) {
	h := startService(t, "sleep")
	h.chapd.push(Event{Kind: EventGrant, OpID: "op-4", Grant: h.s.token(h.s.grantFor("deploy"))})
	deadline := time.Now().Add(20 * time.Second)
	for h.s.launched.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(30 * time.Second):
		t.Fatal("service did not stop with a script running")
	}
	h.done <- context.Canceled
	if time.Since(start) > 25*time.Second {
		t.Fatal("slow shutdown")
	}
	if r := h.chapd.result("op-4"); r.Status != "failed" {
		t.Fatalf("killed script reported %+v", r)
	}
}
