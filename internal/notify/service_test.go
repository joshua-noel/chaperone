package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify/ntfytest"
)

type result struct {
	op  string
	err error
}

type rig struct {
	svc  *Service
	srv  *ntfytest.Server
	done chan result
	logs *syncBuf
	top  Topic
	now  *fakeClock
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newRig(t *testing.T, mutate func(*ServiceConfig)) *rig {
	t.Helper()
	srv := ntfytest.New(t)
	topic := testTopic(t)
	drv, err := NewNtfy(NtfyConfig{Topic: topic, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{srv: srv, done: make(chan result, 256), logs: &syncBuf{}, top: topic,
		now: &fakeClock{t: time.Date(2026, 10, 24, 14, 0, 0, 0, time.UTC)}}
	cfg := ServiceConfig{
		Driver: drv,
		Logger: slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    r.now.Now,
		Done:   func(op string, err error) { r.done <- result{op, err} },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r.svc, err = NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.svc.Close(ctx)
	})
	return r
}

func (r *rig) wake(i int) Wake {
	w := goodWake()
	w.OpHash = fmt.Sprintf("%08x%s", i, goodHash[8:])
	w.ExpiresAt = r.now.Now().Add(30 * time.Minute)
	return w
}

func (r *rig) waitDone(t *testing.T) result {
	t.Helper()
	select {
	case res := <-r.done:
		return res
	case <-time.After(5 * time.Second):
		t.Fatal("no push attempt finished")
		return result{}
	}
}

func (r *rig) noMoreDone(t *testing.T) {
	t.Helper()
	select {
	case res := <-r.done:
		t.Fatalf("unexpected push attempt: %+v", res)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestServiceSendsOnePushPerOpHash(t *testing.T) {
	r := newRig(t, nil)
	w := r.wake(1)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := w
			w.Pending = 1 + i%5 // everything but the hash varies
			if err := r.svc.Notify(t.Context(), w); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if res := r.waitDone(t); res.err != nil || res.op != "00000001" {
		t.Fatalf("%+v", res)
	}
	r.noMoreDone(t)
	if n := len(r.srv.Messages()); n != 1 {
		t.Fatalf("%d pushes for one op hash", n)
	}
	// The same hash again, bare or prefixed, is still one push.
	w2 := w
	w2.OpHash = strings.TrimPrefix(w.OpHash, "sha256:")
	if err := r.svc.Notify(t.Context(), w2); err != nil {
		t.Fatal(err)
	}
	r.noMoreDone(t)
	if n := len(r.srv.Messages()); n != 1 {
		t.Fatalf("%d pushes after the repeat", n)
	}
}

func TestServiceDifferentOpHashesEachGetAPush(t *testing.T) {
	r := newRig(t, nil)
	// Same first 8 hex, different tails: they are different ops.
	a, b := r.wake(1), r.wake(1)
	b.OpHash = a.OpHash[:len(a.OpHash)-1] + "0"
	if a.OpHash == b.OpHash {
		b.OpHash = a.OpHash[:len(a.OpHash)-1] + "1"
	}
	for _, w := range []Wake{a, b, r.wake(2)} {
		if err := r.svc.Notify(t.Context(), w); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if res := r.waitDone(t); res.err != nil {
			t.Fatal(res.err)
		}
	}
	if n := len(r.srv.Messages()); n != 3 {
		t.Fatalf("%d pushes, want 3", n)
	}
}

func TestServiceForgetsHashAfterExpiry(t *testing.T) {
	r := newRig(t, nil)
	w := r.wake(1)
	_ = r.svc.Notify(t.Context(), w)
	r.waitDone(t)
	r.now.Advance(31 * time.Minute)
	w.ExpiresAt = r.now.Now().Add(30 * time.Minute) // a new request after the sticky-deny window
	_ = r.svc.Notify(t.Context(), w)
	r.waitDone(t)
	if n := len(r.srv.Messages()); n != 2 {
		t.Fatalf("%d pushes, want 2", n)
	}
}

func TestServiceFailedPushDoesNotCountAsSent(t *testing.T) {
	r := newRig(t, nil)
	r.srv.SetStatus(503)
	w := r.wake(1)
	if err := r.svc.Notify(t.Context(), w); err != nil {
		t.Fatal("an outage must not surface as a Notify error:", err)
	}
	res := r.waitDone(t)
	if !errors.Is(res.err, ErrPublish) {
		t.Fatalf("Done err = %v", res.err)
	}
	r.srv.SetStatus(0)
	_ = r.svc.Notify(t.Context(), w)
	if res := r.waitDone(t); res.err != nil {
		t.Fatal(res.err)
	}
	if n := len(r.srv.Messages()); n != 1 {
		t.Fatalf("%d pushes", n)
	}
}

// TestServiceOutageDoesNotBlockApproval: ntfy accepts the connection and never
// answers. The approval path (create the card, return it) must not wait.
func TestServiceOutageDoesNotBlockApproval(t *testing.T) {
	r := newRig(t, func(c *ServiceConfig) { c.Timeout = 300 * time.Millisecond })
	r.srv.Hang()
	createApproval := func(i int) (card string, err error) {
		card = fmt.Sprintf("card-%d", i)
		if nerr := r.svc.Notify(t.Context(), r.wake(i)); nerr != nil {
			t.Errorf("Notify: %v", nerr)
		}
		return card, nil
	}
	start := time.Now()
	for i := range 5 {
		if card, err := createApproval(i); err != nil || card == "" {
			t.Fatal(card, err)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("five approvals took %v with ntfy hung", d)
	}
	// The timeout frees the worker; every attempt ends with an error, none hangs.
	for range 5 {
		if res := r.waitDone(t); res.err == nil {
			t.Fatal("push to a hung server reported success")
		}
	}
	if n := len(r.srv.Messages()); n != 0 {
		t.Fatalf("%d messages stored", n)
	}
}

func TestServiceQueueFullDropsInsteadOfBlocking(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	drv := notifierFunc(func(ctx context.Context, _ Wake) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	r := newRig(t, func(c *ServiceConfig) { c.Driver = drv; c.Queue = 1 })
	if err := r.svc.Notify(t.Context(), r.wake(1)); err != nil {
		t.Fatal(err)
	}
	<-entered // the worker holds wake 1; wake 2 fills the queue
	if err := r.svc.Notify(t.Context(), r.wake(2)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := r.svc.Notify(t.Context(), r.wake(3))
	if !errors.Is(err, ErrQueueFull) || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	if !strings.Contains(r.logs.String(), "queue full") {
		t.Error("the dropped wake-up was not logged")
	}
	close(release)
	// A dropped hash is not remembered: it can be sent once there is room.
	r.waitDone(t)
	r.waitDone(t)
	if err := r.svc.Notify(t.Context(), r.wake(3)); err != nil {
		t.Fatal(err)
	}
	r.waitDone(t)
}

type notifierFunc func(context.Context, Wake) error

func (f notifierFunc) Notify(ctx context.Context, w Wake) error { return f(ctx, w) }

func TestServiceRejectsInvalidAndExpired(t *testing.T) {
	r := newRig(t, nil)
	w := r.wake(1)
	w.Kind = "deploy\nTo: x@y.z"
	if err := r.svc.Notify(t.Context(), w); !errors.Is(err, ErrInvalidWake) {
		t.Fatalf("err = %v", err)
	}
	w = r.wake(1)
	w.ExpiresAt = r.now.Now().Add(-time.Second)
	if err := r.svc.Notify(t.Context(), w); !errors.Is(err, ErrInvalidWake) {
		t.Fatalf("expired: err = %v", err)
	}
	r.noMoreDone(t)
	if r.srv.Requests() != 0 {
		t.Fatal("a request was sent")
	}
}

func TestServiceCloseDrainsThenRefuses(t *testing.T) {
	r := newRig(t, nil)
	for i := range 3 {
		if err := r.svc.Notify(t.Context(), r.wake(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.svc.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(r.srv.Messages()); n != 3 {
		t.Fatalf("%d pushes drained, want 3", n)
	}
	if err := r.svc.Notify(t.Context(), r.wake(9)); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	if err := r.svc.Close(t.Context()); err != nil {
		t.Fatal("second Close:", err)
	}
}

func TestServiceCloseAbortsAHungSend(t *testing.T) {
	r := newRig(t, nil)
	r.srv.Hang()
	_ = r.svc.Notify(t.Context(), r.wake(1))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := r.svc.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("Close did not abort the send")
	}
}

func TestNewServiceNeedsDriver(t *testing.T) {
	if _, err := NewService(ServiceConfig{}); err == nil {
		t.Fatal("no error")
	}
}

// TestLogsNeverPrintTheTopic runs every outcome (publish, refusal, outage,
// timeout, drop, invalid) with debug logging on, and a topic-scanning check over
// everything logged and every error returned.
func TestLogsNeverPrintTheTopic(t *testing.T) {
	r := newRig(t, func(c *ServiceConfig) { c.Timeout = 200 * time.Millisecond; c.Queue = 2 })
	secret := r.top.Reveal()
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	note(r.svc.Notify(t.Context(), r.wake(1))) // published
	note(r.waitDone(t).err)

	r.srv.SetStatus(429)
	note(r.svc.Notify(t.Context(), r.wake(2))) // refused
	note(r.waitDone(t).err)

	r.srv.SetStatus(0)
	r.srv.Hang()
	note(r.svc.Notify(t.Context(), r.wake(3))) // timeout
	note(r.waitDone(t).err)
	r.srv.Release()

	bad := r.wake(4)
	bad.Project = secret // even a leaked topic placed in a field is refused, not echoed
	note(r.svc.Notify(t.Context(), bad))

	r.srv.Hang()
	for i := 10; i < 20; i++ {
		note(r.svc.Notify(t.Context(), r.wake(i))) // fills the queue, then drops
	}
	r.srv.Release()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_ = r.svc.Close(ctx)

	logs := r.logs.String()
	if !strings.Contains(logs, "push failed") || !strings.Contains(logs, "queue full") || !strings.Contains(logs, "op=00000002") {
		t.Fatalf("expected log lines are missing:\n%s", logs)
	}
	if strings.Contains(logs, secret) {
		t.Fatalf("a log line carries the topic:\n%s", logs)
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error carries the topic: %v", err)
		}
	}
}
