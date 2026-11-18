package main

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Service is the helper's loop: take events from chapd, keep the toast in step
// with the approval count, and run grants.
type Service struct {
	Chapd  Chapd
	Toast  Toaster
	Runner *Runner
	Log    *slog.Logger
	// Backoff is the wait before reconnecting after the nth consecutive
	// failure (n starts at 1). Nil means 1 s doubling to 30 s.
	Backoff func(n int) time.Duration

	shown int // pending count the toast currently shows; 0 = none
}

func defaultBackoff(n int) time.Duration {
	d := time.Second << min(n-1, 5)
	return min(d, 30*time.Second)
}

// Run serves until ctx ends, then waits for a running script to stop (it is
// killed with ctx) and returns ctx's error.
func (s *Service) Run(ctx context.Context) error {
	backoff := s.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	failures := 0
	for ctx.Err() == nil {
		ev, err := s.Chapd.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			failures++
			s.Log.Warn("chapd stream", "err", err, "retry", backoff(failures).String())
			select {
			case <-ctx.Done():
			case <-time.After(backoff(failures)):
			}
			continue
		}
		failures = 0
		switch ev.Kind {
		case EventApprovals:
			s.syncToast(ctx, ev.Pending)
		case EventGrant:
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.runGrant(ctx, ev)
			}()
		default:
			s.Log.Warn("ignoring unknown event", "kind", ev.Kind)
		}
	}
	return ctx.Err()
}

// syncToast shows the count when it changes and clears the toast at zero. A
// toast that failed is retried on the next event.
func (s *Service) syncToast(ctx context.Context, pending int) {
	if pending == s.shown {
		return
	}
	var err error
	if pending == 0 {
		err = s.Toast.Clear(ctx)
	} else {
		err = s.Toast.Show(ctx, pending)
	}
	if err != nil {
		s.Log.Warn("toast failed", "err", err)
		return
	}
	s.shown = pending
}

func (s *Service) runGrant(ctx context.Context, ev Event) {
	out := newChapdOutput(ctx, s.Chapd, ev.OpID, s.Log)
	o := s.Runner.Run(ctx, ev.Grant, out)
	out.Close()
	// Report even when ctx is ending: the operator should see "failed".
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := s.Chapd.Done(rctx, ev.OpID, o.Result); err != nil {
		s.Log.Warn("could not report result", "id", ev.OpID, "err", err)
	}
}

// chapdOutput forwards redacted script output to chapd in batches: when 4 KiB
// has built up, and once a second while the script runs. A failed send is
// logged once and later chunks are dropped: chapd being down must not stop a
// deploy that is already running.
type chapdOutput struct {
	ctx   context.Context
	chapd Chapd
	id    string
	log   *slog.Logger

	mu     sync.Mutex
	buf    []byte
	failed bool
	stop   chan struct{}
	done   chan struct{}
}

const (
	outputBatch    = 4 << 10
	outputInterval = time.Second
)

func newChapdOutput(ctx context.Context, chapd Chapd, id string, log *slog.Logger) *chapdOutput {
	o := &chapdOutput{ctx: ctx, chapd: chapd, id: id, log: log, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(o.done)
		t := time.NewTicker(outputInterval)
		defer t.Stop()
		for {
			select {
			case <-o.stop:
				return
			case <-t.C:
				o.flush()
			}
		}
	}()
	return o
}

func (o *chapdOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	if !o.failed {
		o.buf = append(o.buf, p...)
	}
	full := len(o.buf) >= outputBatch
	o.mu.Unlock()
	if full {
		o.flush()
	}
	return len(p), nil
}

func (o *chapdOutput) flush() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.buf) == 0 || o.failed {
		return
	}
	chunk := o.buf
	o.buf = nil
	if err := o.chapd.Output(context.WithoutCancel(o.ctx), o.id, chunk); err != nil {
		o.failed = true
		o.log.Warn("output not delivered to chapd; dropping the rest", "id", o.id, "err", err)
	}
}

// Close sends what is left and stops the timer.
func (o *chapdOutput) Close() {
	close(o.stop)
	<-o.done
	o.flush()
}
