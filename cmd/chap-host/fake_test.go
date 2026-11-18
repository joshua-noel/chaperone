package main

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// fakeChapd is a scripted chapd: Next hands out the queued events, then blocks
// until the context ends. It records what the helper sends back.
type fakeChapd struct {
	mu      sync.Mutex
	queue   []any // Event or error
	wake    chan struct{}
	outputs map[string]*strings.Builder
	results map[string]Result
	doneCh  chan string
	nextErr error // returned by Output when set
}

func newFakeChapd() *fakeChapd {
	return &fakeChapd{wake: make(chan struct{}, 1), outputs: map[string]*strings.Builder{}, results: map[string]Result{}, doneCh: make(chan string, 16)}
}

func (f *fakeChapd) push(items ...any) {
	f.mu.Lock()
	f.queue = append(f.queue, items...)
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeChapd) Next(ctx context.Context) (Event, error) {
	for {
		f.mu.Lock()
		if len(f.queue) > 0 {
			it := f.queue[0]
			f.queue = f.queue[1:]
			f.mu.Unlock()
			if err, ok := it.(error); ok {
				return Event{}, err
			}
			return it.(Event), nil
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-f.wake:
		}
	}
}

func (f *fakeChapd) Output(_ context.Context, id string, chunk []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nextErr != nil {
		return f.nextErr
	}
	if f.outputs[id] == nil {
		f.outputs[id] = &strings.Builder{}
	}
	f.outputs[id].Write(chunk)
	return nil
}

func (f *fakeChapd) Done(_ context.Context, id string, r Result) error {
	f.mu.Lock()
	f.results[id] = r
	f.mu.Unlock()
	f.doneCh <- id
	return nil
}

func (f *fakeChapd) output(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.outputs[id]; b != nil {
		return b.String()
	}
	return ""
}

func (f *fakeChapd) result(id string) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.results[id]
}

// fakeToaster records calls.
type fakeToaster struct {
	mu    sync.Mutex
	calls []string
	fail  error
	ch    chan string
}

func newFakeToaster() *fakeToaster { return &fakeToaster{ch: make(chan string, 32)} }

func (f *fakeToaster) record(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
	f.ch <- s
	if f.fail != nil {
		return f.fail
	}
	return nil
}

func (f *fakeToaster) Show(_ context.Context, n int) error { return f.record("show " + toastText(n)) }
func (f *fakeToaster) Clear(context.Context) error         { return f.record("clear") }
func (f *fakeToaster) setFail(err error)                   { f.mu.Lock(); f.fail = err; f.mu.Unlock() }

var errTransient = errors.New("connection refused")
