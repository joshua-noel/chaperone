package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

var (
	// ErrQueueFull means the send queue was full and the wake-up was dropped.
	ErrQueueFull = errors.New("notify: send queue full, wake-up dropped")
	// ErrClosed means [Service.Close] was called.
	ErrClosed = errors.New("notify: service closed")
)

const (
	defaultTimeout = 10 * time.Second
	defaultQueue   = 64
	// maxRetain caps how long an op hash is remembered, whatever its expiry.
	maxRetain = 24 * time.Hour
)

// ServiceConfig configures a [Service].
type ServiceConfig struct {
	// Driver sends the pushes. Required.
	Driver Notifier
	// Logger receives one line per failed or dropped push. It defaults to a
	// discarding logger. Log lines carry the 8-hex op hash, never the topic.
	Logger *slog.Logger
	// Timeout bounds one send. Defaults to 10 s.
	Timeout time.Duration
	// Queue is how many wake-ups may wait for the worker. Defaults to 64. The
	// approvals package already caps pending approvals at 10 in total.
	Queue int
	// Now defaults to time.Now.
	Now func() time.Time
	// Done, if set, is called from the worker after each attempted push with the
	// 8-hex op hash and nil if the driver published it. The approvals code uses
	// it to add `phone` to `shown.channels` (ADR-004: publication, not display).
	Done func(opHash8 string, err error)
}

// Service gives a driver two properties the approval flow needs:
//
//   - One push per op hash. A hash is remembered from its first accepted
//     wake-up until the request expires; a second Notify for it sends nothing
//     and returns nil. A push that failed does not count: the next Notify for
//     the hash tries again. The memory is in process; a restart forgets it,
//     which is safe because the approvals code only calls Notify for a newly
//     created approval.
//   - Notify never blocks on the network. It validates, reserves the hash and
//     queues the send for one worker goroutine. An ntfy outage (slow, refusing
//     or unreachable) is a log line and a [ServiceConfig.Done] callback, never a
//     delay or an error in the approval path.
//
// There is no rate cap, coalescing or quiet-hours logic (decision #16).
type Service struct {
	cfg ServiceConfig
	log *slog.Logger

	mu     sync.Mutex
	seen   map[string]time.Time // full op hash -> forget-after
	closed bool
	queue  chan job

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type job struct {
	hash string
	w    Wake
}

var _ Notifier = (*Service)(nil)

// NewService starts the worker. Call [Service.Close] to stop it.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Driver == nil {
		return nil, errors.New("notify: Driver is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Queue <= 0 {
		cfg.Queue = defaultQueue
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{cfg: cfg, log: cfg.Logger, seen: map[string]time.Time{}, queue: make(chan job, cfg.Queue), done: make(chan struct{})}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.run()
	return s, nil
}

// Notify queues a wake-up. It returns at once.
//
// Errors: [ErrInvalidWake] (field outside the allowlist, or already expired),
// [ErrQueueFull], [ErrClosed]. A caller must treat every one as "no phone
// wake-up", log it, and carry on with the approval. A duplicate op hash
// returns nil and sends nothing. ctx is not used for the send, which outlives
// the request that created the approval.
func (s *Service) Notify(_ context.Context, w Wake) error {
	hash, err := w.validate()
	if err != nil {
		return err
	}
	now := s.cfg.Now()
	if !w.ExpiresAt.After(now) {
		return errors.Join(ErrInvalidWake, errors.New("already expired"))
	}
	retain := min(w.ExpiresAt.Sub(now), maxRetain)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for h, until := range s.seen {
		if !until.After(now) {
			delete(s.seen, h)
		}
	}
	if _, dup := s.seen[hash]; dup {
		return nil
	}
	select {
	case s.queue <- job{hash: hash, w: w}:
		s.seen[hash] = now.Add(retain)
		return nil
	default:
		s.log.Warn("notify: wake-up dropped, queue full", "op", hash[:8])
		return ErrQueueFull
	}
}

func (s *Service) run() {
	defer close(s.done)
	for j := range s.queue {
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.Timeout)
		err := s.cfg.Driver.Notify(ctx, j.w)
		cancel()
		if err != nil {
			s.mu.Lock()
			delete(s.seen, j.hash) // not published: a later Notify may try again
			s.mu.Unlock()
			s.log.Warn("notify: push failed", "op", j.hash[:8], "kind", j.w.Kind, "err", err)
		}
		if s.cfg.Done != nil {
			s.cfg.Done(j.hash[:8], err)
		}
	}
}

// Close stops accepting wake-ups and waits for queued ones to be sent, until
// ctx ends; then it aborts the send in progress and drops the rest. It returns
// ctx's error if it had to abort.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		s.cancel()
		return nil
	case <-ctx.Done():
		s.cancel()
		<-s.done
		return ctx.Err()
	}
}
