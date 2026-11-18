package linear

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Board timing defaults.
const (
	// DefaultPollInterval is how often the poller reads the board: the operator's
	// start value. It is a chapd setting; 0 turns the poller off and
	// every `intake.list` reads Linear on demand.
	DefaultPollInterval = 15 * time.Minute
	// MinPollInterval is the shortest interval chapd accepts (a typo guard: the
	// hourly budget of the client would otherwise be spent on polling).
	MinPollInterval = time.Minute
	// DefaultMinRefresh is the shortest time between two live reads of one board
	// that callers can cause: a `refresh` inside it is answered from the cache.
	DefaultMinRefresh = 30 * time.Second
	// DefaultMaxItems is the most items one list returns.
	DefaultMaxItems = 50
	// idleAfter is how long a board nobody asked for stays in the poller's list.
	idleAfter = 24 * time.Hour
)

// Sources of a snapshot.
const (
	SourceCache = "cache"
	SourceLive  = "live"
)

// BoardConfig builds a [Board].
type BoardConfig struct {
	Client *Client
	// Interval is the poll interval; 0 means no poller and no cache beyond
	// MinRefresh.
	Interval   time.Duration
	MinRefresh time.Duration
	MaxItems   int
	Now        func() time.Time
	Log        *slog.Logger
}

// Snapshot is one reading of a board.
type Snapshot struct {
	Items     []Item
	Truncated bool
	FetchedAt time.Time
	Source    string // SourceCache or SourceLive
	// Note says why a request was answered other than as asked ("refresh skipped").
	Note string
}

type boardKey struct{ team, label string }

type entry struct {
	items     []Item
	truncated bool
	fetchedAt time.Time
	lastUsed  time.Time
	dirty     bool // a write changed the board since fetchedAt
	failing   bool // the last poll failed (to log the change only)
}

// Board is the cache of the boards that were asked for. A board is one team and
// one label, both from the policy. The poller refreshes every board that was
// asked for in the last day; a write drops the board's freshness at once. It
// holds issue text in memory only.
type Board struct {
	cfg BoardConfig

	fetch   sync.Mutex // one Linear read at a time
	mu      sync.Mutex // guards entries
	entries map[boardKey]*entry
}

// NewBoard returns a Board.
func NewBoard(cfg BoardConfig) *Board {
	if cfg.MinRefresh <= 0 {
		cfg.MinRefresh = DefaultMinRefresh
	}
	if cfg.MaxItems <= 0 {
		cfg.MaxItems = DefaultMaxItems
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Board{cfg: cfg, entries: map[boardKey]*entry{}}
}

// maxAge is how old a cached board may be and still answer a plain list: two
// poll intervals (a late poll is not an outage), or MinRefresh with no poller.
func (b *Board) maxAge() time.Duration {
	if b.cfg.Interval > 0 {
		return 2 * b.cfg.Interval
	}
	return b.cfg.MinRefresh
}

// Get returns the open items of the board. A plain call is answered from the
// cache while it is fresh; refresh asks for a live read, which is still
// answered from the cache when the last read is younger than MinRefresh.
// includeClosed always reads live and is not cached.
func (b *Board) Get(ctx context.Context, team, label string, refresh, includeClosed bool) (Snapshot, error) {
	if includeClosed {
		items, trunc, err := b.cfg.Client.ListItems(ctx, team, label, true, b.cfg.MaxItems)
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{Items: items, Truncated: trunc, FetchedAt: b.cfg.Now(), Source: SourceLive}, nil
	}
	k := boardKey{team, label}
	if s, ok := b.cached(k, refresh); ok {
		return s, nil
	}
	b.fetch.Lock()
	defer b.fetch.Unlock()
	// Another caller may have read while this one waited.
	if s, ok := b.cached(k, true); ok {
		return s, nil
	}
	return b.read(ctx, k)
}

// cached returns the board from the cache when it may answer: for a plain
// call while it is younger than maxAge, for a refresh while it is younger than
// MinRefresh. A board a write touched never answers.
func (b *Board) cached(k boardKey, refresh bool) (Snapshot, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[k]
	if e == nil || e.dirty || e.fetchedAt.IsZero() {
		return Snapshot{}, false
	}
	now := b.cfg.Now()
	e.lastUsed = now
	age := now.Sub(e.fetchedAt)
	limit := b.maxAge()
	if refresh {
		limit = b.cfg.MinRefresh
	}
	if age >= limit {
		return Snapshot{}, false
	}
	return b.snapshot(e), true
}

func (b *Board) snapshot(e *entry) Snapshot {
	return Snapshot{Items: e.items, Truncated: e.truncated, FetchedAt: e.fetchedAt, Source: SourceCache}
}

// read reads Linear and stores the answer. The caller holds b.fetch.
func (b *Board) read(ctx context.Context, k boardKey) (Snapshot, error) {
	items, trunc, err := b.cfg.Client.ListItems(ctx, k.team, k.label, false, b.cfg.MaxItems)
	if err != nil {
		return Snapshot{}, err
	}
	now := b.cfg.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[k]
	if e == nil {
		e = &entry{}
		b.entries[k] = e
	}
	e.items, e.truncated, e.fetchedAt, e.lastUsed, e.dirty = items, trunc, now, now, false
	s := b.snapshot(e)
	s.Source = SourceLive
	return s, nil
}

// Invalidate marks the board as changed, so the next list reads Linear. A write
// calls it after the mutation.
func (b *Board) Invalidate(team, label string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.entries[boardKey{team, label}]; e != nil {
		e.dirty = true
	}
}

// Run polls until ctx ends. It does nothing when the interval is 0.
func (b *Board) Run(ctx context.Context) {
	if b.cfg.Interval <= 0 {
		return
	}
	t := time.NewTicker(b.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Poll(ctx)
		}
	}
}

// Poll refreshes every board that was asked for in the last day, and forgets
// the others. A failure is logged once, and again when the board recovers; the
// cache then ages out and the next list reads Linear and reports the error.
func (b *Board) Poll(ctx context.Context) {
	b.mu.Lock()
	var keys []boardKey
	now := b.cfg.Now()
	for k, e := range b.entries {
		if now.Sub(e.lastUsed) > idleAfter {
			delete(b.entries, k)
			continue
		}
		keys = append(keys, k)
	}
	b.mu.Unlock()
	for _, k := range keys {
		b.fetch.Lock()
		_, err := b.read(ctx, k)
		b.fetch.Unlock()
		b.mu.Lock()
		e := b.entries[k]
		switch {
		case e == nil:
		case err != nil && !e.failing:
			e.failing = true
			b.cfg.Log.Warn("linear: the board poll failed; list reads Linear on demand until it works", "team", k.team, "err", err)
		case err == nil && e.failing:
			e.failing = false
			b.cfg.Log.Info("linear: the board poll works again", "team", k.team)
		}
		b.mu.Unlock()
	}
}
