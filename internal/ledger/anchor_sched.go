package ledger

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Alert keys the scheduler raises (each matches alerts.ps1's key pattern).
const (
	// AlertExportStale: no JSONL export has completed for [AnchorsConfig.StaleAfter]
	// (26 hours by default, the same bound the hygiene check uses for backups).
	AlertExportStale = "ledger-export-stale"
	// AlertExportBroken: the export and SQLite disagree about events already
	// exported (an edit, a cut-off tail, a deleted segment). Raised at once.
	AlertExportBroken = "ledger-export-broken"
	// AlertAnchorStale: no anchor has reached both the records file and the
	// phone for [AnchorsConfig.StaleAfter].
	AlertAnchorStale = "ledger-anchor-stale"
)

// Alerter raises and clears the operator's alerts (alerts.ps1 -Raise/-Resolve on
// the server). Raise is called again every [alertRepeat] while the problem lasts;
// the script itself decides when to show a toast. Both must return quickly and
// never fail the caller.
type Alerter interface {
	Raise(ctx context.Context, key, text string)
	Resolve(ctx context.Context, key string)
}

const (
	defaultAnchorEvery = 24 * time.Hour
	defaultExportEvery = 10 * time.Minute
	defaultStaleAfter  = 26 * time.Hour
	defaultTick        = time.Minute
	defaultRetryEvery  = 10 * time.Minute
	alertRepeat        = 30 * time.Minute
	notifyTimeout      = 20 * time.Second
)

// AnchorsConfig configures [Anchors].
type AnchorsConfig struct {
	// Ledger is the chain to export and anchor; its Config.ExportDir must be set.
	Ledger *Ledger
	// Signer signs each record with the ledger key. Required.
	Signer AnchorSigner
	// Notifier delivers each anchor to the operator's phone. Required: an anchor
	// that reaches only the server proves nothing.
	Notifier notify.AnchorNotifier
	// Alerts raises the stale and broken alerts. Nil logs them only.
	Alerts Alerter
	Log    *slog.Logger
	// Now defaults to the ledger's clock.
	Now func() time.Time

	// AnchorEvery is the gap between daily anchors (default 24 h); a deploy
	// result newer than the last anchor makes one at once.
	AnchorEvery time.Duration
	// ExportEvery is how often the JSONL export runs (default 10 min).
	ExportEvery time.Duration
	// StaleAfter is how long an export or a delivery may be missing before an
	// alert is raised (default 26 h).
	StaleAfter time.Duration
	// Tick is how often the scheduler looks (default 1 min).
	Tick time.Duration
	// RetryEvery spaces retries of a failed phone delivery (default 10 min).
	RetryEvery time.Duration
}

// Anchors is the JSONL export scheduler and the anchor writer and deliverer of
// ticket L1-21 (ADR-006 "Anchors"). Every tick it
//
//  1. writes a ledger.anchor event (kind offline-copy) when one is due: daily,
//     and after every deploy that finished since the last anchor,
//  2. exports new events to the daily JSONL segments (every ExportEvery, and
//     right after an anchor),
//  3. delivers each anchor to the two places chapd cannot edit afterwards: a
//     signed record appended to <ExportDir>/anchors/<chain>.jsonl (inside the
//     nightly backup set) and an ntfy push to the operator's phone, and
//  4. raises alerts: no export for StaleAfter, no delivered anchor for
//     StaleAfter, and an export that disagrees with SQLite.
//
// Because a daily anchor is itself an event, the export folder changes at least
// once a day while chapd runs; a host-side check can alert when it does not.
//
// All state that must survive a restart is in the database (store_meta) or in
// the records file, so a restart repeats nothing and loses nothing: an anchor
// event with no record gets its record, an unsent push is sent.
type Anchors struct {
	cfg AnchorsConfig
	log *slog.Logger
	l   *Ledger

	mu        sync.Mutex
	startedAt time.Time
	lastExp   time.Time // last export attempt
	lastPush  time.Time // last failed push attempt
	alerts    map[string]time.Time
	resolved  map[string]bool
}

// NewAnchors validates cfg.
func NewAnchors(cfg AnchorsConfig) (*Anchors, error) {
	switch {
	case cfg.Ledger == nil:
		return nil, errors.New("ledger: Anchors needs a Ledger")
	case cfg.Ledger.cfg.ExportDir == "":
		return nil, errors.New("ledger: Anchors needs Config.ExportDir (the export and the records live there)")
	case cfg.Signer == nil:
		return nil, errors.New("ledger: Anchors needs a Signer (the ledger key)")
	case cfg.Notifier == nil:
		return nil, errors.New("ledger: Anchors needs a Notifier: an anchor must also reach the phone")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = cfg.Ledger.cfg.Clock
	}
	for p, d := range map[*time.Duration]time.Duration{
		&cfg.AnchorEvery: defaultAnchorEvery, &cfg.ExportEvery: defaultExportEvery, &cfg.StaleAfter: defaultStaleAfter,
		&cfg.Tick: defaultTick, &cfg.RetryEvery: defaultRetryEvery,
	} {
		if *p <= 0 {
			*p = d
		}
	}
	return &Anchors{
		cfg: cfg, log: cfg.Log, l: cfg.Ledger, startedAt: cfg.Now(),
		alerts: map[string]time.Time{}, resolved: map[string]bool{},
	}, nil
}

// Run works until ctx ends: one pass now, then one per Tick. On the way out it
// exports once more, so a clean stop leaves the export current.
func (a *Anchors) Run(ctx context.Context) {
	t := time.NewTicker(a.cfg.Tick)
	defer t.Stop()
	for {
		a.RunOnce(ctx)
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if _, err := a.l.Export(fctx); err != nil {
				a.log.Warn("ledger: final export failed", "err", err)
			}
			cancel()
			return
		case <-t.C:
		}
	}
}

// RunOnce is one pass of the scheduler. Errors are logged and retried on the
// next pass; nothing here may block an op, and nothing here is on the append
// path.
func (a *Anchors) RunOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.cfg.Now()
	if a.anchorIfDue(ctx, now) {
		a.lastExp = time.Time{}
	}
	a.export(ctx, now) // after the anchor, so the anchor event is in the export at once
	a.deliver(ctx, now)
	a.watch(ctx, now)
}

// ---- export ----------------------------------------------------------------

func (a *Anchors) metaKey(what string) string { return "ledger." + what + "." + a.l.chain }

func (a *Anchors) getMeta(ctx context.Context, what string) (string, bool, error) {
	var v string
	err := a.l.db.SQL().QueryRowContext(ctx, `SELECT value FROM store_meta WHERE key = ?`, a.metaKey(what)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%w: read %s: %w", ErrUnavailable, what, err)
	}
	return v, true, nil
}

func (a *Anchors) setMeta(ctx context.Context, what, value string) error {
	err := a.l.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO store_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, a.metaKey(what), value)
		return err
	})
	return wrapDB(err)
}

func (a *Anchors) export(ctx context.Context, now time.Time) {
	if !a.lastExp.IsZero() && now.Sub(a.lastExp) < a.cfg.ExportEvery {
		return
	}
	a.lastExp = now
	if _, err := a.l.Export(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		a.log.Error("ledger: export failed", "err", err)
		if errors.Is(err, ErrExportMismatch) {
			a.raise(ctx, now, AlertExportBroken, "The ledger export disagrees with the database ("+StopChainBroken+"). Run chap ledger verify --against-export.")
		}
		return
	}
	a.clear(ctx, AlertExportBroken)
	if err := a.setMeta(ctx, "export.last_ok", now.UTC().Format(time.RFC3339)); err != nil {
		a.log.Error("ledger: record export time failed", "err", err)
	}
}

// ---- anchors ---------------------------------------------------------------

// deployFinishedSince reports whether a deploy op has an op.result after seq.
func (a *Anchors) deployFinishedSince(ctx context.Context, seq int64) (bool, error) {
	var one int
	err := a.l.db.SQL().QueryRowContext(ctx,
		`SELECT 1 FROM ledger_events e
		  WHERE e.chain = ? AND e.event_name = 'op.result' AND e.seq > ?
		    AND json_extract(e.event, '$.attributes."factory.request_id"') IN (SELECT id FROM ops WHERE op = 'deploy')
		  LIMIT 1`, a.l.chain, seq).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: look for a finished deploy: %w", ErrUnavailable, err)
	}
	return true, nil
}

func (a *Anchors) anchorIfDue(ctx context.Context, now time.Time) bool {
	head, _, err := a.l.Head(ctx)
	if err != nil {
		a.log.Error("ledger: anchor: read head failed", "err", err)
		return false
	}
	if head < 0 {
		return false // nothing to anchor yet
	}
	evs, err := anchorEvents(ctx, a.l.db.SQL(), a.l.chain, -1)
	if err != nil {
		a.log.Error("ledger: anchor: read anchors failed", "err", err)
		return false
	}
	reason := "daily"
	if len(evs) > 0 {
		last := evs[len(evs)-1]
		if now.Sub(time.Unix(0, last.TimeNS)) < a.cfg.AnchorEvery {
			deployed, err := a.deployFinishedSince(ctx, last.Seq)
			if err != nil {
				a.log.Error("ledger: anchor: deploy check failed", "err", err)
				return false
			}
			if !deployed {
				return false
			}
			reason = "deploy"
		}
	}
	ref := fmt.Sprintf("%s/%s.jsonl + ntfy (%s)", anchorsDirName, a.l.chain, reason)
	rc, err := a.l.Anchor(ctx, AnchorKindOffline, ref)
	if err != nil {
		a.log.Error("ledger: anchor not written", "reason", reason, "err", err)
		return false
	}
	a.log.Info("ledger: anchor written", "reason", reason, "seq", rc.Seq)
	return true
}

// ---- delivery --------------------------------------------------------------

// appendRecord appends one record line to path and fsyncs it, cutting off a
// torn last line first.
func appendRecord(path string, line []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("ledger: anchors directory: %w", err)
	}
	data, err := os.ReadFile(path)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return fmt.Errorf("ledger: read anchor records: %w", err)
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if err := truncateSync(path, int64(bytes.LastIndexByte(data, '\n')+1)); err != nil {
			return fmt.Errorf("ledger: repair torn anchor record: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("ledger: open anchor records: %w", err)
	}
	if _, err := f.Write(append(append([]byte(nil), line...), '\n')); err != nil {
		f.Close()
		return fmt.Errorf("ledger: write anchor record: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("ledger: fsync anchor records: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ledger: close anchor records: %w", err)
	}
	if created {
		return syncDir(dir)
	}
	return nil
}

// deliver gives every anchor event its signed record in the records file, then
// pushes the newest undelivered one to the phone. Older undelivered anchors are
// superseded by the newest (it covers every event they cover), so one push is
// enough after an outage.
func (a *Anchors) deliver(ctx context.Context, now time.Time) {
	path := AnchorsPath(a.l.cfg.ExportDir, a.l.chain)
	evs, err := anchorEvents(ctx, a.l.db.SQL(), a.l.chain, -1)
	if err != nil {
		a.log.Error("ledger: anchor delivery: read anchors failed", "err", err)
		return
	}
	if len(evs) == 0 {
		return
	}
	recs, _, _, err := ReadAnchorRecords(path)
	if err != nil {
		a.log.Error("ledger: anchor delivery failed", "err", err)
		return
	}
	bySeq := map[int64]AnchorRecord{}
	for _, r := range recs {
		if r.Chain == a.l.chain {
			bySeq[r.AnchorSeq] = r
		}
	}
	for _, e := range evs {
		if _, ok := bySeq[e.Seq]; ok {
			continue
		}
		rec, err := signAnchor(ctx, a.cfg.Signer, e.record(a.l.chain, a.cfg.Signer.KeyID()))
		if err != nil {
			a.log.Error("ledger: anchor not signed", "seq", e.Seq, "err", err)
			return
		}
		line, err := rec.Line()
		if err == nil {
			err = appendRecord(path, line)
		}
		if err != nil {
			a.log.Error("ledger: anchor record not written", "seq", e.Seq, "err", err)
			return
		}
		bySeq[e.Seq] = rec
	}

	newest := evs[len(evs)-1]
	sent, ok, err := a.getMeta(ctx, "anchor.notified")
	if err != nil {
		a.log.Error("ledger: anchor delivery failed", "err", err)
		return
	}
	if n, perr := strconv.ParseInt(sent, 10, 64); ok && perr == nil && n >= newest.Seq {
		return
	}
	if !a.lastPush.IsZero() && now.Sub(a.lastPush) < a.cfg.RetryEvery {
		return
	}
	rec := bySeq[newest.Seq]
	nctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	err = a.cfg.Notifier.NotifyAnchor(nctx, notify.Anchor{
		Chain: rec.Chain, HeadSeq: rec.HeadSeq, HeadHash: rec.HeadHash, KeyID: rec.KeyID, Sig: rec.Sig,
	})
	if err != nil {
		a.lastPush = now
		a.log.Error("ledger: anchor push to the phone failed; will retry", "seq", newest.Seq, "err", err)
		return
	}
	a.lastPush = time.Time{}
	if err := a.setMeta(ctx, "anchor.notified", strconv.FormatInt(newest.Seq, 10)); err != nil {
		a.log.Error("ledger: record anchor push failed", "seq", newest.Seq, "err", err)
	}
}

// ---- alerts ----------------------------------------------------------------

// watch raises or clears the two staleness alerts.
func (a *Anchors) watch(ctx context.Context, now time.Time) {
	// Export: the last time Export completed, or this scheduler's start.
	lastOK := a.startedAt
	if v, ok, err := a.getMeta(ctx, "export.last_ok"); err == nil && ok {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil && t.After(lastOK) {
			lastOK = t
		}
	}
	if age := now.Sub(lastOK); age > a.cfg.StaleAfter {
		a.raise(ctx, now, AlertExportStale, fmt.Sprintf("The ledger JSONL export has not run for %d hours (limit %d).", int(age.Hours()), int(a.cfg.StaleAfter.Hours())))
	} else {
		a.clear(ctx, AlertExportStale)
	}

	// Anchor: the newest anchor that reached the records file and the phone.
	delivered := a.startedAt
	if evs, err := anchorEvents(ctx, a.l.db.SQL(), a.l.chain, -1); err == nil && len(evs) > 0 {
		if v, ok, err := a.getMeta(ctx, "anchor.notified"); err == nil && ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			recs, _, _, _ := ReadAnchorRecords(AnchorsPath(a.l.cfg.ExportDir, a.l.chain))
			inFile := map[int64]bool{}
			for _, r := range recs {
				inFile[r.AnchorSeq] = true
			}
			for i := len(evs) - 1; i >= 0; i-- {
				if evs[i].Seq <= n && inFile[evs[i].Seq] {
					if t := time.Unix(0, evs[i].TimeNS); t.After(delivered) {
						delivered = t
					}
					break
				}
			}
		}
	}
	if age := now.Sub(delivered); age > a.cfg.StaleAfter {
		a.raise(ctx, now, AlertAnchorStale, fmt.Sprintf("No ledger anchor has reached the phone and the backup folder for %d hours (limit %d).", int(age.Hours()), int(a.cfg.StaleAfter.Hours())))
	} else {
		a.clear(ctx, AlertAnchorStale)
	}
}

// raise raises key now, and again every [alertRepeat] while it stays raised.
func (a *Anchors) raise(ctx context.Context, now time.Time, key, text string) {
	a.resolved[key] = false
	if last, ok := a.alerts[key]; ok && now.Sub(last) < alertRepeat {
		return
	}
	a.alerts[key] = now
	a.log.Error("ledger alert", "key", key, "text", text)
	if a.cfg.Alerts != nil {
		a.cfg.Alerts.Raise(ctx, key, text)
	}
}

// clear resolves key: once after a raise, and once after start (an alert raised
// before a restart is not remembered here).
func (a *Anchors) clear(ctx context.Context, key string) {
	if _, raised := a.alerts[key]; !raised && a.resolved[key] {
		return
	}
	delete(a.alerts, key)
	a.resolved[key] = true
	if a.cfg.Alerts != nil {
		a.cfg.Alerts.Resolve(ctx, key)
	}
}
