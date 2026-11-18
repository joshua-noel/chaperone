package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// Query limits.
const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 1000
)

// QueryParams selects events of this ledger's chain. Zero fields do not filter.
type QueryParams struct {
	RunID     string
	RequestID string // factory.request_id attribute
	EventName string
	From, To  time.Time // From <= event time < To
	AfterSeq  *int64    // only events with seq > *AfterSeq (paging)
	Limit     int       // default [DefaultQueryLimit], at most [MaxQueryLimit]
}

// Query returns events in seq order. It reads the stored events as they are:
// it does not verify the chain (use [Ledger.Verify]). With no filter the events
// are the whole chain, with no gap in seq.
func (l *Ledger) Query(ctx context.Context, p QueryParams) ([]spec.Event, error) {
	limit := p.Limit
	switch {
	case limit <= 0:
		limit = DefaultQueryLimit
	case limit > MaxQueryLimit:
		limit = MaxQueryLimit
	}
	conds := []string{"chain = ?"}
	args := []any{l.chain}
	if p.RunID != "" {
		conds, args = append(conds, "run_id = ?"), append(args, p.RunID)
	}
	if p.EventName != "" {
		conds, args = append(conds, "event_name = ?"), append(args, p.EventName)
	}
	if p.RequestID != "" {
		conds, args = append(conds, `json_extract(event, '$.attributes."factory.request_id"') = ?`), append(args, p.RequestID)
	}
	if !p.From.IsZero() {
		conds, args = append(conds, "time_unix_nano >= ?"), append(args, p.From.UnixNano())
	}
	if !p.To.IsZero() {
		conds, args = append(conds, "time_unix_nano < ?"), append(args, p.To.UnixNano())
	}
	if p.AfterSeq != nil {
		conds, args = append(conds, "seq > ?"), append(args, *p.AfterSeq)
	}
	args = append(args, limit)
	rs, err := l.db.SQL().QueryContext(ctx,
		"SELECT event FROM ledger_events WHERE "+strings.Join(conds, " AND ")+" ORDER BY seq LIMIT ?", args...)
	if err != nil {
		return nil, fmt.Errorf("%w: query: %w", ErrUnavailable, err)
	}
	defer rs.Close()
	var out []spec.Event
	for rs.Next() {
		var text string
		if err := rs.Scan(&text); err != nil {
			return nil, fmt.Errorf("%w: query: %w", ErrUnavailable, err)
		}
		var ev spec.Event
		dec := json.NewDecoder(bytes.NewReader([]byte(text)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ev); err != nil {
			return nil, l.markBroken(fmt.Errorf("%w: stored event does not decode: %w", ErrChainBroken, err))
		}
		out = append(out, ev)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("%w: query: %w", ErrUnavailable, err)
	}
	return out, nil
}

// Verify checks this ledger's chain, with the JSONL export when againstExport
// is set and Config.ExportDir is known. See the package-level [Verify].
func (l *Ledger) Verify(ctx context.Context, againstExport bool) (Report, error) {
	return Verify(ctx, l.db, VerifyOptions{Chain: l.chain, AgainstExport: againstExport, ExportDir: l.cfg.ExportDir})
}
