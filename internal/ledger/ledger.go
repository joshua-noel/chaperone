package ledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// StopChainBroken is the stop-table code raised when the stored chain does
// not match its head or fails verification.
const StopChainBroken = "LEDGER_CHAIN_BROKEN"

// MaxEventBytes bounds one stored event (canonical JSON). Events carry hashes
// and short labels, never payloads, so a larger one is a bug or an attack.
const MaxEventBytes = 32 << 10

// maxBatch is the most events the writer goroutine commits in one transaction.
const maxBatch = 256

// Errors. Every error from an append means the event is NOT in the ledger and
// the operation that needed it MUST be refused.
var (
	// ErrRejected: the draft is not a valid spec event (unknown attribute,
	// missing field, too large). Nothing was written.
	ErrRejected = errors.New("ledger: event rejected")
	// ErrUnavailable: the database could not be read or written.
	ErrUnavailable = errors.New("ledger: database unavailable")
	// ErrChainBroken: the stored chain disagrees with its head ([StopChainBroken]).
	ErrChainBroken = errors.New("ledger: " + StopChainBroken)
	// ErrClosed: the ledger was closed.
	ErrClosed = errors.New("ledger: closed")
)

// Redactor masks secrets in a string. *redact.Registry is one.
type Redactor interface {
	Redact(s string) (string, redact.Result)
}

// Config configures a [Ledger].
type Config struct {
	// Instance names this chapd instance; the chain id is "chaperone.<Instance>"
	// (ADR-006), also the resource's service.instance.id. Required.
	Instance string
	// Version is the resource's service.version. Optional.
	Version string
	// ExportDir is the root of the JSONL export. Only [Ledger.Export] needs it.
	ExportDir string
	// Redactor masks secrets in every draft. Required: a ledger without one
	// would write secrets down.
	Redactor Redactor
	// Clock returns the event time. Default time.Now.
	Clock func() time.Time
}

// Draft is what a caller supplies. The ledger stamps spec_version, chain, seq,
// prev_hash, hash, time_unix_nano (unless Time is set), trace_id, span_id
// (unless set), severity_number, severity_text and resource.
type Draft struct {
	Name         string         // spec event_name, for example "op.request"
	RunID        string         // omit for events with no run (orchestrator ops, stop.*, ledger.anchor)
	Project      string         // project id
	Severity     string         // TRACE, DEBUG, INFO, WARN, ERROR or FATAL; "" means INFO
	Attributes   map[string]any // closed per Name by the spec; nil means none
	Body         string         // human-readable line, redacted; "" omits it
	SpanID       string         // 16 lowercase hex; random when empty
	ParentSpanID string         // optional
	Time         time.Time      // zero means the ledger clock
}

// Receipt says where an appended event landed.
type Receipt struct {
	Seq  int64
	Hash string
	// Redactions lists the redaction rules that masked something in the draft.
	// When it is not empty the caller MUST raise redact.CauseCode
	// (REDACTION_BLOCKED) with its own ledger event.
	Redactions []redact.Hit
}

// Ledger appends to and exports one chain. It is safe for concurrent use.
type Ledger struct {
	db    *store.DB
	cfg   Config
	chain string
	res   spec.Resource

	mu     sync.RWMutex // guards closed and the send on reqs
	closed bool
	reqs   chan *request
	wg     sync.WaitGroup

	brokenMu sync.Mutex
	broken   error // sticky ErrChainBroken

	exportMu sync.Mutex
}

var (
	instanceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
	spanRE     = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Open prepares a ledger on a migrated database and starts its writer
// goroutine. It checks the chain head against the last stored event and
// returns [ErrChainBroken] if they differ, so chapd does not start on a
// damaged ledger. Close it when done.
func Open(ctx context.Context, db *store.DB, cfg Config) (*Ledger, error) {
	switch {
	case db == nil:
		return nil, errors.New("ledger: nil database")
	case !instanceRE.MatchString(cfg.Instance):
		return nil, fmt.Errorf("ledger: instance %q must be lowercase letters, digits and '-' (chain id chaperone.<instance>)", cfg.Instance)
	case cfg.Redactor == nil:
		return nil, errors.New("ledger: a Redactor is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	l := &Ledger{
		db:    db,
		cfg:   cfg,
		chain: "chaperone." + cfg.Instance,
		res:   spec.Resource{ServiceName: "chaperone", ServiceVersion: cfg.Version, ServiceInstanceID: cfg.Instance},
		reqs:  make(chan *request, maxBatch),
	}
	if err := l.checkHead(ctx, db.SQL()); err != nil {
		return nil, err
	}
	l.wg.Add(1)
	go l.writer()
	return l, nil
}

// Chain returns the chain id, "chaperone.<instance>".
func (l *Ledger) Chain() string { return l.chain }

// Close stops the writer after it commits every queued event. Later appends
// return [ErrClosed].
func (l *Ledger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.reqs)
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

// querier is what *sql.DB, *sql.Conn and *store.Tx share.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// chainState is the head of the chain as the next append sees it.
type chainState struct {
	seq    int64 // -1 for an empty chain
	hash   string
	stored bool // a ledger_chains row exists
}

func (s chainState) nextSeq() int64 { return s.seq + 1 }

func (s chainState) prevHash() string {
	if s.seq < 0 {
		return spec.ZeroHash
	}
	return s.hash
}

// loadHead reads the chain head and checks it against the newest event. A
// mismatch is [ErrChainBroken].
func (l *Ledger) loadHead(ctx context.Context, q querier) (chainState, error) {
	st := chainState{seq: -1}
	err := q.QueryRowContext(ctx, `SELECT head_seq, head_hash FROM ledger_chains WHERE chain = ?`, l.chain).Scan(&st.seq, &st.hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		st = chainState{seq: -1}
	case err != nil:
		return st, fmt.Errorf("%w: read head: %w", ErrUnavailable, err)
	default:
		st.stored = true
	}

	var lastSeq int64
	var lastHash string
	err = q.QueryRowContext(ctx, `SELECT seq, hash FROM ledger_events WHERE chain = ? ORDER BY seq DESC LIMIT 1`, l.chain).Scan(&lastSeq, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if st.stored {
			return st, l.markBroken(fmt.Errorf("%w: head says seq %d but the chain has no events", ErrChainBroken, st.seq))
		}
	case err != nil:
		return st, fmt.Errorf("%w: read last event: %w", ErrUnavailable, err)
	default:
		switch {
		case !st.stored:
			return st, l.markBroken(fmt.Errorf("%w: chain has events (last seq %d) but no head record", ErrChainBroken, lastSeq))
		case lastSeq != st.seq || lastHash != st.hash:
			return st, l.markBroken(fmt.Errorf("%w: head says seq %d %s, last event is seq %d %s (tail cut off or head edited)",
				ErrChainBroken, st.seq, st.hash, lastSeq, lastHash))
		}
	}
	return st, nil
}

func (l *Ledger) markBroken(err error) error {
	l.brokenMu.Lock()
	defer l.brokenMu.Unlock()
	if l.broken == nil {
		l.broken = err
	}
	return err
}

func (l *Ledger) brokenErr() error {
	l.brokenMu.Lock()
	defer l.brokenMu.Unlock()
	return l.broken
}

func (l *Ledger) checkHead(ctx context.Context, q querier) error {
	if _, err := l.loadHead(ctx, q); err != nil {
		return err
	}
	return nil
}

// saveHead records st as the committed head. Inside the transaction that
// inserted the events it points at.
func (l *Ledger) saveHead(ctx context.Context, tx *store.Tx, st chainState) error {
	var err error
	if st.stored {
		_, err = tx.ExecContext(ctx, `UPDATE ledger_chains SET head_seq = ?, head_hash = ? WHERE chain = ?`, st.seq, st.hash, l.chain)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO ledger_chains (chain, head_seq, head_hash) VALUES (?, ?, ?)`, l.chain, st.seq, st.hash)
	}
	if err != nil {
		return fmt.Errorf("%w: save head: %w", ErrUnavailable, err)
	}
	return nil
}

// prepared is a validated, redacted event waiting for its seq and hash.
type prepared struct {
	tree    map[string]any
	hits    []redact.Hit
	fixedAt bool
	runID   string
	name    string
}

var severities = map[string]struct {
	number int
	text   string
}{
	"":      {9, "INFO"},
	"TRACE": {1, "TRACE"},
	"DEBUG": {5, "DEBUG"},
	"INFO":  {9, "INFO"},
	"WARN":  {13, "WARN"},
	"ERROR": {17, "ERROR"},
	"FATAL": {21, "FATAL"},
}

// placeholder envelope values: any shape-valid value, replaced by stamp.
const (
	placeholderHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	placeholderTime = "1700000000000000000"
)

// prepare turns a draft into a redacted tree that passed the spec schema,
// before any lock is taken. Errors never contain draft values: redaction runs
// first, so even the validator's messages quote masked text only.
func (l *Ledger) prepare(d Draft) (*prepared, error) {
	sev, ok := severities[d.Severity]
	if !ok {
		return nil, fmt.Errorf("%w: unknown severity %q", ErrRejected, "(redacted)")
	}
	span := d.SpanID
	if span == "" {
		var err error
		if span, err = randomSpan(); err != nil {
			return nil, fmt.Errorf("%w: span id: %w", ErrUnavailable, err)
		}
	}
	if !spanRE.MatchString(span) {
		return nil, fmt.Errorf("%w: span_id is not 16 lowercase hex", ErrRejected)
	}
	attrs := d.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	ev := spec.Event{
		SpecVersion:    spec.SpecVersion,
		Chain:          l.chain,
		Seq:            1,
		PrevHash:       placeholderHash,
		Hash:           placeholderHash,
		TimeUnixNano:   placeholderTime,
		SpanID:         span,
		ParentSpanID:   d.ParentSpanID,
		SeverityNumber: sev.number,
		SeverityText:   sev.text,
		EventName:      d.Name,
		Resource:       l.res,
		RunID:          d.RunID,
		Project:        d.Project,
		Attributes:     attrs,
	}
	if d.Body != "" {
		body := d.Body
		ev.Body = &body
	}
	if !d.Time.IsZero() {
		ev.TimeUnixNano = strconv.FormatInt(d.Time.UnixNano(), 10)
	}
	if d.RunID != "" {
		ev.TraceID = spec.TraceID(d.RunID)
	} else {
		ev.TraceID = spec.TraceID(l.chain)
	}
	tree, err := spec.Tree(ev)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	var hits []redact.Hit
	redacted, err := l.redactTree(tree, &hits)
	if err != nil {
		return nil, err
	}
	m := redacted.(map[string]any)
	if err := spec.Validate(spec.SchemaEvent, m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return &prepared{tree: m, hits: hits, name: d.Name, runID: d.RunID, fixedAt: !d.Time.IsZero()}, nil
}

func randomSpan() (string, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		if b != [8]byte{} {
			return hex.EncodeToString(b[:]), nil
		}
	}
}

// redactTree masks every string, and every object key, in v.
func (l *Ledger) redactTree(v any, hits *[]redact.Hit) (any, error) {
	switch x := v.(type) {
	case string:
		out, res := l.cfg.Redactor.Redact(x)
		mergeHits(hits, res.Hits)
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := l.redactTree(e, hits)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			nk, res := l.cfg.Redactor.Redact(k)
			mergeHits(hits, res.Hits)
			if _, dup := out[nk]; dup {
				return nil, fmt.Errorf("%w: two attribute names collide after redaction", ErrRejected)
			}
			r, err := l.redactTree(e, hits)
			if err != nil {
				return nil, err
			}
			out[nk] = r
		}
		return out, nil
	}
	return v, nil
}

func mergeHits(dst *[]redact.Hit, add []redact.Hit) {
	for _, h := range add {
		found := false
		for i := range *dst {
			if (*dst)[i].Rule == h.Rule && (*dst)[i].SecretID == h.SecretID {
				(*dst)[i].Count += h.Count
				found = true
				break
			}
		}
		if !found {
			*dst = append(*dst, h)
		}
	}
}

// stamped is an event with its final envelope.
type stamped struct {
	seq     int64
	hash    string
	prev    string
	timeNS  int64
	name    string
	runID   string
	text    string
	receipt Receipt
}

// stamp sets seq, prev_hash, time and hash on p and renders the canonical JSON.
func (l *Ledger) stamp(p *prepared, st chainState, now time.Time) (stamped, error) {
	m := p.tree
	ns := now.UnixNano()
	if !p.fixedAt {
		m["time_unix_nano"] = strconv.FormatInt(ns, 10)
	} else {
		ns, _ = strconv.ParseInt(m["time_unix_nano"].(string), 10, 64)
	}
	m["seq"] = float64(st.nextSeq())
	m["prev_hash"] = st.prevHash()
	delete(m, "hash")
	// m came from spec.Tree, so it is already a document tree: this is
	// spec.EventHash without the second JSON round trip.
	unhashed, err := spec.JCS(m)
	if err != nil {
		return stamped{}, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	hash := spec.SHA256Tagged(unhashed)
	m["hash"] = hash
	text, err := spec.JCS(m)
	if err != nil {
		return stamped{}, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if len(text) > MaxEventBytes {
		return stamped{}, fmt.Errorf("%w: event is %d bytes, the limit is %d", ErrRejected, len(text), MaxEventBytes)
	}
	return stamped{
		seq: st.nextSeq(), hash: hash, prev: st.prevHash(), timeNS: ns, name: p.name, runID: p.runID, text: string(text),
		receipt: Receipt{Seq: st.nextSeq(), Hash: hash, Redactions: p.hits},
	}, nil
}

// put inserts one stamped event and returns the new head.
func (l *Ledger) put(ctx context.Context, tx *store.Tx, s stamped) (chainState, error) {
	var run any
	if s.runID != "" {
		run = s.runID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ledger_events (chain, seq, hash, prev_hash, time_unix_nano, event_name, run_id, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		l.chain, s.seq, s.hash, s.prev, s.timeNS, s.name, run, s.text); err != nil {
		return chainState{}, fmt.Errorf("%w: insert event: %w", ErrUnavailable, err)
	}
	return chainState{seq: s.seq, hash: s.hash, stored: true}, nil
}

// AppendTx appends d inside the caller's transaction (a [store.DB.Immediate]
// function), so the state change and its event commit together. If the
// transaction rolls back the event is gone with it. Any error means the event
// was not written and the operation MUST be refused.
func (l *Ledger) AppendTx(ctx context.Context, tx *store.Tx, d Draft) (Receipt, error) {
	if err := l.brokenErr(); err != nil {
		return Receipt{}, err
	}
	p, err := l.prepare(d)
	if err != nil {
		return Receipt{}, err
	}
	st, err := l.loadHead(ctx, tx)
	if err != nil {
		return Receipt{}, err
	}
	s, err := l.stamp(p, st, l.cfg.Clock())
	if err != nil {
		return Receipt{}, err
	}
	nst, err := l.put(ctx, tx, s)
	if err != nil {
		return Receipt{}, err
	}
	nst.stored = st.stored
	if err := l.saveHead(ctx, tx, nst); err != nil {
		return Receipt{}, err
	}
	return s.receipt, nil
}

// Anchor writes a ledger.anchor event covering every event before it: its
// head_hash and head_seq are the chain head at that moment. kind is git-tag,
// transparency-log or offline-copy; ref says where the copy went. Delivery is
// L1-21; this only records it.
func (l *Ledger) Anchor(ctx context.Context, kind, ref string) (Receipt, error) {
	var r Receipt
	err := l.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		r, err = l.AnchorTx(ctx, tx, kind, ref)
		return err
	})
	return r, wrapDB(err)
}

// AnchorTx is [Ledger.Anchor] inside the caller's transaction.
func (l *Ledger) AnchorTx(ctx context.Context, tx *store.Tx, kind, ref string) (Receipt, error) {
	if err := l.brokenErr(); err != nil {
		return Receipt{}, err
	}
	st, err := l.loadHead(ctx, tx)
	if err != nil {
		return Receipt{}, err
	}
	if st.seq < 0 {
		return Receipt{}, fmt.Errorf("%w: nothing to anchor on an empty chain", ErrRejected)
	}
	p, err := l.prepare(Draft{Name: "ledger.anchor", Attributes: map[string]any{
		"factory.anchor.head_hash": st.hash,
		"factory.anchor.head_seq":  st.seq,
		"factory.anchor.kind":      kind,
		"factory.anchor.ref":       ref,
	}})
	if err != nil {
		return Receipt{}, err
	}
	s, err := l.stamp(p, st, l.cfg.Clock())
	if err != nil {
		return Receipt{}, err
	}
	nst, err := l.put(ctx, tx, s)
	if err != nil {
		return Receipt{}, err
	}
	nst.stored = true
	if err := l.saveHead(ctx, tx, nst); err != nil {
		return Receipt{}, err
	}
	return s.receipt, nil
}

// wrapDB marks an error that did not come from this package as
// [ErrUnavailable]: the transaction could not start, commit or roll back.
func wrapDB(err error) error {
	if err == nil || errors.Is(err, ErrRejected) || errors.Is(err, ErrUnavailable) ||
		errors.Is(err, ErrChainBroken) || errors.Is(err, ErrClosed) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

var errRollback = errors.New("ledger: roll back probe")

// Preflight checks, without leaving a trace, that the ledger can append now:
// the database accepts a write and the chain head matches the last event. Call
// it before work that must not start unless its event can be recorded.
func (l *Ledger) Preflight(ctx context.Context) error {
	if err := l.brokenErr(); err != nil {
		return err
	}
	err := l.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := l.loadHead(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO store_meta (key, value) VALUES ('ledger.preflight', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
			return err
		}
		return errRollback
	})
	if errors.Is(err, errRollback) {
		return nil
	}
	return wrapDB(err)
}

// Head returns the committed head: seq -1 and ZeroHash for an empty chain.
func (l *Ledger) Head(ctx context.Context) (seq int64, hash string, err error) {
	st, err := l.loadHead(ctx, l.db.SQL())
	if err != nil {
		return 0, "", err
	}
	return st.seq, st.prevHash(), nil
}
