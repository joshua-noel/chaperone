package ledger

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Problem codes reported by [VerifyAnchors].
const (
	ProblemAnchorNone      = "ANCHOR_NONE"           // no signed record to compare with: nothing outside the database vouches for the chain
	ProblemAnchorRewritten = "ANCHOR_REWRITTEN"      // the chain has other hashes than a record that was copied off the server
	ProblemAnchorCut       = "ANCHOR_CUT"            // a record covers events the chain no longer has
	ProblemAnchorSig       = "ANCHOR_BAD_SIGNATURE"  // a record's signature does not verify
	ProblemAnchorKey       = "ANCHOR_KEY_UNKNOWN"    // a record was signed by a key that was not supplied
	ProblemAnchorRecord    = "ANCHOR_BAD_RECORD"     // a line of the records file is not a valid record
	ProblemAnchorMissing   = "ANCHOR_RECORD_MISSING" // an anchor event has no off-box record, past the grace period
	ProblemAnchorChain     = "ANCHOR_OTHER_CHAIN"    // a record belongs to another chain
)

// DefaultAnchorGrace is how long a new ledger.anchor event may exist before a
// missing record for it is a problem: delivery runs on the scheduler tick.
const DefaultAnchorGrace = 6 * time.Hour

// AnchorVerifyOptions selects what [VerifyAnchors] compares the chain with.
type AnchorVerifyOptions struct {
	// Chain is the chain id; required.
	Chain string
	// ExportDir, when set, adds the records file chapd keeps under it
	// ([AnchorsPath]).
	ExportDir string
	// Records are further records: a copy restored from the Drive backup, or
	// lines typed in from the phone. A record held outside the server is the real
	// check, because chapd cannot have edited it.
	Records []AnchorRecord
	// Keys are the ledger public keys to trust (the current key, and old ones
	// after a rotation). A record signed by any other key is a problem.
	Keys []ed25519.PublicKey
	// Now defaults to time.Now; Grace to [DefaultAnchorGrace].
	Now   time.Time
	Grace time.Duration
}

// AnchorReport is the result of [VerifyAnchors].
type AnchorReport struct {
	Chain    string
	Checked  int           // distinct records compared with the chain
	Newest   *AnchorRecord // the record with the highest anchor seq that verified, if any
	Problems []Problem
}

// OK reports whether the chain agrees with every record and at least one record
// was checked.
func (r AnchorReport) OK() bool { return len(r.Problems) == 0 }

// VerifyAnchors compares the chain with the signed anchor records copied off the
// server (`chap ledger verify --anchor`). For each record it checks the signature
// and that the chain holds the same hash at the covered head and at the anchor
// event. A record's head hash covers every earlier event, so a rewrite of any
// event before an anchor, however consistent the rewritten chain is with
// itself, shows up as ANCHOR_REWRITTEN; a chain cut back below an anchor shows
// up as ANCHOR_CUT. It also reports each ledger.anchor event that has no record
// after the grace period (a deleted or never delivered copy), and no records at
// all as ANCHOR_NONE.
//
// The error is for failures to run the check; defects are in the report.
func VerifyAnchors(ctx context.Context, db *store.DB, opt AnchorVerifyOptions) (AnchorReport, error) {
	rep := AnchorReport{Chain: opt.Chain}
	add := func(code string, seq int64, format string, args ...any) {
		rep.Problems = append(rep.Problems, Problem{Code: code, Seq: seq, Msg: fmt.Sprintf(format, args...)})
	}
	if !chainRE.MatchString(opt.Chain) {
		return rep, errors.New("ledger: VerifyAnchors needs a chain id")
	}
	now, grace := opt.Now, opt.Grace
	if now.IsZero() {
		now = time.Now()
	}
	if grace <= 0 {
		grace = DefaultAnchorGrace
	}

	recs := append([]AnchorRecord(nil), opt.Records...)
	if opt.ExportDir != "" {
		fromFile, bad, _, err := ReadAnchorRecords(AnchorsPath(opt.ExportDir, opt.Chain))
		if err != nil {
			return rep, err
		}
		for _, b := range bad {
			add(ProblemAnchorRecord, -1, "%s: %s", AnchorsPath(opt.ExportDir, opt.Chain), b)
		}
		recs = append(recs, fromFile...)
	}
	// One record per distinct content; the same copy found twice is not two.
	type ident struct {
		seq  int64
		hash string
		sig  string
	}
	seen := map[ident]bool{}
	uniq := recs[:0:0]
	for _, r := range recs {
		id := ident{r.AnchorSeq, r.AnchorHash, r.Sig}
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, r)
		}
	}
	sort.SliceStable(uniq, func(i, j int) bool { return uniq[i].AnchorSeq < uniq[j].AnchorSeq })

	keys := map[string]ed25519.PublicKey{}
	for _, k := range opt.Keys {
		keys[KeyID(k)] = k
	}

	covered := map[int64]bool{}
	var maxSeq int64
	err := db.SQL().QueryRowContext(ctx, `SELECT coalesce(max(seq), -1) FROM ledger_events WHERE chain = ?`, opt.Chain).Scan(&maxSeq)
	if err != nil {
		return rep, fmt.Errorf("%w: read chain end: %w", ErrUnavailable, err)
	}
	hashAt := func(seq int64) (string, bool, error) {
		var h string
		err := db.SQL().QueryRowContext(ctx, `SELECT hash FROM ledger_events WHERE chain = ? AND seq = ?`, opt.Chain, seq).Scan(&h)
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("%w: read event %d: %w", ErrUnavailable, seq, err)
		}
		return h, true, nil
	}

	for _, r := range uniq {
		if r.Chain != opt.Chain {
			add(ProblemAnchorChain, r.AnchorSeq, "a record for chain %s was supplied while checking %s", r.Chain, opt.Chain)
			continue
		}
		covered[r.AnchorSeq] = true
		pub, known := keys[r.KeyID]
		switch {
		case !known:
			add(ProblemAnchorKey, r.AnchorSeq, "record for anchor seq %d was signed by key %s, which was not supplied", r.AnchorSeq, r.KeyID)
			continue
		case !r.Verify(pub):
			add(ProblemAnchorSig, r.AnchorSeq, "the signature on the record for anchor seq %d does not verify against key %s", r.AnchorSeq, r.KeyID)
			continue
		}
		rep.Checked++
		if rep.Newest == nil || r.AnchorSeq > rep.Newest.AnchorSeq {
			cp := r
			rep.Newest = &cp
		}
		for _, c := range []struct {
			what string
			seq  int64
			want string
		}{
			{"the head it covers", r.HeadSeq, r.HeadHash},
			{"the anchor event", r.AnchorSeq, r.AnchorHash},
		} {
			got, found, err := hashAt(c.seq)
			if err != nil {
				return rep, err
			}
			switch {
			case !found && c.seq > maxSeq:
				add(ProblemAnchorCut, c.seq, "the record for anchor seq %d covers %s at seq %d, but the chain ends at seq %d: %d event(s) were cut off",
					r.AnchorSeq, c.what, c.seq, maxSeq, c.seq-maxSeq)
			case !found:
				add(ProblemAnchorCut, c.seq, "the record for anchor seq %d covers %s at seq %d, which is no longer in the chain (row removed)", r.AnchorSeq, c.what, c.seq)
			case got != c.want:
				add(ProblemAnchorRewritten, c.seq, "the record for anchor seq %d says %s (seq %d) has hash %s, the chain has %s: events before the anchor were rewritten",
					r.AnchorSeq, c.what, c.seq, c.want, got)
			}
		}
	}

	// Every anchor event the chain holds should have a record somewhere.
	evs, err := anchorEvents(ctx, db.SQL(), opt.Chain, -1)
	if err != nil {
		return rep, err
	}
	for _, e := range evs {
		if covered[e.Seq] || now.Sub(time.Unix(0, e.TimeNS)) < grace {
			continue
		}
		add(ProblemAnchorMissing, e.Seq, "the chain has an anchor event at seq %d (%s) but no signed record of it was found: the off-box copy is missing",
			e.Seq, time.Unix(0, e.TimeNS).UTC().Format(time.RFC3339))
	}
	if len(uniq) == 0 {
		add(ProblemAnchorNone, -1, "no anchor record was found: nothing outside the database vouches for this chain")
	}
	return rep, nil
}

// VerifyAnchors is [VerifyAnchors] for this ledger's chain and export folder.
func (l *Ledger) VerifyAnchors(ctx context.Context, records []AnchorRecord, keys []ed25519.PublicKey) (AnchorReport, error) {
	return VerifyAnchors(ctx, l.db, AnchorVerifyOptions{
		Chain: l.chain, ExportDir: l.cfg.ExportDir, Records: records, Keys: keys, Now: l.cfg.Clock(),
	})
}

// anchorEvent is a stored ledger.anchor event of kind offline-copy.
type anchorEvent struct {
	Seq      int64
	Hash     string
	TimeNS   int64
	HeadSeq  int64
	HeadHash string
}

type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// anchorEvents lists the offline-copy ledger.anchor events after seq, oldest
// first.
func anchorEvents(ctx context.Context, q rowQuerier, chain string, after int64) ([]anchorEvent, error) {
	rs, err := q.QueryContext(ctx,
		`SELECT seq, hash, time_unix_nano, event FROM ledger_events WHERE chain = ? AND event_name = 'ledger.anchor' AND seq > ? ORDER BY seq`, chain, after)
	if err != nil {
		return nil, fmt.Errorf("%w: read anchor events: %w", ErrUnavailable, err)
	}
	defer rs.Close()
	var out []anchorEvent
	for rs.Next() {
		var e anchorEvent
		var text string
		if err := rs.Scan(&e.Seq, &e.Hash, &e.TimeNS, &text); err != nil {
			return nil, fmt.Errorf("%w: read anchor events: %w", ErrUnavailable, err)
		}
		tree, err := spec.ParseStrict([]byte(text))
		if err != nil {
			continue // reported as BAD_EVENT by Verify
		}
		attrs, _ := tree.(map[string]any)["attributes"].(map[string]any)
		if kind, _ := attrs["factory.anchor.kind"].(string); kind != AnchorKindOffline {
			continue
		}
		hs, ok1 := attrs["factory.anchor.head_seq"].(float64)
		hh, ok2 := attrs["factory.anchor.head_hash"].(string)
		if !ok1 || !ok2 {
			continue
		}
		e.HeadSeq, e.HeadHash = int64(hs), hh
		out = append(out, e)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("%w: read anchor events: %w", ErrUnavailable, err)
	}
	return out, nil
}

func (e anchorEvent) record(chain, keyID string) AnchorRecord {
	return AnchorRecord{
		Chain: chain, HeadSeq: e.HeadSeq, HeadHash: e.HeadHash, AnchorSeq: e.Seq, AnchorHash: e.Hash,
		TimeUnixNano: strconv.FormatInt(e.TimeNS, 10), KeyID: keyID,
	}
}
