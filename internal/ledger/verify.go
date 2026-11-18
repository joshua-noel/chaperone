package ledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// Problem codes reported by [Verify].
const (
	ProblemBadEvent       = "BAD_EVENT"       // a stored event is not strict JSON or not an object
	ProblemNotCanonical   = "NOT_CANONICAL"   // stored text is not the RFC 8785 form of the event
	ProblemColumnMismatch = "COLUMN_MISMATCH" // an indexed copy disagrees with the event JSON
	ProblemSeqGap         = "SEQ_GAP"         // a seq is missing between two events
	ProblemChain          = "CHAIN"           // spec.VerifyChain finding: hash, prev_hash, order, trace_id
	ProblemHeadMissing    = "HEAD_MISSING"    // events exist, no head record
	ProblemHeadMismatch   = "HEAD_MISMATCH"   // head differs from the last event: cut-off tail
	ProblemAnchor         = "ANCHOR_MISMATCH" // a ledger.anchor names a head the chain does not have

	ProblemExportDiffers = "EXPORT_DIFFERS" // JSONL line and SQLite row differ
	ProblemExportMissing = "EXPORT_MISSING" // export is shorter than what was exported before
	ProblemExportAhead   = "EXPORT_AHEAD"   // export holds events SQLite does not
	ProblemExportGap     = "EXPORT_GAP"     // export skips, repeats or reorders seq
	ProblemExportBadLine = "EXPORT_BAD_LINE"
	ProblemExportTorn    = "EXPORT_TORN" // last line has no newline: a crash mid-export; run Export to repair
	ProblemExportStray   = "EXPORT_STRAY"
)

// maxChainProblems caps the VerifyChain findings kept per chain: one dropped
// row makes every later event "off by one", which is noise.
const maxChainProblems = 20

// Problem is one defect found by [Verify].
type Problem struct {
	Code string
	Seq  int64 // -1 when not about one event
	Msg  string
}

func (p Problem) String() string {
	if p.Seq >= 0 {
		return fmt.Sprintf("%s seq %d: %s", p.Code, p.Seq, p.Msg)
	}
	return p.Code + ": " + p.Msg
}

// ChainReport is the result for one chain.
type ChainReport struct {
	Chain    string
	Events   int64 // rows read
	HeadSeq  int64 // last event's seq, -1 if none
	HeadHash string
	// ExportedThrough is the highest seq the JSONL export holds correctly and
	// without a gap; -1 if none or if the export was not checked.
	ExportedThrough int64
	// Unexported is how many events are newer than the export (normal until the
	// next Export). Only set when the export was checked.
	Unexported int64
	Problems   []Problem
}

// Report is the result of [Verify].
type Report struct {
	Chains []ChainReport
}

// OK reports whether no chain has a problem.
func (r Report) OK() bool {
	for _, c := range r.Chains {
		if len(c.Problems) > 0 {
			return false
		}
	}
	return true
}

// Problems lists every problem of every chain.
func (r Report) Problems() []Problem {
	var out []Problem
	for _, c := range r.Chains {
		out = append(out, c.Problems...)
	}
	return out
}

// ErrVerifyFailed wraps the summary returned by [Report.Err]. A caller that
// sees it raises stop code [StopChainBroken].
var ErrVerifyFailed = errors.New("ledger: verification failed (" + StopChainBroken + ")")

// Err is nil for a clean report, else [ErrVerifyFailed] with every problem.
func (r Report) Err() error {
	ps := r.Problems()
	if len(ps) == 0 {
		return nil
	}
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return fmt.Errorf("%w: %d problem(s):\n%s", ErrVerifyFailed, len(ps), strings.Join(lines, "\n"))
}

// VerifyOptions selects what [Verify] checks.
type VerifyOptions struct {
	// Chain limits the check to one chain id; empty means every chain in the
	// database.
	Chain string
	// AgainstExport also compares SQLite with the JSONL segments under
	// ExportDir/<chain>/ (`chap ledger verify --against-export`).
	AgainstExport bool
	ExportDir     string
}

type row struct {
	seq    int64
	hash   string
	prev   string
	timeNS int64
	name   string
	run    sql.NullString
	text   string
}

// Verify checks the ledger and reports every problem it finds. The error is
// for failures to run the check at all (database unreadable); defects in the
// ledger are in the Report. It only reads, so `chap` can run it while chapd
// writes.
//
// Checked per chain: every stored event is strict I-JSON in canonical form;
// its indexed copies (chain, seq, hash, prev_hash, time, name, run_id) match
// the JSON; seq has no gaps; [spec.VerifyChain] (hash over the content,
// prev_hash links, order, trace_id, mixed chains); the committed head equals
// the last event; every ledger.anchor names an event that exists with that
// hash. With AgainstExport: every JSONL line equals the SQLite row of its seq
// byte for byte, the export has no gap and nothing SQLite lacks, and it still
// reaches the last event the exporter recorded.
func Verify(ctx context.Context, db *store.DB, opt VerifyOptions) (Report, error) {
	if opt.AgainstExport && opt.ExportDir == "" {
		return Report{}, errors.New("ledger: AgainstExport needs ExportDir")
	}
	chains := []string{opt.Chain}
	if opt.Chain == "" {
		rs, err := db.SQL().QueryContext(ctx,
			`SELECT chain FROM ledger_chains UNION SELECT DISTINCT chain FROM ledger_events ORDER BY 1`)
		if err != nil {
			return Report{}, fmt.Errorf("%w: list chains: %w", ErrUnavailable, err)
		}
		chains = nil
		for rs.Next() {
			var c string
			if err := rs.Scan(&c); err != nil {
				rs.Close()
				return Report{}, fmt.Errorf("%w: list chains: %w", ErrUnavailable, err)
			}
			chains = append(chains, c)
		}
		if err := rs.Err(); err != nil {
			rs.Close()
			return Report{}, fmt.Errorf("%w: list chains: %w", ErrUnavailable, err)
		}
		rs.Close()
	}
	var rep Report
	for _, c := range chains {
		cr, err := verifyChain(ctx, db, c, opt)
		if err != nil {
			return Report{}, err
		}
		rep.Chains = append(rep.Chains, cr)
	}
	return rep, nil
}

func verifyChain(ctx context.Context, db *store.DB, chain string, opt VerifyOptions) (ChainReport, error) {
	cr := ChainReport{Chain: chain, HeadSeq: -1, ExportedThrough: -1}
	add := func(code string, seq int64, format string, args ...any) {
		cr.Problems = append(cr.Problems, Problem{Code: code, Seq: seq, Msg: fmt.Sprintf(format, args...)})
	}
	unavailable := func(what string, err error) (ChainReport, error) {
		return cr, fmt.Errorf("%w: %s: %w", ErrUnavailable, what, err)
	}

	// One read transaction so the rows, the head and the export mark are one
	// snapshot even while chapd appends.
	conn, err := db.SQL().Conn(ctx)
	if err != nil {
		return unavailable("verify connection", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return unavailable("verify snapshot", err)
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")

	var headSeq, exportedSeq int64
	var headHash, exportedHash string
	hasHead := true
	err = conn.QueryRowContext(ctx,
		`SELECT head_seq, head_hash, exported_seq, exported_hash FROM ledger_chains WHERE chain = ?`, chain).
		Scan(&headSeq, &headHash, &exportedSeq, &exportedHash)
	if errors.Is(err, sql.ErrNoRows) {
		hasHead, exportedSeq = false, -1
	} else if err != nil {
		return unavailable("read head", err)
	}

	rs, err := conn.QueryContext(ctx,
		`SELECT seq, hash, prev_hash, time_unix_nano, event_name, run_id, event FROM ledger_events WHERE chain = ? ORDER BY seq`, chain)
	if err != nil {
		return unavailable("read events", err)
	}
	rows := map[int64]*row{}
	var texts []json.RawMessage
	var anchors []*row
	next := int64(0)
	for rs.Next() {
		r := &row{}
		if err := rs.Scan(&r.seq, &r.hash, &r.prev, &r.timeNS, &r.name, &r.run, &r.text); err != nil {
			rs.Close()
			return unavailable("read events", err)
		}
		cr.Events++
		cr.HeadSeq, cr.HeadHash = r.seq, r.hash
		rows[r.seq] = r
		if r.seq != next {
			add(ProblemSeqGap, r.seq, "expected seq %d, found %d (%d event(s) missing)", next, r.seq, r.seq-next)
		}
		next = r.seq + 1
		texts = append(texts, json.RawMessage(r.text))
		if r.name == "ledger.anchor" {
			anchors = append(anchors, r)
		}
		checkRow(r, chain, add)
	}
	if err := rs.Err(); err != nil {
		rs.Close()
		return unavailable("read events", err)
	}
	rs.Close()

	found := spec.VerifyChain(texts)
	for i, p := range found {
		if i == maxChainProblems {
			add(ProblemChain, -1, "... and %d more", len(found)-maxChainProblems)
			break
		}
		add(ProblemChain, -1, "%s", p)
	}

	switch {
	case !hasHead && cr.Events > 0:
		add(ProblemHeadMissing, -1, "the chain has %d event(s) (last seq %d) but no head record", cr.Events, cr.HeadSeq)
	case hasHead && cr.Events == 0:
		add(ProblemHeadMismatch, -1, "head says seq %d but the chain has no events (all removed)", headSeq)
	case hasHead && headSeq > cr.HeadSeq:
		add(ProblemHeadMismatch, -1, "tail cut off: head says seq %d, last event is seq %d (%d event(s) removed)", headSeq, cr.HeadSeq, headSeq-cr.HeadSeq)
	case hasHead && (headSeq != cr.HeadSeq || headHash != cr.HeadHash):
		add(ProblemHeadMismatch, -1, "head says seq %d %s, last event is seq %d %s", headSeq, headHash, cr.HeadSeq, cr.HeadHash)
	}

	for _, a := range anchors {
		checkAnchor(a, rows, add)
	}

	if opt.AgainstExport {
		checkExport(cr.Chain, opt.ExportDir, rows, cr.HeadSeq, exportedSeq, &cr, add)
	}
	return cr, nil
}

// checkRow compares a row with the JSON it carries.
func checkRow(r *row, chain string, add func(code string, seq int64, format string, args ...any)) {
	tree, err := spec.ParseStrict([]byte(r.text))
	if err != nil {
		add(ProblemBadEvent, r.seq, "stored event is not strict JSON: %v", err)
		return
	}
	m, ok := tree.(map[string]any)
	if !ok {
		add(ProblemBadEvent, r.seq, "stored event is not a JSON object")
		return
	}
	if c, err := spec.JCS(tree); err != nil || string(c) != r.text {
		add(ProblemNotCanonical, r.seq, "stored text is not the canonical (RFC 8785) form of the event")
	}
	var bad []string
	if s, _ := m["chain"].(string); s != chain {
		bad = append(bad, fmt.Sprintf("chain %q", s))
	}
	if f, ok := m["seq"].(float64); !ok || int64(f) != r.seq {
		bad = append(bad, fmt.Sprintf("seq %s", jsonScalar(m["seq"])))
	}
	if s, _ := m["hash"].(string); s != r.hash {
		bad = append(bad, "hash")
	}
	if s, _ := m["prev_hash"].(string); s != r.prev {
		bad = append(bad, "prev_hash")
	}
	if s, _ := m["event_name"].(string); s != r.name {
		bad = append(bad, "event_name")
	}
	if s, _ := m["time_unix_nano"].(string); s != strconv.FormatInt(r.timeNS, 10) {
		bad = append(bad, "time_unix_nano")
	}
	run, hasRun := m["run_id"].(string)
	if hasRun != r.run.Valid || run != r.run.String {
		bad = append(bad, "run_id")
	}
	if len(bad) > 0 {
		add(ProblemColumnMismatch, r.seq, "indexed column(s) disagree with the event JSON: %s", strings.Join(bad, ", "))
	}
}

func jsonScalar(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}

// checkAnchor: a ledger.anchor must name an earlier event that exists with the
// recorded hash.
func checkAnchor(a *row, rows map[int64]*row, add func(code string, seq int64, format string, args ...any)) {
	tree, err := spec.ParseStrict([]byte(a.text))
	if err != nil {
		return // reported as BAD_EVENT
	}
	attrs, _ := tree.(map[string]any)["attributes"].(map[string]any)
	hs, ok1 := attrs["factory.anchor.head_seq"].(float64)
	hh, ok2 := attrs["factory.anchor.head_hash"].(string)
	if !ok1 || !ok2 {
		add(ProblemAnchor, a.seq, "anchor has no head_seq/head_hash")
		return
	}
	target, ok := rows[int64(hs)]
	switch {
	case int64(hs) >= a.seq:
		add(ProblemAnchor, a.seq, "anchor covers seq %d, which is not before it", int64(hs))
	case !ok:
		add(ProblemAnchor, a.seq, "anchor covers seq %d, which is not in the chain", int64(hs))
	case target.hash != hh:
		add(ProblemAnchor, a.seq, "anchor says seq %d has hash %s, the chain has %s: events before the anchor were rewritten", int64(hs), hh, target.hash)
	}
}

var segmentRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl$`)

// segments lists the day files of one chain in order, and any other regular
// file. A missing directory is an empty list.
func segments(dir string) (days, stray []string, err error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, e := range ents {
		switch {
		case e.IsDir():
			stray = append(stray, e.Name()+"/")
		case segmentRE.MatchString(e.Name()):
			days = append(days, e.Name())
		default:
			stray = append(stray, e.Name())
		}
	}
	sort.Strings(days)
	return days, stray, nil
}

// selfHashOK reports whether text is an event whose hash matches its content.
func selfHashOK(text []byte) bool {
	tree, err := spec.ParseStrict(text)
	if err != nil {
		return false
	}
	m, ok := tree.(map[string]any)
	if !ok {
		return false
	}
	got, err := spec.EventHash(m)
	return err == nil && m["hash"] == got
}

func checkExport(chain, root string, rows map[int64]*row, headSeq, markSeq int64, cr *ChainReport,
	add func(code string, seq int64, format string, args ...any)) {
	dir := filepath.Join(root, chain)
	days, stray, err := segments(dir)
	if err != nil {
		add(ProblemExportMissing, -1, "cannot read export directory %s: %v", dir, err)
		return
	}
	for _, s := range stray {
		add(ProblemExportStray, -1, "unexpected entry %q in %s", s, dir)
	}
	next := int64(0)
	through := int64(-1)
	contiguous := true
	for _, day := range days {
		data, err := os.ReadFile(filepath.Join(dir, day))
		if err != nil {
			add(ProblemExportMissing, -1, "cannot read %s: %v", day, err)
			contiguous = false
			continue
		}
		lineNo := 0
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				add(ProblemExportTorn, -1, "%s ends with an incomplete line (%d bytes): a crash during export; run Export to repair", day, len(data))
				break
			}
			line := data[:i]
			data = data[i+1:]
			lineNo++
			var h struct {
				Chain string `json:"chain"`
				Seq   *int64 `json:"seq"`
			}
			if err := json.Unmarshal(line, &h); err != nil || h.Seq == nil {
				add(ProblemExportBadLine, -1, "%s line %d is not a ledger event", day, lineNo)
				next++
				contiguous = false
				continue
			}
			seq := *h.Seq
			if h.Chain != chain {
				add(ProblemExportBadLine, seq, "%s line %d belongs to chain %q", day, lineNo, h.Chain)
				next = seq + 1
				contiguous = false
				continue
			}
			if seq != next {
				add(ProblemExportGap, seq, "%s line %d: expected seq %d, found %d", day, lineNo, next, seq)
				contiguous = false
			}
			next = seq + 1
			r, ok := rows[seq]
			switch {
			case !ok && seq > headSeq:
				add(ProblemExportAhead, seq, "export holds this event but SQLite does not (SQLite tail cut off, or export forged)")
				contiguous = false
			case !ok:
				add(ProblemExportDiffers, seq, "export holds this event but SQLite has no row for it (row dropped)")
				contiguous = false
			case string(line) != r.text:
				add(ProblemExportDiffers, seq, "%s line %d differs from the SQLite row (export line hash %s, SQLite row hash %s): edited in only one place",
					day, lineNo, okWord(selfHashOK(line)), okWord(selfHashOK([]byte(r.text))))
				contiguous = false
			case contiguous:
				through = seq
			}
		}
	}
	cr.ExportedThrough = through
	if markSeq > through {
		add(ProblemExportMissing, -1, "the exporter recorded events through seq %d but the export holds only through seq %d (segment truncated or deleted)", markSeq, through)
	}
	if headSeq > through {
		cr.Unexported = headSeq - through
	}
}

func okWord(ok bool) string {
	if ok {
		return "valid"
	}
	return "INVALID"
}
