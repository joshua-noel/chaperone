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
	"runtime"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// ErrExportMismatch: the JSONL export and SQLite disagree about events that
// were already exported (an edit, a cut-off tail or a deleted segment). Export
// stops instead of papering over it; run [Verify] with AgainstExport and raise
// [StopChainBroken].
var ErrExportMismatch = errors.New("ledger: export disagrees with SQLite (" + StopChainBroken + ")")

// exportBatch is how many events one query reads.
const exportBatch = 1000

// ExportResult says what one [Ledger.Export] call did.
type ExportResult struct {
	Events  int64 // events written by this call
	Through int64 // seq of the last exported event, -1 if none
}

// Export appends every event not yet exported to the daily segment
// `<ExportDir>/<chain>/<yyyy-mm-dd>.jsonl` (UTC day of the event), one
// canonical event per line, calls fsync on each segment it wrote (and on the
// directory when it created a segment), and only then records the export mark
// in SQLite. A crash leaves at worst a torn last line, which the next Export
// removes and rewrites.
//
// An event whose clock reading is earlier than its predecessor's day goes to
// the predecessor's segment, so segments follow seq order.
//
// Before writing it checks that the newest exported line equals the SQLite row
// and that the export still reaches the recorded mark; otherwise it returns
// [ErrExportMismatch] and writes nothing.
func (l *Ledger) Export(ctx context.Context) (ExportResult, error) {
	if l.cfg.ExportDir == "" {
		return ExportResult{Through: -1}, errors.New("ledger: Config.ExportDir is not set")
	}
	l.exportMu.Lock()
	defer l.exportMu.Unlock()
	res := ExportResult{Through: -1}

	dir := filepath.Join(l.cfg.ExportDir, l.chain)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return res, fmt.Errorf("ledger: export directory: %w", err)
	}
	last, err := lastExported(dir)
	if err != nil {
		return res, err
	}

	var headSeq, markSeq int64
	err = l.db.SQL().QueryRowContext(ctx,
		`SELECT head_seq, exported_seq FROM ledger_chains WHERE chain = ?`, l.chain).Scan(&headSeq, &markSeq)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res.Through = last.seq
		if last.seq >= 0 {
			return res, fmt.Errorf("%w: export holds seq %d, SQLite has no events", ErrExportMismatch, last.seq)
		}
		return res, nil // nothing appended yet
	case err != nil:
		return res, fmt.Errorf("%w: read export mark: %w", ErrUnavailable, err)
	}
	res.Through = last.seq
	switch {
	case last.seq > headSeq:
		return res, fmt.Errorf("%w: export holds seq %d, SQLite head is seq %d", ErrExportMismatch, last.seq, headSeq)
	case last.seq < markSeq:
		return res, fmt.Errorf("%w: the exporter recorded events through seq %d but the export ends at seq %d", ErrExportMismatch, markSeq, last.seq)
	case last.seq >= 0:
		var text string
		if err := l.db.SQL().QueryRowContext(ctx, `SELECT event FROM ledger_events WHERE chain = ? AND seq = ?`, l.chain, last.seq).Scan(&text); err != nil {
			return res, fmt.Errorf("%w: read event %d: %w", ErrUnavailable, last.seq, err)
		}
		if text != string(last.line) {
			return res, fmt.Errorf("%w: seq %d differs between the export and SQLite", ErrExportMismatch, last.seq)
		}
	}

	prevDay := last.day
	for {
		batch, err := l.readAfter(ctx, res.Through)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			return res, nil
		}
		// Group consecutive events by segment.
		for i := 0; i < len(batch); {
			day := dayOf(batch[i].timeNS)
			if day < prevDay {
				day = prevDay
			}
			j := i
			var buf bytes.Buffer
			for ; j < len(batch); j++ {
				d := dayOf(batch[j].timeNS)
				if d < day {
					d = day
				}
				if d != day {
					break
				}
				buf.WriteString(batch[j].text)
				buf.WriteByte('\n')
			}
			if err := appendSegment(dir, day, buf.Bytes()); err != nil {
				return res, err
			}
			prevDay = day
			res.Events += int64(j - i)
			i = j
		}
		tail := batch[len(batch)-1]
		err = l.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE ledger_chains SET exported_seq = ?, exported_hash = ? WHERE chain = ?`, tail.seq, tail.hash, l.chain)
			return err
		})
		if err != nil {
			return res, wrapDB(fmt.Errorf("record export mark: %w", err))
		}
		res.Through = tail.seq
	}
}

// RunExport calls [Ledger.Export] now and then every interval until ctx ends.
// Errors go to onErr (nil drops them); a failed export is retried next tick.
func (l *Ledger) RunExport(ctx context.Context, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := l.Export(ctx); err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func dayOf(ns int64) string { return time.Unix(0, ns).UTC().Format("2006-01-02") }

type exportRow struct {
	seq    int64
	hash   string
	timeNS int64
	text   string
}

// readAfter reads the next batch of events after seq, which must follow one
// another without a gap.
func (l *Ledger) readAfter(ctx context.Context, seq int64) ([]exportRow, error) {
	rs, err := l.db.SQL().QueryContext(ctx,
		`SELECT seq, hash, time_unix_nano, event FROM ledger_events WHERE chain = ? AND seq > ? ORDER BY seq LIMIT ?`, l.chain, seq, exportBatch)
	if err != nil {
		return nil, fmt.Errorf("%w: read events to export: %w", ErrUnavailable, err)
	}
	defer rs.Close()
	var out []exportRow
	want := seq + 1
	for rs.Next() {
		var r exportRow
		if err := rs.Scan(&r.seq, &r.hash, &r.timeNS, &r.text); err != nil {
			return nil, fmt.Errorf("%w: read events to export: %w", ErrUnavailable, err)
		}
		if r.seq != want {
			return nil, fmt.Errorf("%w: SQLite jumps from seq %d to %d", ErrExportMismatch, want-1, r.seq)
		}
		want++
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("%w: read events to export: %w", ErrUnavailable, err)
	}
	return out, nil
}

type lastLine struct {
	seq  int64 // -1 when the export is empty
	day  string
	line []byte
}

// lastExported finds the newest complete line of the export. A torn last line
// (a crash during a write) is cut off the newest segment first.
func lastExported(dir string) (lastLine, error) {
	none := lastLine{seq: -1}
	days, _, err := segments(dir)
	if err != nil {
		return none, fmt.Errorf("ledger: list export segments: %w", err)
	}
	for i := len(days) - 1; i >= 0; i-- {
		path := filepath.Join(dir, days[i])
		data, err := os.ReadFile(path)
		if err != nil {
			return none, fmt.Errorf("ledger: read segment %s: %w", days[i], err)
		}
		if i == len(days)-1 && len(data) > 0 && data[len(data)-1] != '\n' {
			cut := bytes.LastIndexByte(data, '\n') + 1
			if err := truncateSync(path, int64(cut)); err != nil {
				return none, fmt.Errorf("ledger: repair torn segment %s: %w", days[i], err)
			}
			data = data[:cut]
		}
		if len(data) == 0 {
			continue
		}
		body := data[:len(data)-1]
		line := body[bytes.LastIndexByte(body, '\n')+1:]
		var h struct {
			Seq *int64 `json:"seq"`
		}
		if err := json.Unmarshal(line, &h); err != nil || h.Seq == nil {
			return none, fmt.Errorf("%w: last line of %s is not a ledger event", ErrExportMismatch, days[i])
		}
		return lastLine{seq: *h.Seq, day: strings.TrimSuffix(days[i], ".jsonl"), line: line}, nil
	}
	return none, nil
}

func truncateSync(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// appendSegment appends data to the day's segment and fsyncs it, and the
// directory too when the segment is new.
func appendSegment(dir, day string, data []byte) error {
	path := filepath.Join(dir, day+".jsonl")
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("ledger: open segment: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("ledger: write segment: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("ledger: fsync segment: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ledger: close segment: %w", err)
	}
	if created {
		return syncDir(dir)
	}
	return nil
}

// syncDir makes a new directory entry durable. Windows cannot fsync a
// directory handle; NTFS journals the entry itself.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("ledger: open export directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("ledger: fsync export directory: %w", err)
	}
	return nil
}
