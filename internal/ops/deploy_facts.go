package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// This file reads the two facts on the server that `deploy` needs besides GitHub
// and the pilot itself: the load gate (scripts/pilot-host/load-gate.ps1) and
// the last valid backup (scripts/pilot-host/backup.ps1). Both are small JSON
// files written by host scripts, read here and never written.
//
// Both readers fail closed: a missing, unreadable, oversized, malformed, empty
// or future-dated file is a reason to refuse, never a pass. Nothing about a
// file's content except a fixed word list and numbers reaches an error or a
// card: a file the pilot's scripts wrote could be edited by anyone who can
// write that folder.

const (
	// LoadGateNormal is the one gate mode a deploy runs in.
	LoadGateNormal = "normal"

	// DefaultGateMaxAge: the gate script runs every few minutes; a reading
	// older than this says nothing about now.
	DefaultGateMaxAge = 5 * time.Minute

	// DefaultBackupMaxAge is the hygiene limit of heartbeat.ps1 and
	// hygiene-check.mjs: a `validatedAt` older than 26 hours means no valid backup.
	DefaultBackupMaxAge = 26 * time.Hour

	// futureSkew is how far ahead of the clock a timestamp may be before it is
	// treated as forged or as a broken clock.
	futureSkew = time.Minute

	maxFactFile = 64 << 10
)

// LoadGate is the gate's last reading.
type LoadGate struct {
	Mode      string
	CheckedAt time.Time
}

// BackupFact is `last-valid-backup.json`: the newest dump that passed
// `pg_restore -l`.
type BackupFact struct {
	ValidatedAt time.Time
	File        string
	Path        string
	Bytes       int64
	Entries     int64
}

// HostFacts reads the files. Paths are absolute in production and temporary in
// tests.
type HostFacts struct {
	GatePath   string // %LOCALAPPDATA%\Storefront\load-gate.json
	BackupPath string // D:\Storefront\health\last-valid-backup.json
	// DumpSize, when set, returns the size of the dump file the backup fact
	// names (its `path`). A zero size, or a file that is gone, refuses the
	// deploy. An access error is not a refusal: chapd's account may not be able
	// to read C:\Storefront\pilot-backups, and the fact file's `bytes` is
	// then the only witness. Nil skips this check.
	DumpSize func(path string) (int64, error)
}

func readFact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("the file is not configured")
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("the file does not exist")
		}
		return nil, errors.New("the file cannot be read")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFactFile+1))
	if err != nil {
		return nil, errors.New("the file cannot be read")
	}
	if len(raw) > maxFactFile {
		return nil, errors.New("the file is too large")
	}
	// PowerShell 5.1's Out-File and Set-Content write a UTF-8 or UTF-16 BOM.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if len(raw) >= 2 && ((raw[0] == 0xFF && raw[1] == 0xFE) || (raw[0] == 0xFE && raw[1] == 0xFF)) {
		raw = utf16ToUTF8(raw)
	}
	return raw, nil
}

// utf16ToUTF8 decodes the BOM-marked UTF-16 that Windows PowerShell 5.1 writes
// with `Out-File` by default. Only code units below 0x80 matter for the JSON
// these files hold; anything else becomes '?', which the JSON parser then
// rejects or which lands in a string no caller trusts.
func utf16ToUTF8(raw []byte) []byte {
	le := raw[0] == 0xFF
	raw = raw[2:]
	out := make([]byte, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		var u uint16
		if le {
			u = uint16(raw[i]) | uint16(raw[i+1])<<8
		} else {
			u = uint16(raw[i])<<8 | uint16(raw[i+1])
		}
		if u < 0x80 {
			out = append(out, byte(u))
		} else {
			out = append(out, '?')
		}
	}
	return out
}

// strictFact decodes one JSON object and ignores unknown fields (the scripts
// add fields over time), but refuses trailing data.
func strictFact(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return errors.New("the file is not valid JSON of the expected shape")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("the file has data after the JSON object")
	}
	return nil
}

func parseFactTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("the timestamp is not RFC 3339")
}

// ReadLoadGate reads the gate file.
func (f HostFacts) ReadLoadGate() (LoadGate, error) {
	raw, err := readFact(f.GatePath)
	if err != nil {
		return LoadGate{}, err
	}
	var doc struct {
		Mode      string `json:"mode"`
		CheckedAt string `json:"checkedAt"`
	}
	if err := strictFact(raw, &doc); err != nil {
		return LoadGate{}, err
	}
	at, err := parseFactTime(doc.CheckedAt)
	if err != nil {
		return LoadGate{}, errors.New("checkedAt: " + err.Error())
	}
	return LoadGate{Mode: doc.Mode, CheckedAt: at}, nil
}

// ReadBackup reads the last valid backup fact.
func (f HostFacts) ReadBackup() (BackupFact, error) {
	raw, err := readFact(f.BackupPath)
	if err != nil {
		return BackupFact{}, err
	}
	var doc struct {
		ValidatedAt string `json:"validatedAt"`
		File        string `json:"file"`
		Path        string `json:"path"`
		Bytes       int64  `json:"bytes"`
		Entries     int64  `json:"entries"`
	}
	if err := strictFact(raw, &doc); err != nil {
		return BackupFact{}, err
	}
	at, err := parseFactTime(doc.ValidatedAt)
	if err != nil {
		return BackupFact{}, errors.New("validatedAt: " + err.Error())
	}
	return BackupFact{ValidatedAt: at, File: doc.File, Path: doc.Path, Bytes: doc.Bytes, Entries: doc.Entries}, nil
}

// judgeGate applies the gate rule: mode `normal` and a reading under maxAge old.
func judgeGate(g LoadGate, now time.Time, maxAge time.Duration) (ok bool, detail string) {
	age := now.Sub(g.CheckedAt)
	switch {
	case age < -futureSkew:
		return false, "the load gate reading is dated in the future"
	case age > maxAge:
		return false, fmt.Sprintf("the load gate reading is %s old (limit %s)", roundAge(age), maxAge)
	case g.Mode != LoadGateNormal:
		return false, "the load gate is " + gateWord(g.Mode) + ", not " + LoadGateNormal
	}
	return true, fmt.Sprintf("%s, read %s ago", LoadGateNormal, roundAge(age))
}

// gateWord shows a gate mode only if it is a plain lowercase word.
func gateWord(mode string) string {
	if mode == "" || len(mode) > 20 || strings.Trim(mode, "abcdefghijklmnopqrstuvwxyz-") != "" {
		return "in an unknown mode"
	}
	return mode
}

// judgeBackup applies the backup rule: validated, non-empty, and young enough.
func judgeBackup(b BackupFact, now time.Time, maxAge time.Duration) (ok bool, detail string) {
	age := now.Sub(b.ValidatedAt)
	switch {
	case age < -futureSkew:
		return false, "the last valid backup is dated in the future"
	case b.Bytes <= 0:
		return false, "the last valid backup is empty (0 bytes)"
	case b.Entries <= 0:
		return false, "the last valid backup lists no entries"
	case age > maxAge:
		return false, fmt.Sprintf("the last valid backup is %s old (limit %s)", roundAge(age), maxAge)
	}
	return true, fmt.Sprintf("validated %s ago, %d bytes", roundAge(age), b.Bytes)
}

func roundAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}
