package grant

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NonceStore records nonces so that each is accepted once.
type NonceStore interface {
	// Consume records nonce until expires and returns ErrReplay if it was
	// recorded before and has not yet expired. Any other error means the nonce
	// could not be recorded; the caller must refuse the grant. Consume must be
	// safe for concurrent use and must not return nil before the record is
	// durable in the store's sense.
	Consume(nonce string, expires, now time.Time) error
}

// MemoryNonces is an in-process store, lost on restart. Tests and short-lived
// tools use it; chap-host uses [FileNonces].
type MemoryNonces struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryNonces returns an empty store.
func NewMemoryNonces() *MemoryNonces { return &MemoryNonces{seen: map[string]time.Time{}} }

// Consume implements NonceStore.
func (m *MemoryNonces) Consume(nonce string, expires, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return consumeLocked(m.seen, nonce, expires, now)
}

func consumeLocked(seen map[string]time.Time, nonce string, expires, now time.Time) error {
	for n, exp := range seen {
		if !now.Before(exp) {
			delete(seen, n)
		}
	}
	if _, dup := seen[nonce]; dup {
		return ErrReplay
	}
	seen[nonce] = expires
	return nil
}

// FileNonces keeps used nonces in an append-only file, so a restart of
// chap-host inside a grant's five-minute life does not forget them. One JSON
// object per line: {"n": nonce, "e": expiry unix seconds}. Expired entries are
// dropped when the file is opened.
type FileNonces struct {
	mu   sync.Mutex
	seen map[string]time.Time
	f    *os.File
	lock *processLock
	bad  error // set after a failed write: the file may end mid-line, so refuse everything
}

type nonceRecord struct {
	N string `json:"n"`
	E int64  `json:"e"`
}

// OpenFileNonces opens or creates the store at path (directory created with
// mode 0700, file 0600), takes an exclusive lock on path+".lock" for the life
// of the store (a second open fails), and compacts it. A complete line that
// does not parse is an error: forgetting nonces silently would reopen replay.
// A final line
// without a newline is a torn write from a crash before Consume returned, so
// that grant never ran; it is dropped.
func OpenFileNonces(path string, now time.Time) (*FileNonces, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// One chap-host per nonce file: two would each forget the other's nonces.
	lock, err := lockProcess(path + ".lock")
	if err != nil {
		return nil, err
	}
	s, err := openLocked(path, now)
	if err != nil {
		lock.Close()
		return nil, err
	}
	s.lock = lock
	return s, nil
}

func openLocked(path string, now time.Time) (*FileNonces, error) {
	seen := map[string]time.Time{}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if i := bytes.LastIndexByte(raw, '\n'); i < len(raw)-1 {
		raw = raw[:i+1] // drops the torn tail; i is -1 for no newline at all
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for line := 1; sc.Scan(); line++ {
		var r nonceRecord
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil || !nonceRe.MatchString(r.N) {
			return nil, fmt.Errorf("grant: nonce file %s line %d is corrupt", path, line)
		}
		if exp := time.Unix(r.E, 0); now.Before(exp) {
			seen[r.N] = exp
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Compact: rewrite the live entries, then append from here on.
	var buf bytes.Buffer
	for n, exp := range seen {
		line, _ := json.Marshal(nonceRecord{N: n, E: exp.Unix()})
		buf.Write(line)
		buf.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileNonces{seen: seen, f: f}, nil
}

// Consume implements NonceStore. The record is flushed to disk before it
// returns nil.
func (s *FileNonces) Consume(nonce string, expires, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bad != nil {
		return s.bad
	}
	if err := consumeLocked(s.seen, nonce, expires, now); err != nil {
		return err
	}
	line, _ := json.Marshal(nonceRecord{N: nonce, E: expires.Unix()})
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		s.bad = fmt.Errorf("nonce file write failed: %w", err)
		return s.bad
	}
	if err := s.f.Sync(); err != nil {
		s.bad = fmt.Errorf("nonce file sync failed: %w", err)
		return s.bad
	}
	return nil
}

// Close closes the file and releases the process lock.
func (s *FileNonces) Close() error {
	err := s.f.Close()
	if lerr := s.lock.Close(); err == nil {
		err = lerr
	}
	return err
}
