// Package logrot is a size-rotated log file for the Chaperone daemons (ticket
// L1-17). A Windows service has no stderr to redirect, so chapd and chap-host
// write their slog output here instead: <dir>/<name>.log, and at 10 MiB the
// file becomes <name>.1.log, the older ones shift up, and the file past the
// keep limit is deleted. Disk use is therefore bounded by (Keep+1) x MaxBytes.
//
// A logger must never stop its program: when a rotation step fails, Write
// keeps appending to the current file and reports nothing it cannot recover.
package logrot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Defaults for [Open].
const (
	DefaultMaxBytes = 10 << 20
	DefaultKeep     = 9
)

// Options tune a Writer. The zero value means the defaults.
type Options struct {
	// MaxBytes is the size at which the current file is rotated.
	MaxBytes int64
	// Keep is how many rotated files stay (name.1.log ... name.<Keep>.log).
	Keep int
}

// Writer is an io.Writer over a rotating log file. It is safe for concurrent use.
type Writer struct {
	mu   sync.Mutex
	dir  string
	name string
	opt  Options
	f    *os.File
	size int64
}

// Open creates dir (private to the owner) if needed and opens <dir>/<name>.log
// for appending.
func Open(dir, name string, opt Options) (*Writer, error) {
	if dir == "" || name == "" || filepath.Base(name) != name {
		return nil, errors.New("logrot: a directory and a plain file name are required")
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.Keep <= 0 {
		opt.Keep = DefaultKeep
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logrot: %w", err)
	}
	w := &Writer{dir: dir, name: name, opt: opt}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) path(n int) string {
	if n == 0 {
		return filepath.Join(w.dir, w.name+".log")
	}
	return filepath.Join(w.dir, fmt.Sprintf("%s.%d.log", w.name, n))
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path(0), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("logrot: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("logrot: %w", err)
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when p would push the file past MaxBytes.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(p)) > w.opt.MaxBytes {
		w.rotate()
		if w.f == nil {
			return 0, os.ErrClosed
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts the files up by one. The current file is closed first (Windows
// will not rename an open file) and always reopened: if any step fails the
// writer carries on appending to whichever file it ends up with.
func (w *Writer) rotate() {
	w.f.Close()
	w.f = nil
	os.Remove(w.path(w.opt.Keep))
	for n := w.opt.Keep - 1; n >= 0; n-- {
		if err := os.Rename(w.path(n), w.path(n+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			break // leave the rest where they are; the log still works
		}
	}
	if err := w.open(); err != nil {
		// Cannot happen without the directory vanishing; retry once in place.
		os.MkdirAll(w.dir, 0o700)
		w.open()
	}
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
