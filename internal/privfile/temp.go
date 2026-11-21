package privfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CreateTemp makes a NEW private file in dir whose name is pattern with its last "*" (or, with none, its end) replaced
// by random characters, as os.CreateTemp does, and opens it for writing. It is [Create] on a name nobody can have
// planted a link at.
func CreateTemp(dir, pattern string) (*os.File, error) {
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		f, err := Create(filepath.Join(dir, prefix+hex.EncodeToString(b[:])+suffix))
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: os.ErrExist}
}
