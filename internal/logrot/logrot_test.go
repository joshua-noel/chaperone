package logrot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRotatesAtMaxBytesAndKeepsOnlyKeep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	w, err := Open(dir, "chapd", Options{MaxBytes: 10, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, line := range []string{"aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	// Four 9-byte lines, 10-byte limit: each write after the first rotates.
	if got := read(t, filepath.Join(dir, "chapd.log")); got != "dddddddd\n" {
		t.Errorf("chapd.log = %q", got)
	}
	if got := read(t, filepath.Join(dir, "chapd.1.log")); got != "cccccccc\n" {
		t.Errorf("chapd.1.log = %q", got)
	}
	if got := read(t, filepath.Join(dir, "chapd.2.log")); got != "bbbbbbbb\n" {
		t.Errorf("chapd.2.log = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "chapd.3.log")); !os.IsNotExist(err) {
		t.Errorf("chapd.3.log must not exist (keep=2): %v", err)
	}
}

func TestReopenAppendsAndCountsExistingSize(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, "x", Options{MaxBytes: 20, Keep: 1})
	w.Write([]byte("0123456789\n"))
	w.Close()
	w, err := Open(dir, "x", Options{MaxBytes: 20, Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.Write([]byte("abcdefghi\n")) // 11+10 > 20: rotates first
	if got := read(t, filepath.Join(dir, "x.1.log")); got != "0123456789\n" {
		t.Errorf("x.1.log = %q", got)
	}
	if got := read(t, filepath.Join(dir, "x.log")); got != "abcdefghi\n" {
		t.Errorf("x.log = %q", got)
	}
}

func TestOneLargeWriteIsNeverSplitOrDropped(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, "x", Options{MaxBytes: 5, Keep: 1})
	defer w.Close()
	big := strings.Repeat("z", 50)
	if n, err := w.Write([]byte(big)); err != nil || n != 50 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := read(t, filepath.Join(dir, "x.log")); got != big {
		t.Errorf("x.log = %q", got)
	}
}

func TestOpenRejectsBadNamesAndWriteAfterClose(t *testing.T) {
	for _, c := range [][2]string{{"", "a"}, {t.TempDir(), ""}, {t.TempDir(), "../a"}} {
		if _, err := Open(c[0], c[1], Options{}); err == nil {
			t.Errorf("Open(%q, %q) succeeded", c[0], c[1])
		}
	}
	w, _ := Open(t.TempDir(), "x", Options{})
	w.Close()
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write after Close succeeded")
	}
}
