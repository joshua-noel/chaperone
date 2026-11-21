//go:build windows

package privfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func icacls(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func whoami(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("whoami").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}

// A new file in a folder that hands its access to everybody gets none of it: it holds one entry, full control for
// the current user, nothing inherited. A file made the ordinary way in the same folder shows the leak the test is
// looking for, so the test cannot pass by accident.
func TestCreateIsOwnerOnlyByIcacls(t *testing.T) {
	dir := t.TempDir()
	// Everyone can read what is made in this folder (object and container inherit).
	icacls(t, dir, "/grant", "*S-1-1-0:(OI)(CI)R")

	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := icacls(t, plain); !strings.Contains(out, "Everyone:(I)(R)") && !strings.Contains(out, "Everyone:(I)") {
		t.Fatalf("control: an ordinary file in this folder does not inherit Everyone, so the test proves nothing:\n%s", out)
	}

	path := filepath.Join(dir, "key")
	f, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("secret"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := icacls(t, path)
	if n := strings.Count(out, ":("); n != 1 {
		t.Errorf("%d access entries, want 1 (the current user):\n%s", n, out)
	}
	if strings.Contains(out, "(I)") {
		t.Errorf("the file inherits access from its folder:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), whoami(t)+":(f)") {
		t.Errorf("the one entry is not full control for %s:\n%s", whoami(t), out)
	}
	if strings.Contains(out, "Everyone") {
		t.Errorf("Everyone has access:\n%s", out)
	}
	// The user can still replace it (the rename over the key file in `chap key claim` and `chap agent enrol`).
	next := filepath.Join(dir, "key.new")
	g, err := Create(next)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	if err := os.Rename(next, path); err != nil {
		t.Errorf("the owner cannot rename a new file over the key file: %v", err)
	}
}
