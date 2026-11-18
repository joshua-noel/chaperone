package version

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestStringShape(t *testing.T) {
	i := Info{Binary: "chap", Version: "v1.2.3", Commit: "0123456789abcdef", GoOS: "linux", GoArch: "amd64", Go: "go1.26.10"}
	want := "chap v1.2.3 (commit 0123456789ab) linux/amd64 go1.26.10"
	if got := i.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestStringUnknownCommit(t *testing.T) {
	i := Info{Binary: "chap", Version: "dev", GoOS: "windows", GoArch: "amd64", Go: "go1.26.10"}
	if got := i.String(); !strings.Contains(got, "(commit unknown)") {
		t.Fatalf("String() = %q, want an unknown commit marker", got)
	}
}

func TestFprintReportsRuntime(t *testing.T) {
	var b bytes.Buffer
	if err := Fprint(&b, "chapd"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"chapd ", runtime.GOOS + "/" + runtime.GOARCH, runtime.Version()} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Errorf("output %q is not exactly one line", out)
	}
}
