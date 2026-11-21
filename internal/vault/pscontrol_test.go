package vault

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The process-list check of the real-keyring tests is only worth anything if
// its control process is visible. This runs that control on every system that
// has ps (so on a developer's Mac or Linux machine, not only in CI) and checks
// the failure report names what ps printed.
func TestPSControlProcessIsSeen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no ps on Windows; the real-keyring tests that use it do not run there")
	}
	if _, err := exec.LookPath("ps"); err != nil {
		t.Skip("no ps")
	}
	requirePSSeesArguments(t)
}

func TestDescribePSReportsWhatPSPrinted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no ps on Windows")
	}
	got := describePS("chaperone-ps-control-none")
	for _, want := range []string{"command: ps -axww -o command=", "bytes:", "lines:", "first lines:"} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q:\n%s", want, got)
		}
	}
}
