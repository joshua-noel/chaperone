package vault

import "testing"

func TestIsPtyPipeName(t *testing.T) {
	for name, want := range map[string]bool{
		`\msys-dd50a72ab4668b33-pty0-to-master`:       true,
		`\msys-dd50a72ab4668b33-pty12-from-master`:    true,
		`\cygwin-e022582115c10879-pty0-from-master`:   true,
		`\CYGWIN-E022582115C10879-PTY0-FROM-MASTER`:   true,
		`\msys-dd50a72ab4668b33-1234-nat`:             false,
		`\Device\NamedPipe\something`:                 false,
		`\LOCAL\pty-from-master`:                      false,
		`\other-msys-dd50a72ab4668b33-pty0-to-master`: false,
		``: false,
	} {
		if got := isPtyPipeName(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}
