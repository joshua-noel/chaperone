//go:build windows

package vault

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A real named pipe called like mintty's pty pipe: standard input in that
// setup. It is a terminal; an ordinary pipe and a file are not.
func TestWindowsPtyPipeIsATerminal(t *testing.T) {
	const name = `\\.\pipe\msys-0123456789abcdef-pty0-to-master`
	p16, _ := windows.UTF16PtrFromString(name)
	srv, err := windows.CreateNamedPipe(p16, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 512, 512, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(srv)
	client, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if got := handleFileName(windows.Handle(client.Fd())); !strings.HasPrefix(got, `\msys-`) {
		t.Fatalf("file name of the pipe is %q", got)
	}
	if !isTerminal(client) {
		t.Error("an msys pty pipe was not taken for a terminal")
	}

	old := os.Stdin
	os.Stdin = client
	t.Cleanup(func() { os.Stdin = old })
	if _, err := FDPassphrase(0); err == nil || !strings.Contains(err.Error(), "is a terminal") {
		t.Errorf("an msys pty pipe as descriptor 0: %v", err)
	}
}

func TestWindowsOrdinaryPipeIsNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(r) {
		t.Errorf("an ordinary pipe (%q) is a terminal", handleFileName(windows.Handle(r.Fd())))
	}
}
