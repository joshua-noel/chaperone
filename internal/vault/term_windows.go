//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

// consoleTerminal is the console: CONIN$ to read and CONOUT$ to write, not
// standard input and output, which may be pipes.
type consoleTerminal struct{ in, out *os.File }

func init() {
	openTerminal = func() (terminal, error) {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, errNoTerminal
		}
		out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if err != nil {
			in.Close()
			return nil, errNoTerminal
		}
		return consoleTerminal{in, out}, nil
	}
	isTerminal = func(f *os.File) bool {
		var mode uint32
		return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
	}
}

func (t consoleTerminal) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t consoleTerminal) Write(p []byte) (int, error) { return t.out.Write(p) }
func (t consoleTerminal) Close() error {
	t.out.Close()
	return t.in.Close()
}

func (t consoleTerminal) disableEcho() (func(), error) {
	h := windows.Handle(t.in.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}
