//go:build windows

package vault

import (
	"encoding/binary"
	"os"
	"unsafe"

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
		h := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			return true
		}
		// mintty, MSYS2 and Cygwin without the Windows pseudo-console give a
		// program a named pipe in place of a console. It is a terminal too.
		return isPtyPipeName(handleFileName(h))
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

// handleFileName returns the name Windows gives the object behind h (for a
// pipe, "\msys-...-pty0-to-master"), or "" if it cannot be read. It is the
// call go-isatty makes.
func handleFileName(h windows.Handle) string {
	// FILE_NAME_INFO: a uint32 length in bytes, then the UTF-16 name.
	buf := make([]byte, 4+2*windows.MAX_PATH)
	if err := windows.GetFileInformationByHandleEx(h, windows.FileNameInfo, &buf[0], uint32(len(buf))); err != nil {
		return ""
	}
	n := int(binary.LittleEndian.Uint32(buf)) / 2
	if n == 0 || 4+2*n > len(buf) {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[4])), n))
}
