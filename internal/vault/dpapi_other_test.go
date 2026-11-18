//go:build !windows

package vault

import (
	"errors"
	"testing"
)

func TestDPAPIUnsupportedOffWindows(t *testing.T) {
	w := NewDPAPI()
	if _, err := w.Wrap([]byte("x")); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Wrap: %v", err)
	}
	if _, err := w.Unwrap([]byte("x")); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Unwrap: %v", err)
	}
}
