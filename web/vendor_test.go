package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"
)

// TestVendorPinned fails when a vendored file is edited or replaced, and
// when an unpinned file sneaks into static/vendor.
func TestVendorPinned(t *testing.T) {
	static := Static()
	for name, want := range VendorSHA256 {
		b, err := fs.ReadFile(static, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: sha256 %s, pinned %s", name, got, want)
		}
	}
	err := fs.WalkDir(static, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), "LICENSE-") {
			return err
		}
		if _, ok := VendorSHA256[p]; !ok {
			t.Errorf("%s is vendored but not pinned in VendorSHA256", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
