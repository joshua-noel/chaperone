// Package web holds the console's embedded front end: html/template files
// and static assets. Nothing is loaded from a CDN at run time (ADR-004: the
// console must work offline and a page may not pull script from elsewhere).
//
// The vendored files under static/vendor are pinned by SHA-256 in
// [VendorSHA256]; see VENDOR.md and vendor_test.go.
package web

import (
	"embed"
	"io/fs"
)

//go:embed templates static
var content embed.FS

// Templates returns the html/template source files (templates/*.html).
func Templates() fs.FS { return mustSub("templates") }

// Static returns the public assets served under /static/.
func Static() fs.FS { return mustSub("static") }

func mustSub(dir string) fs.FS {
	sub, err := fs.Sub(content, dir)
	if err != nil {
		panic("web: " + err.Error()) // dir is a constant that the embed directive guarantees
	}
	return sub
}

// VendorSHA256 maps each vendored file (path relative to Static) to the
// SHA-256 it must have. The files are copied unmodified from the npm
// tarballs listed in VENDOR.md; a changed or replaced file fails the test.
var VendorSHA256 = map[string]string{
	"vendor/basecoat.min.css": "8123677adb9bba43be3298e1543bcc5fc763e8cda3d32dc74c806046a3537ca0",
	"vendor/basecoat.min.js":  "93fa012baa09fa49a06d411da3ced2176a121e45ae977955ecf82c5bd3eb6a50",
	"vendor/htmx.min.js":      "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
}
