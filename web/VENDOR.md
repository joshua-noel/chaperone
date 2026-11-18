# Vendored front-end files

Copied **unmodified** from `storefront/tools/shared/ui/` (which copied them from the npm tarballs; see its
`VENDOR.md`). Nothing is loaded from a CDN. `vendor_test.go` checks the SHA-256 sums in `web.go`
(`VendorSHA256`), so an edited or replaced file fails `go test ./web/`. `static/vendor/.gitattributes` turns off
line-ending conversion so the bytes in the repository are the bytes that were hashed.

| File               | Package        | Version | Licence                    |
| ------------------ | -------------- | ------- | -------------------------- |
| `basecoat.min.css` | `basecoat-css` | 1.0.2   | MIT, `LICENSE-basecoat.md` |
| `basecoat.min.js`  | `basecoat-css` | 1.0.2   | MIT, `LICENSE-basecoat.md` |
| `htmx.min.js`      | `htmx.org`     | 2.0.11  | 0BSD, `LICENSE-htmx.txt`   |

```text
8123677adb9bba43be3298e1543bcc5fc763e8cda3d32dc74c806046a3537ca0  basecoat.min.css
93fa012baa09fa49a06d411da3ced2176a121e45ae977955ecf82c5bd3eb6a50  basecoat.min.js
d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717  htmx.min.js
```

`popover.min.js` and `sidebar.min.js` from the same package are not vendored yet; L1-20 copies them when a screen
needs them (add the file, its hash to `VendorSHA256`, and a row here).

The pages set `htmx-config` `allowEval: false`, `allowScriptTags: false` and `includeIndicatorStyles: false`, so the
Content-Security-Policy (`script-src 'self'`, `style-src 'self'`) needs no `unsafe-eval` and no `unsafe-inline`.

## Refresh

Same procedure as `storefront/tools/shared/ui/VENDOR.md`: take the new files from the npm tarballs, update the
table and `VendorSHA256`, run the console tests.
