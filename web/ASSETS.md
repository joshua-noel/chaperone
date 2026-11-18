# Assets in the console

Images and marks the console ships, with where each came from. Vendored code is in `VENDOR.md`; this file covers
art. Everything is served from `static/`, nothing is hot-linked (the Content-Security-Policy allows `img-src 'self' data:`).

## Artwork

| File                    | Used on                                 | Size   |
| ----------------------- | --------------------------------------- | ------ |
| `static/art/doorway.jpg` | Sign in, enrol and the error page      | 79 KB  |

**Elevation of Rustic Doric Doorway**

- Artist and date: after Robert Morris (British, ca. 1701-1754), early to mid-18th century
- Medium: pen and black ink, brush and gray wash, touches of graphite
- Object number: 66.567.8 (object ID 363884)
- Credit line: The Elisha Whittelsey Collection, The Elisha Whittelsey Fund, 1966
- Object page: <https://www.metmuseum.org/art/collection/search/363884>
- Image file: the museum's `web-large` rendition (<https://images.metmuseum.org/CRDImages/dp/web-large/DP806027.jpg>),
  444 x 625 px, copied unchanged. The museum's object record has `isPublicDomain: true`.
- Rights: **CC0, The Met Open Access.** The Metropolitan Museum of Art's Open Access policy releases images of public
  domain works under Creative Commons Zero, for any use, without permission.
  <https://www.metmuseum.org/policies/open-access>
- How it is used: as an asset, directly. It sits beside the sign-in and enrol forms as a quiet picture of a threshold
  (an opening in a wall). It has empty `alt` text because it carries no information; the caption under it names the work
  and the collection. In dark mode the page dims it with a CSS `filter`; the file is not edited.

Why this one: the console is "the threshold between agents and the world" (the `chap` banner's tagline). A drawn doorway
is that idea in one plain picture, and a pen-and-wash elevation is calm, precise and low in contrast, so it never competes
with the form.

## Marks

| File                  | What it is                                                                           |
| --------------------- | ------------------------------------------------------------------------------------ |
| header mark (inline SVG in `templates/layout.html`) | Two bracket marks with a short bar in the gap: the `[  ]` of the `chap` banner. Drawn for Chaperone. |
| `static/icon.svg`     | The same mark on a rounded square, as the browser tab icon. Drawn for Chaperone.        |

## Not used

`archives.design` and the Internet Archive items it links to were looked at as a source and dropped: the operator chose The
Met's Open Access collection, whose images are CC0. No item from either site is in this repository.
