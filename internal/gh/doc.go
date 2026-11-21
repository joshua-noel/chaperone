// Package gh is Chaperone's GitHub App client (ticket L1-05, ADR-002).
//
// It does five things and nothing else:
//
//   - signs the short App JWT (RS256, 10 minutes) with a key that comes from a
//     [KeySource], so the vault (L1-03) plugs in without this package knowing it;
//   - mints installation tokens narrowed by repositories and permissions, and
//     revokes them ([Client.MintToken], [Client.RevokeToken]);
//   - makes the typed REST calls ADR-002 needs: pulls, pull files, check-runs,
//     compare, merge with `sha`, update-branch, create PR, deployments;
//   - returns every GitHub refusal to the caller as an [*APIError];
//   - sets the App up: the manifest Chaperone asks GitHub to turn into an App, the exchange of the temporary
//     code for the App's key, and the two calls that show the new App works (manifest.go; `chapd connect github`).
//
// # Rules the code keeps
//
// Tokens are opaque. [Token] never prints its value (String, GoString, JSON and
// text marshalling all redact it), never checks its length or prefix (the old
// 40-character form and the 2026 stateless `ghs_<app>_<jwt>` form both work),
// and can be wiped from memory. Code outside this package gets the value only
// through [Token.Reveal], for example the git proxy that injects it.
//
// There is no retry anywhere in the client. A refused merge, a 409 on a moved
// head, a primary or secondary rate limit, a 5xx: each is one request and one
// returned error. Rate-limit errors carry RetryAfter and the reset time so the
// caller can decide; the client never sleeps and never loops.
//
// Every request goes over https (plain http only to a loopback address, for the
// fake server). The default HTTP client does not follow redirects, and no
// credential is ever placed in a URL.
//
// # Tests
//
// Package ghtest is a fake GitHub server with an in-memory commit graph, pull
// requests, check-runs and installation tokens. It covers every refusal in
// ADR-002 steps 2-8, including a merge refused when `verify` is not success on
// the exact head, when the head is behind the base, and when the head moved
// (409). L1-10 and L1-09 reuse it.
//
// # Live test (needs the operator's GitHub App, H1)
//
// live_test.go carries build tag `live` and also refuses to run unless the
// environment names the App. It proves, against the scratch repository only:
// a narrowed token cannot touch another repository; a token without
// `workflows` cannot write a workflow file; and DELETE /installation/token
// makes the token return 401.
//
// The exact command, PowerShell, from the repository root (after the toolchain
// setup in README "Developing"):
//
//	$env:CHAP_GH_LIVE_APP_ID = '<App ID or client ID of chaperone-app>'
//	$env:CHAP_GH_LIVE_VAULT  = '<path of state.db; the key was stored with chapd vault import --name github-app-key>'
//	$env:CHAP_GH_LIVE_REPO   = 'joshua-noel/chaperone-sandbox'
//	$env:CHAP_GH_LIVE_OTHER  = 'example-org/storefront'   # another repo the App is installed on
//	$env:CHAP_GH_LIVE_BRANCH = 'main'                            # default branch of the sandbox repo
//	$env:GOFLAGS = '-mod=vendor'; $env:CGO_ENABLED = '0'
//	go test -tags live -run TestLive -count=1 -v ./internal/gh/
//
// The test reads the App key from the vault (gh.VaultKey), as the account that
// imported it; the .pem never has to stay on disk (chapd vault import --delete).
// The test creates one throwaway branch in the sandbox repo
// and deletes it again. It writes to CHAP_GH_LIVE_OTHER nothing: it only expects
// a 404 there. If the revoke subtest fails, record that in ADR-002 and make
// run-end revocation rely on expiry plus cache wipe ([Token.Wipe]).
package gh
