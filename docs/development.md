# Developing Chaperone

How to build, test and change this repository. For what Chaperone is, read the [README](../README.md). To run `chapd`, read [running-chapd.md](running-chapd.md).

## Layout

```
cmd/{chapd,chap,chap-host}/   entry points (each builds with CGO_ENABLED=0)
internal/store/               SQLite: WAL, synchronous=FULL, foreign keys, migrations, BEGIN IMMEDIATE
internal/ledger/              the hash-chained ledger and its anchors
internal/vault/               encrypted secrets
internal/runtoken/            run tokens and the orchestrator token
internal/approvals/           the approvals engine and the approval cards
internal/console/             the web console; web/ holds its templates and static files
internal/gh/, internal/gitproxy/   the GitHub App client and chapd's git proxy
internal/ops/, internal/policy/    the operations and the policy that gates them
internal/connectors/          third-party connectors (Google, Linear, Sentry)
internal/mcpfront/            the local MCP server behind `chap mcp`
internal/spec/                the contract shared with the runner: schemas and golden vectors (specdata/), strict JSON, JCS, hashes, validation
internal/version/             build identity printed by `<binary> version`
api/                          chapd's HTTP contract: openapi.yaml, manual.yaml (the `chap manual` data), examples/
policy/                       per-project policy files
docs/adr/                     architecture decision records
docs/runbooks/                procedures for the operator
docs/dependencies.allow       every third-party module allowed in go.mod
scripts/allowcheck/           fails when go.mod has a module that is not on that list
scripts/spec-manifest/        writes and checks internal/spec/specdata/MANIFEST (`-check`)
scripts/build.sh              the build CI uses
scripts/windows/              install, uninstall and run-agent scripts
scripts/demo/                 demos that run against a fake GitHub
vendor/                       vendored modules (committed)
```

## Developing

### Toolchain (Windows, no admin, no installer)

Go is a portable unzip. You can put it in any folder. The examples use `D:\Chaperone\tools\`:

| What | Where |
| --- | --- |
| Go 1.26.10 (windows/amd64) | `D:\Chaperone\tools\go\` |
| `GOPATH` (module cache, installed tools) | `D:\Chaperone\tools\gopath\` |
| `govulncheck` v1.9.0 | `D:\Chaperone\tools\gopath\bin\govulncheck.exe` |
| build cache | `D:\Chaperone\tools\gocache\` |

Put it on the PATH for the current PowerShell session (nothing system-wide is changed):

```powershell
$env:GOROOT      = 'D:\Chaperone\tools\go'
$env:GOPATH      = 'D:\Chaperone\tools\gopath'
$env:GOCACHE     = 'D:\Chaperone\tools\gocache'
$env:GOTOOLCHAIN = 'local'   # never let go download a different toolchain
$env:Path        = "$env:GOROOT\bin;$env:GOPATH\bin;$env:Path"
go version                    # go version go1.26.10 windows/amd64
```

Git Bash:

```bash
export GOROOT=/d/Chaperone/tools/go GOPATH=/d/Chaperone/tools/gopath
export GOCACHE=/d/Chaperone/tools/gocache GOTOOLCHAIN=local
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
```

To set it up on another machine: download `go1.26.10.windows-amd64.zip` from <https://go.dev/dl/>, check it against the SHA-256 on that page (`Get-FileHash -Algorithm SHA256 .\go1.26.10.windows-amd64.zip` must print `7ecd2d7260e82c59bcbd7f1077a07cee2dea607295b858df67195a1e4e09629b`), `Expand-Archive` it so that `go\bin\go.exe` exists, then `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0`. When `go.mod`'s `go` line moves, bump the zip the same way.

### The checks CI runs

Run these from the repository root before you propose a change. The pull request template asks for their output. `go.mod` says `go 1.26.10` and `vendor/` exists, so every command builds from `vendor/` with no download.

```powershell
go mod verify
go mod vendor; git status --porcelain -- vendor go.mod go.sum   # must print nothing
go run ./scripts/allowcheck                                      # go.mod vs docs/dependencies.allow
gofmt -l cmd internal scripts                                    # must print nothing
go vet ./...
$env:GOOS='windows'; go vet ./...; $env:GOOS='linux'; go vet ./...; Remove-Item Env:GOOS
go test -count=1 ./...
govulncheck ./...
```

Build the binaries (static, `CGO_ENABLED=0`, both targets) with `scripts/build.sh` in Git Bash, or in PowerShell:

```powershell
$env:CGO_ENABLED='0'
foreach ($os in 'windows','linux') { $env:GOOS=$os; $env:GOARCH='amd64'; go build -trimpath -o "dist\$os\" ./cmd/... }
Remove-Item Env:GOOS, Env:GOARCH
.\dist\windows\chap.exe version
```

A `GOOS=linux` test binary cannot run on Windows; CI runs the Linux tests. Locally, `go test -c` for linux proves it compiles, and the static `chap` runs in any Linux.

### Adding a dependency

1. Stdlib first. A third-party module needs a reason.
2. Pick a version at least 7 days old.
3. `go get <module>@<version>`, `go mod tidy`, `go mod vendor`.
4. Add the module (and every new indirect module) to `docs/dependencies.allow` with a comment, and add an addendum to `docs/adr/001-language-runtime.md`.
5. `go run ./scripts/allowcheck` must pass; CI runs it and fails the PR otherwise.

### Migrations

`internal/store/migrations/NNNN_name.sql`, numbered from 0001. Take the next free number; never edit or renumber a file that has merged. `store.DB.Migrate` is forward-only and checks each applied migration's checksum, so an edited, reordered or missing migration is refused at start-up instead of corrupting the schema.

### The spec binding

`internal/spec/specdata/` holds the contract that Chaperone shares with the runner (a separate project that starts agent runs and signs their run tokens; it is not public yet). It has the schemas (the run token, the operation request, the denial and the ledger event), the stop table, the golden vectors (`vectors/v0.json`) and the schemas' examples. `VERSION` names the contract version.

The contract is edited in this repository. `MANIFEST` holds the SHA-256 of every file, so `go test ./internal/spec` finds an edit that was not planned. After you edit the contract, bring the derived hashes in the examples and vectors up to date (`op_hash`, `challenge_sha256`, ledger hash chains, profile digests; the tests in `internal/spec` say which ones are wrong). Then seal the files again:

```powershell
go run ./scripts/spec-manifest           # rewrite MANIFEST
go run ./scripts/spec-manifest -check    # fail if MANIFEST is out of date, write nothing
go test ./internal/spec                  # reproduce every golden vector, validate every example
```

`chap`, `chapd` and `chap-host` never read the spec from the network.

## CI

The workflows are [`ci.yml`](../.github/workflows/ci.yml), [`keyring.yml`](../.github/workflows/keyring.yml), [`release.yml`](../.github/workflows/release.yml) and [`scan.yml`](../.github/workflows/scan.yml). Every action is pinned to a commit SHA; reuse the SHAs already in the files, and do not add an action without a reason.

| Job | Runs | Steps |
| --- | --- | --- |
| `linux` (`ci.yml`, `ubuntu-latest`) | on every pull request to `main` and every push to `main`, unless the change is only files in the `paths-ignore` list of `ci.yml` (docs the tests do not read); by hand with `workflow_dispatch` | `go mod verify`, vendor-drift check, allowlist check, `gofmt`, `go vet` (linux, `GOOS=windows` and `GOOS=darwin`), `go test`, build all three binaries for both targets with `CGO_ENABLED=0`, `chap version` inside a clean `ubuntu:24.04` container |
| `windows` (`ci.yml`, `windows-latest`) | on every push to `main`, and by hand; not on a pull request; only after `linux` passed | `go vet`, `go test`, build, `chap.exe version` |
| `macos` (`ci.yml`, `macos-latest`, an Apple silicon runner: darwin/arm64) | the same as `windows` | `go vet`, `go test`, build the three programs natively, `chap version` |
| `macos keychain` (`keyring.yml`, `macos-latest`) | on a pull request or push to `main` that changes `internal/vault/**`, `go.mod`, `go.sum` or `keyring.yml`; Wednesdays 05:41 UTC; by hand | a throwaway keychain, then one step for the `keychain-macos` wrapper on the real `security` tool, one for the `age-passphrase` wrapper on a real terminal (`script`) |
| `linux secret service` (`keyring.yml`, `ubuntu-latest`) | the same as `macos keychain` | installs `libsecret-tools`, `gnome-keyring` and `dbus`; a self-check of a private D-Bus session with an unlocked GNOME Keyring; then one step for the `secret-service` wrapper on the real `secret-tool`, one for the `age-passphrase` wrapper on a real terminal |
| `release` (`release.yml`, `ubuntu-latest`) | on a pushed tag `v*`, and by hand from a tag | `verify` (`go vet`, `go test`, the tag is a version and on `main`), then the archives for five systems, checksums, and a **draft** GitHub release. See [releasing.md](releasing.md) |
| `govulncheck` (`scan.yml`, `ubuntu-latest`) | Mondays 05:23 UTC, by hand, and on a pull request that changes `go.mod` or `go.sum` | `govulncheck ./...` (v1.9.0) |

A change that touches `internal/vault/` or `cmd/chap-host/` still gets `go vet` for `GOOS=windows` and `GOOS=darwin` from the Linux job. To run the Windows and macOS jobs on a branch before it merges, run `gh workflow run ci -r <branch>`. To run the keyring jobs on a branch, run `gh workflow run keyring -r <branch>`.

A new push cancels the older run for the same branch (`concurrency`), for pull requests only. Job time limits stop a hung job.

### The real keychain and keyring tests

The unit tests of the vault use fake `security` and `secret-tool` programs. The tests in `internal/vault/*_integration_test.go` run the key wrappers on the real tools. They are **opt-in**, and they are skipped, with a message that names the variable, unless it is set to `1`:

| Variable | System | Test | What it uses |
| --- | --- | --- | --- |
| `CHAPERONE_TEST_REAL_KEYCHAIN` | macOS | `TestRealKeychainMacOS` | `/usr/bin/security` and the **default keychain** of the user (the wrapper cannot name another). CI makes a throwaway keychain the default first. |
| `CHAPERONE_TEST_REAL_SECRET_SERVICE` | Linux | `TestRealSecretServiceLinux` | `secret-tool` and the Secret Service on the current session bus. CI starts a private bus and an unlocked GNOME Keyring first. |
| `VAULT_TEST_REAL_TTY` | macOS, Linux | `TestTerminalPassphraseOnARealTerminal` | `/dev/tty`; run it inside a pseudo-terminal, see the comment on the test |

Each test deletes the items it made, and compares keys without printing them. Do not run the first two on a machine whose keychain or keyring you care about unless you accept a test item that stays behind if the run is killed (service `chaperone-vault`, label `chaperone-vault-key`). To run them the way CI does, compile once with `go test -c ./internal/vault`; the steps in `keyring.yml` show the rest. `TestRealKeyringScenariosOnFakeTools` runs the same scenarios on the fake tools in every ordinary test run.

### Release builds

`scripts/build.sh` is the CI build (two targets, amd64 only). The release archives are made by `release.yml`, which has its own loop with the same `-trimpath` and the same version and commit linker flags. Change the flags in both places. How to cut a release is in [releasing.md](releasing.md).

## Pull requests

Outside pull requests are not accepted for now; see [CONTRIBUTING.md](../CONTRIBUTING.md). For maintainers: one logical change per pull request, branch `type/short-kebab`, Conventional Commit title of at most 72 characters. The template asks for Testing, Risk and How to revert. The code owner is set in [`.github/CODEOWNERS`](../.github/CODEOWNERS).
