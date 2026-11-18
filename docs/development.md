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
internal/connectors/          third-party connectors (Google, Linear)
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

The workflows are [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and [`.github/workflows/scan.yml`](../.github/workflows/scan.yml).

| Job | Runs | Steps |
| --- | --- | --- |
| `linux` (`ubuntu-latest`) | on every pull request to `main` and every push to `main`, unless the change is only files in the `paths-ignore` list of `ci.yml` (docs the tests do not read); by hand with `workflow_dispatch` | `go mod verify`, vendor-drift check, allowlist check, `gofmt`, `go vet` (linux and `GOOS=windows`), `go test`, build all three binaries for both targets with `CGO_ENABLED=0`, `chap version` inside a clean `ubuntu:24.04` container |
| `windows` (`windows-latest`) | on every push to `main`, and by hand; not on a pull request; only after `linux` passed | `go vet`, `go test`, build, `chap.exe version` |
| `govulncheck` (`scan.yml`, `ubuntu-latest`) | Mondays 05:23 UTC, by hand, and on a pull request that changes `go.mod` or `go.sum` | `govulncheck ./...` (v1.9.0) |

A change that touches `internal/vault/` or `cmd/chap-host/` still gets `GOOS=windows go vet` from the Linux job. To run the Windows tests on a branch before it merges, run `gh workflow run ci -r <branch>`.

A new push cancels the older run for the same branch (`concurrency`). Job time limits (10 and 15 minutes) stop a hung job.

## Pull requests

Outside pull requests are not accepted for now; see [CONTRIBUTING.md](../CONTRIBUTING.md). For maintainers: one logical change per pull request, branch `type/short-kebab`, Conventional Commit title of at most 72 characters. The template asks for Testing, Risk and How to revert. The code owner is set in [`.github/CODEOWNERS`](../.github/CODEOWNERS).
