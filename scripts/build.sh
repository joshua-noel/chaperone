#!/usr/bin/env bash
# Build chapd, chap and chap-host as static binaries (CGO_ENABLED=0) for
# windows/amd64 and linux/amd64 into dist/<os>/. Used by CI and by developers.
#
#   scripts/build.sh              # both targets
#   scripts/build.sh linux        # one target
#
# GO=/path/to/go overrides the go binary (default: go on PATH).
set -euo pipefail

cd "$(dirname "$0")/.."
export CGO_ENABLED=0
go_bin=${GO:-go}

pkg=github.com/joshua-noel/chaperone/internal/version
version=${CHAP_VERSION:-dev}
commit=${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}
ldflags="-s -w -X ${pkg}.Version=${version} -X ${pkg}.Commit=${commit}"

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(linux windows)

rm -rf dist
for os in "${targets[@]}"; do
  ext=""
  [ "$os" = windows ] && ext=".exe"
  for bin in chapd chap chap-host; do
    GOOS=$os GOARCH=amd64 "$go_bin" build -trimpath -ldflags "$ldflags" -o "dist/$os/$bin$ext" "./cmd/$bin"
  done
done
ls -l dist/*
