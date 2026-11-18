#!/bin/bash
# THROWAWAY STAND-IN for scripts/pilot-host/pilot.sh, used only to rehearse the
# `deploy` runbook end to end (adapters/wsl-host/rehearsal_test.go). It touches
# no file, no network, no WSL distro, no Docker and no pilot: it prints what the
# real runbook would do and exits.
#
#   pilot.sh deploy <40-hex sha>
#
# With REHEARSAL_FAIL=1 in its environment (the test sets it; no grant can) the
# runbook fails at the deploy step (exit 3), so the failure path can be
# rehearsed. Otherwise it succeeds.
set -eu

[ "${1:-}" = "deploy" ] || { echo "usage: pilot.sh deploy <sha>" >&2; exit 2; }
sha="${2:-}"
case "$sha" in
  *[!0-9a-f]* | "") echo "refusing: the argument is not a lower-case hex SHA" >&2; exit 2 ;;
esac
[ "${#sha}" -eq 40 ] || { echo "refusing: the SHA is not 40 characters" >&2; exit 2; }

echo "rehearsal: changelog assembly for $sha"
echo "rehearsal: migration rehearsal ok"
if [ "${REHEARSAL_FAIL:-}" = "1" ]; then
  echo "rehearsal: deploy step failed (REHEARSAL_FAIL=1)" >&2
  exit 3
fi
echo "rehearsal: deploy ok"
echo "rehearsal: record ok"
