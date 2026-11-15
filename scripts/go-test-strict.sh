#!/bin/sh
# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT
# Runs the whole Go suite with the race detector and fails if any test was
# skipped. Skips are how an integration test silently stops running when its
# database or emulator is not wired up, so they are not allowed here.
#
# COVER_MIN=70 additionally fails if total statement coverage of internal/ and
# pkg/ (counted across packages) is below that percentage.
set -u
log=$(mktemp)
trap 'rm -f "$log"' EXIT

cover=
if [ -n "${COVER_MIN:-}" ]; then
  profile=$(mktemp)
  cover="-coverpkg=./internal/...,./pkg/... -coverprofile=$profile"
fi
# shellcheck disable=SC2086
go test -race -count=1 -v $cover ./... >"$log" 2>&1
status=$?

passed=$(grep -c '^--- PASS' "$log")
if [ "$status" -ne 0 ]; then
  grep -E '^(--- FAIL|FAIL|panic:)|^\s+\S+_test\.go:[0-9]+:' "$log" | head -60
  echo "FAILED (see above)"
  exit 1
fi
skipped=$(grep -E '^\s*--- SKIP' "$log" || true)
if [ -n "$skipped" ]; then
  echo "Tests were skipped; the integration environment is incomplete:"
  echo "$skipped"
  exit 1
fi
echo "ok: $passed tests passed, 0 skipped"

if [ -n "${COVER_MIN:-}" ]; then
  total=$(go tool cover -func="$profile" | awk '/^total:/ {sub("%","",$3); print $3}')
  rm -f "$profile"
  echo "coverage: ${total}% (minimum ${COVER_MIN}%)"
  if ! awk -v t="$total" -v m="$COVER_MIN" 'BEGIN { exit !(t+0 >= m+0) }'; then
    echo "Coverage fell below the minimum. Add tests for the code you changed."
    exit 1
  fi
fi
