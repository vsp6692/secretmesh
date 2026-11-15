#!/bin/sh
# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT
# Checks that the author of a pull request has accepted CLA.md, recorded in
# .github/cla-signatories.txt. Environment: PR_AUTHOR (GitHub login),
# CLA_ENFORCE ("true" fails the check; anything else only reports). CLA.md is
# a draft, so CI starts with CLA_ENFORCE=false.
set -eu
cd "$(dirname "$0")/.."
author=${PR_AUTHOR:?PR_AUTHOR is required}
case "$author" in *'[bot]') echo "ok: $author is a bot account"; exit 0;; esac
if grep -qixF "$author" .github/cla-signatories.txt 2>/dev/null; then
  echo "ok: $author has accepted the CLA"; exit 0
fi
msg="$author has not accepted CLA.md. Read it, state your agreement in the pull request, and a maintainer will record it in .github/cla-signatories.txt."
if [ "${CLA_ENFORCE:-false}" = "true" ]; then
  echo "::error::$msg"; exit 1
fi
echo "::warning::$msg (reporting only: CLA enforcement is off until CLA.md is approved)"
