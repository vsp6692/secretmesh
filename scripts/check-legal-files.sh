#!/bin/sh
# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT
# Checks the licensing documentation is complete and consistent.
#
#   scripts/check-legal-files.sh            structure checks (CI, pre-commit)
#   scripts/check-legal-files.sh --release  also refuse a draft licence: used by the release gate,
#                                           which must fail until the owner has adopted the licence
set -eu
cd "$(dirname "$0")/.."
failed=0
fail() { echo "legal: $*" >&2; failed=1; }

required="LICENSE.md COMMERCIAL_LICENSE.md LICENSE_FAQ.md CONTRIBUTING.md CLA.md TRADEMARK_POLICY.md README.md SECURITY.md
docs/legal/LICENSING_STRATEGY.md docs/legal/THIRD_PARTY_LICENSES.md docs/legal/license-policy.json LICENSES/Apache-2.0.txt"
for f in $required; do [ -f "$f" ] || fail "missing $f"; done

standard='SecretMesh is source-available software, free for personal and internal organizational use, including production deployments. Commercial redistribution, resale, white-labeling, and third-party SaaS or managed hosting require a separate commercial license.'
for f in README.md LICENSE_FAQ.md; do
  grep -qF "$standard" "$f" 2>/dev/null || fail "$f must contain the standard description verbatim"
done

# The licence ID in LICENSE.md, the headers tool and the docs must agree.
id=$(sed -n 's/^SPDX identifier: `\(.*\)`$/\1/p' LICENSE.md)
[ -n "$id" ] || fail "LICENSE.md must state its SPDX identifier"
grep -q "spdxID = \"$id\"" scripts/licenses/headers.go || fail "scripts/licenses/headers.go spdxID does not match LICENSE.md ($id)"

# No licence key, activation or telemetry code for permitted internal use.
if git ls-files '*.go' '*.ts' '*.tsx' | xargs grep -nEi 'licen[cs]e[_-]?key|activation[_-]?(key|code)|phone[_-]?home' 2>/dev/null | grep -v 'scripts/check-legal-files.sh'; then
  fail "licence-key, activation or phone-home code is not allowed for permitted uses (docs/legal/LICENSING_STRATEGY.md)"
fi

if [ "${1:-}" = "--release" ]; then
  docs="LICENSE.md COMMERCIAL_LICENSE.md LICENSE_FAQ.md CLA.md TRADEMARK_POLICY.md CONTRIBUTING.md SECURITY.md README.md docs/legal/LICENSING_STRATEGY.md docs/legal/THIRD_PARTY_LICENSES.md"
  # shellcheck disable=SC2086
  if grep -nE 'DRAFT|pending (qualified )?legal review' $docs; then fail "the licence documents are still marked as drafts: adopt them first (docs/legal/LICENSING_STRATEGY.md, adoption checklist)"; fi
  # shellcheck disable=SC2086
  if grep -nE '\[[A-Z][A-Z0-9_ ]{3,}[]:]' $docs; then fail "unresolved placeholders remain in the licence documents"; fi
  case "$id" in *DRAFT*) fail "SPDX identifier $id is a draft identifier";; esac
fi

[ "$failed" = 0 ] && echo "ok: licensing documents are complete and consistent"
exit "$failed"
