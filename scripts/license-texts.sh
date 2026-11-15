#!/bin/sh
# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT
# Collects the licence and copyright files of every dependency that ships with
# SecretMesh into build/licenses (go/ for the API, npm/ for the web console).
# The container images copy this directory to /licenses.
set -eu
cd "$(dirname "$0")/.."
out=build/licenses
rm -rf "$out"
mkdir -p "$out/go" "$out/npm"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
GOBIN="$tmp" go install github.com/google/go-licenses/v2@v2.0.1
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$tmp/go-licenses" save ./apps/api --ignore github.com/secretmesh/secretmesh --save_path "$out/go" --force 2>/dev/null
(cd apps/web && npx --yes license-checker-rseidelsohn@4.4.2 --production --excludePrivatePackages --files "../../$out/npm" >/dev/null)
echo "licence texts written to $out/ ($(find "$out" -type f | wc -l | tr -d ' ') files)"
