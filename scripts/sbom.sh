#!/bin/sh
# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT
# Writes CycloneDX software bills of materials for the API binary (Go modules)
# and the web console (production npm packages) to build/sbom/.
# Tool versions are pinned; nothing is uploaded anywhere.
set -eu
cd "$(dirname "$0")/.."
out=build/sbom
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Installed with the host's settings, then run for the platform the images use.
GOBIN="$tmp" go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$tmp/cyclonedx-gomod" app -json -licenses -main apps/api -output "$out/secretmesh-api.cdx.json"
(cd apps/web && npx --yes @cyclonedx/cyclonedx-npm@7.0.1 --omit dev --output-format JSON --output-file "../../$out/secretmesh-web.cdx.json")
echo "SBOMs written to $out/"
