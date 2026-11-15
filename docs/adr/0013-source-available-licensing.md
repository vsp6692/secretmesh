# 0013. Source-available licensing with commercial restrictions

Status: Proposed (draft; pending qualified legal review and owner approval)
Date: 2026-11-15

## Context

SecretMesh was published under the Apache License 2.0 as a personal project. The owner wants the code to stay publicly readable, contributable and free for any organisation to run for itself, while keeping the right to build a commercial business on it: resale, white-labelling, embedding, and SaaS or managed hosting for third parties. Apache-2.0 allows all of those for everyone. Copies already distributed stay Apache-2.0 for their recipients, and no lawyer has reviewed any alternative yet.

## Decision (proposed)

- Move **future** versions to a custom **source-available** licence ([LICENSE.md](../../LICENSE.md)): free for personal, educational, research and non-commercial use and for internal use by any organisation (including production, with no limits), and restricted for commercial redistribution, resale, white-labelling, embedding, commercial derivatives and third-party hosting, which need a separate [commercial licence](../../COMMERCIAL_LICENSE.md).
- Use a **licence-back CLA** ([CLA.md](../../CLA.md)) so the owner can include contributions and grant commercial licences, together with DCO sign-off.
- Keep the Apache-2.0 text in `LICENSES/` for earlier versions and Apache-licensed third-party code. Do not try to relicense copies that were already distributed.
- Protect the name and logo separately ([TRADEMARK_POLICY.md](../../TRADEMARK_POLICY.md)).
- Enforce the dependency licence policy, SPDX headers, notice drift and SBOM generation in CI and git hooks, and add **no** licence keys, activation, telemetry or feature limits for permitted uses.
- A release gate fails any `v*` tag while the documents are drafts or contain placeholders.
- The analysis, the BUSL 1.1 and FSL comparison, the legal risks and the owner's decisions are in [docs/legal/LICENSING_STRATEGY.md](../legal/LICENSING_STRATEGY.md).

## Consequences

- Nothing changes for anyone until the owner adopts the draft; this ADR stays **Proposed** until then. The change lives on the draft branch `licensing/source-available-draft`.
- Protection covers only new code. The Apache-2.0 version that exists today can be forked and hosted by anyone indefinitely.
- The licence is not OSI-approved and cannot prevent copying or independently developed competing products. Enforcement across jurisdictions is uncertain and costs money.
- A bespoke licence adds adoption friction and needs legal drafting; BUSL 1.1 and FSL are cheaper but convert to open source after a fixed time.
- Third-party obligations stay with their owners: an LGPL-3.0 component and MPL-2.0 components are present and must be handled as described in [THIRD_PARTY_LICENSES.md](../legal/THIRD_PARTY_LICENSES.md).
- Open questions that block adoption: who the Licensor is, AI-assisted authorship, the CLA form, the service-provider boundary, governing law and trademark clearance.
