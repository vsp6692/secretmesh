# 0003. Stage pending secret values in the cloud vault

Status: Accepted
Date: 2026-11-11

## Context

Changes to sensitive secrets require approval. The new value must exist somewhere while approval is pending, but SecretMesh must never persist secret values. Asking the requester to resubmit the value after approval is fragile and leaks the value through more systems.

## Decision

When a change is submitted, the API writes the value directly into the customer's vault in a location live consumers do not read, then discards it from memory. Approval promotes it; rejection or expiry destroys it. Only references (staging resource ID, provider version ID) are stored.

| Provider | Update existing secret | Create new secret |
|----------|------------------------|-------------------|
| AWS | New version with custom staging label `SECRETMESH_PENDING` (not `AWSPENDING`, which rotation uses). Approve: move `AWSCURRENT`. Reject: remove label. | Shadow staging secret |
| Azure | Shadow staging secret `sm-staging-<request>`; approve copies into the target, then delete and purge staging | Same |
| GCP | Shadow staging secret `sm-staging-<request>`; approve adds a version to the target, then delete staging | Same |

Shadow secrets are used where a disabled new version would become "latest" and could break consumers. Staging secrets are readable only by SecretMesh's executor identity, tagged with request ID and expiry, and swept by a cleanup job.

## Consequences

- Nothing about the value is stored in SecretMesh; the vault remains the sole holder.
- Requires write access to the vault at submission time, before approval. That identity must be scoped to staging operations.
- Azure vaults with purge protection retain deleted staging secrets (soft-deleted, still inside the vault) for the retention period. This must be documented for operators.
- To verify in spikes: AWS first-version label behaviour; Azure/GCP "latest" semantics with disabled versions.
