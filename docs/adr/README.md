# Architecture Decision Records

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-modular-monolith.md) | Go modular monolith with isolated workers | Accepted |
| [0002](0002-postgres-rls.md) | PostgreSQL with Row-Level Security and split roles | Accepted |
| [0003](0003-stage-pending-values-in-cloud-vault.md) | Stage pending secret values in the cloud vault | Accepted |
| [0004](0004-approval-binding.md) | Approval binding and tamper check | Accepted |
| [0005](0005-postgres-job-queue.md) | Postgres-backed job queue instead of Temporal (MVP) | Accepted |
| [0006](0006-embedded-opa.md) | Embedded OPA for execution policy | Accepted |
| [0007](0007-execution-journal.md) | Execution journal and reconciler | Accepted |
| [0008](0008-tenant-context-and-principals.md) | Tenant context, principals and API tokens | Accepted |
| [0009](0009-governance-gate-chain.md) | Governance gate chain: role bindings, approvals, worker enforcement and audit ledger | Accepted |
| [0010](0010-aws-vertical-slice.md) | AWS vertical slice: connector, staging, KMS keyring, audit export and break-glass | Accepted |
| [0011](0011-rotation-and-notifications.md) | Rotation engine and notifications | Accepted |
| [0012](0012-azure-and-gcp-connectors.md) | Azure Key Vault and Google Cloud Secret Manager connectors | Accepted |
| [0013](0013-source-available-licensing.md) | Source-available licensing with commercial restrictions | Proposed (draft) |

New ADRs: copy the structure below, number sequentially, and never rewrite an accepted ADR. Supersede it with a new one.

```
# NNNN. Title
Status: Proposed | Accepted | Superseded by NNNN
Date: YYYY-MM-DD

## Context
## Decision
## Consequences
```
