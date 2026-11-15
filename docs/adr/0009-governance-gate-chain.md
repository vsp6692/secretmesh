# 0009. Governance gate chain: role bindings, approvals, worker enforcement and audit ledger

Status: Accepted
Date: 2026-11-12

## Context

M2 implements the blueprint's four enforcement gates (identity, authorization, approval, execution policy), the approval binding of ADR-0004, the execution journal of ADR-0007 and a tamper-evident audit trail. Several choices the earlier ADRs left open are recorded here.

## Decision

**Authorization (gate 2).**
- Organization roles (`org_admin`, `member`) govern the organization itself.
- Resource permissions come only from role bindings: `cloud_admin`, `security_admin`, `secret_admin`, `developer`, `approver` and `auditor`. Each binding applies organization-wide or to one environment. Environment scoping is the ABAC attribute in M2; teams and classification conditions come later.
- Organization admins have no implicit resource permissions (separation of duties). They must bind themselves, which is audited.
- API tokens can carry `secrets:read`, `secrets:write` and `audit:read`, but are always bounded by the creator's current bindings. Tokens can never approve, manage policy or manage connections.

**Approvals (gate 3).**
- Each organization has an approval policy: rules keyed by environment kind, operation and classification. The requirement is the maximum over matching rules.
- Default policy:
  - production changes need 1 approval;
  - production deletes need 2;
  - restricted secrets need 1 in any environment.
- Submitting a change stages the value in the provider. The request stores only `value_mac = HMAC-SHA256(K_tenant, value)` plus a `binding_hash`: SHA-256 over canonical JSON of the tenant, request, operation, target, staging reference and version, the MAC, a nonce and the expiry.
- Approvers must hold `approval.decide` in the environment, must not be the requester, must have authenticated within 5 minutes, and must submit the binding hash they reviewed.
- One open request per secret.
- Requests expire after 72 hours by default.

**Execution (gate 4).**
- Workers run on River (ADR-0005), embedded in the API process by default or as `secretmesh-api worker`. Job arguments carry only IDs.
- Before every provider call, the worker rebuilds the OPA input from the database:
  - the requester is still a member, still holds the binding and (for tokens) the token is still valid;
  - only approvals of the exact binding hash count, from approvers who still hold the role;
  - the binding is recomputed;
  - expiry, environment kind, the current approval policy and the organization's MFA requirement are re-read.
- It then evaluates `policies/execution.rego` with embedded OPA. The built-in policy also requires that production approvals were made with MFA.
- A journal intent is committed before the call, and its ID is the provider idempotency key.
- The staged value is re-MACed and compared before promotion.
- Results, metadata and the audit event commit in one transaction.
- A reconciler resumes stale intents by asking the provider what happened.

**Keys.**
- M2 derives keys from `SECRETMESH_MASTER_KEY` with HKDF:
  - per-tenant MAC keys;
  - an Ed25519 checkpoint-signing key.
- They sit behind a `keys.Keyring` interface so that a KMS-backed keyring (AWS KMS `GenerateMac`/`Sign`) can replace it from M3 without schema changes.

**Audit ledger.**
- One hash chain per organization: `hash = SHA-256(prev_hash ‖ canonical event)`. A head row serializes appends.
- Events are written in the same transaction as the change they record.
- The runtime role has no UPDATE/DELETE policy on the ledger, and triggers reject UPDATE, DELETE and TRUNCATE for everyone except the schema owner, who must disable them explicitly.
- A periodic job signs the chain head as a checkpoint.
- Verification recomputes the chain and checks every checkpoint signature.
- Event details are flat strings, and keys that look sensitive are refused.

## Consequences

- Any gate can be bypassed only by changing code or the database owner's data, and the worker re-checks gates 1–4 even for requests the API approved.
- The local keyring keeps key material in process memory, which is weaker than a KMS. Losing `SECRETMESH_MASTER_KEY` invalidates pending approvals and checkpoint verification.
- Until checkpoints are exported off-database (S3 Object Lock, deferred to M3 with the AWS SDK), a database owner who rewrites history *and* deletes checkpoints is undetectable.
- The dev Keycloak has no MFA, so production changes in the dev stack are denied by policy (`production_requires_mfa`). This is the intended secure default; operators can supply their own policy with `SECRETMESH_EXECUTION_POLICY_FILE`.
- The fake connector keeps state in memory and therefore needs the embedded worker.
