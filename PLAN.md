# SecretMesh – Implementation Plan

Source: SecretMesh Architecture & Engineering Blueprint v1.0
Constraints: solo developer · self-hosted first, SaaS after v0.1 · no secret value ever persisted by the application

## Decisions

Full records: [docs/adr](docs/adr/README.md).

| # | Decision | Status |
|---|----------|--------|
| ADR-001 | Go modular monolith + isolated workers; Next.js frontend | Accepted (blueprint) |
| ADR-002 | PostgreSQL with Row-Level Security on every tenant table, even while self-hosted | Accepted |
| ADR-003 | Pending values are staged **in the cloud vault**, never in the app; approval promotes, rejection/expiry destroys | Accepted |
| ADR-004 | Approval bound to (tenant, target, operation, staging ref, provider version id, nonce, expiry) + HMAC-SHA256 (KMS-held key) of the value, re-verified before promotion | Accepted |
| ADR-005 | Postgres-backed job queue (River) for MVP behind a `workflows` interface; Temporal can replace it later | Accepted (default, solo + self-hosted) |
| ADR-006 | OPA embedded as a Go library (`rego` package); policies in `policies/` | Accepted |
| ADR-007 | Execution journal (intent row written before every cloud call) + reconciler | Accepted |
| ADR-009 | Environment-scoped role bindings, approval policy, worker re-checks all gates with OPA, per-tenant hash-chained audit with signed checkpoints, local keyring until KMS | Accepted |
| ADR-008 | Transaction-local tenant context, SECURITY DEFINER pre-tenant lookups, org-bound scoped API tokens, step-up via `max_age=0` | Accepted |

## ADR-003 detail – staged values in the cloud vault

Rule: between submission and approval, the value exists only in the customer's vault, in a location live consumers do not read. The API receives the value, writes it to staging, and drops it from memory. On approval, the worker promotes it. Nothing is persisted in Postgres, logs, traces or job payloads; jobs carry only references.

| Provider | Update existing secret | Create new secret |
|----------|------------------------|-------------------|
| AWS | `PutSecretValue` with custom staging label `SECRETMESH_PENDING` (not `AWSPENDING`, reserved for rotation). Approve → `UpdateSecretVersionStage` moves `AWSCURRENT`. Reject → remove label (AWS reaps unlabelled versions). | Shadow staging secret (first version of a new secret gets `AWSCURRENT` automatically – verify in spike). |
| Azure | Shadow staging secret `sm-staging-<request>` in the same vault. Approve → read staging, `SetSecret` on target, delete + purge staging. | Same shadow approach. |
| GCP | Shadow staging secret `sm-staging-<request>` in the same project. Approve → `AddSecretVersion` on target, delete staging. | Same shadow approach. |

Why shadow secrets for Azure/GCP: a disabled new version becomes "latest", which can break consumers that read the latest version. To be confirmed in the M3/M5 spikes.

Staging secrets:
- Restricted IAM: only the SecretMesh executor identity can read/write them.
- Tagged `secretmesh:request=<id>`, `secretmesh:expires=<ts>`.
- Cleanup job destroys expired/rejected staging; reconciler sweeps orphans by tag.
- Azure with purge protection: staged values remain soft-deleted in the vault for the retention period (still only in the cloud) – document this.

Promotion flow:
1. Worker re-checks all four gates (identity of request, authorization, approval valid and unexpired, OPA).
2. Writes journal intent row.
3. Reads staged value, recomputes HMAC, compares with approval binding (tamper check).
4. Promotes, records provider version id + cloud request id, writes audit event.
5. Destroys staging; marks journal complete.

## Milestones (solo, sequential)

| Milestone | Scope | Est. | Exit criteria |
|-----------|-------|------|---------------|
| M0 Foundation ✅ (verified locally 2026-11-11; CI not yet run on GitHub, CODEOWNERS pending) | Monorepo, `docker compose` (Postgres, Keycloak, Moto — replaced LocalStack in M3, which now needs an auth token), migrations, OpenAPI 3.1 + oapi-codegen, Next.js shell, CI (lint, test, gitleaks, semgrep, trivy, CodeQL), redacting logger, OSS governance files | 3 wks | `make dev` → OIDC login → see org |
| M1 Tenancy & identity ✅ (verified locally 2026-11-12; Google/Entra not tested live, web UI not browser-tested) | RLS everywhere, tenant from verified identity (`SET LOCAL`), OIDC (Google/Entra/generic), MFA claim, step-up, scoped API tokens (hashed) | 3 wks | Cross-tenant read/write tests fail closed |
| M2 Security gates & audit ✅ (verified locally 2026-11-12; immutable export, break-glass and KMS keyring moved to M3) | Hash-chained audit + signed checkpoints + S3 Object Lock export; RBAC/ABAC; approval state machine; OPA at worker; journal + reconciler | 5 wks | Full gate chain on a fake connector; bypass/replay/tamper tests |
| M3 AWS vertical slice ✅ (verified locally against Moto 2026-11-12; **real AWS account not yet tested**, so v0.1.0-alpha is not tagged) | KMS keyring, audit export to S3 Object Lock, break-glass, AssumeRole + ExternalId, `SecretStore` interface + capabilities, discovery, CRUD via ADR-003 staging, reveal (step-up, `no-store`), UI: inventory/detail/approvals/audit | 6 wks | Blueprint §20 Deliverable 3 against an emulator (Moto) + real test account → **v0.1.0-alpha** |
| M4 Rotation & notifications ✅ (verified locally 2026-11-12; native AWS rotation completion not tested against real AWS) | Scheduler on job queue, plugin contract, AWS-native + manual plugins, reminders/escalation, SMTP + Slack | 5 wks | Worker killed mid-rotation recovers |
| M5 Azure & GCP ✅ (built 2026-11-15; **verified against in-process fakes only, no live Azure or GCP account yet**) | Adapters via workload identity, shadow-staging, connector contract test suite | 6 wks | Same CRUD/approval E2E on all three clouds |
| M6 Posture & release | ≥10 posture rules, scoring, CLI, Helm chart, SBOM/Cosign/SLSA, docs, external pentest | 5 wks | **v0.1.0** self-hosted release |

Total ≈ 33 weeks (~8 months). Alpha after M3 (~17 weeks).

## M1 breakdown

1. Migration: RLS policies on all tenant tables, definer functions, invitations, API tokens, session `auth_time`/MFA, org `require_mfa`.
2. `postgres.Tx` with transaction-local tenant context; runtime role check at startup; test databases use separate owner/app roles.
3. Principals: session or bearer token; org middleware verifies membership before setting the tenant.
4. API: members (list, change role, remove; last admin protected), invitations, API tokens (step-up), org settings (`require_mfa`).
5. OIDC: MFA detection from `amr`/`acr`, step-up re-auth, session rotation, `return_to`, Google/Entra/Keycloak guide.
6. Cross-origin protection; gitleaks rule for `smt_` tokens.
7. Tests: RLS coverage and cross-tenant isolation at the SQL level; cross-tenant, scope, revocation, step-up and MFA tests at the HTTP level.
8. Web: organization page (members, invitations, tokens, settings).

## M2 delivered

- Inventory metadata (environments, connections, secrets) and environment-scoped role bindings for the blueprint roles; organization admins get no implicit resource rights.
- Change requests (create/update/delete) staging values in the provider, HMAC-bound approvals (step-up, no self-approval, exact binding hash), configurable approval policy, expiry and cancellation.
- Worker on River (embedded or `secretmesh-api worker`): rebuilds gates 1-4 from the database, OPA execution policy (`policies/execution.rego`), execution journal with idempotency keys, tamper check of staged values, reconciler.
- Per-organization hash-chained audit ledger, append-only for the runtime role, signed checkpoints, verification API; M1 actions now audited.
- Fake connector (in-memory) behind the `connectors.SecretStore` interface.
- Tests: full lifecycle, bypass attempts (scope, self-approval, token limits, cross-tenant), replay, staged-value and record tampering, lost provider responses, expiry, River end to end, audit tampering by the database owner, zero secret persistence across every table.

Deferred: S3 Object Lock export, break-glass, KMS keyring (M3); teams and classification conditions for ABAC; web UI for approvals/audit (M3).

## M3 delivered

- AWS Secrets Manager connector: AssumeRole with a SecretMesh-generated ExternalId (15-minute sessions, no stored credentials), capabilities, ADR-0003 staging (update: version labelled `SECRETMESH_PENDING`; create: shadow secret `secretmesh-staging/<request>`), idempotent promotion with `ClientRequestToken`, soft delete, conflict detection.
- Discovery (metadata only) with `secretmesh:environment` / `secretmesh:classification` tags and a per-connection default environment; periodic and on-demand sync, failures surfaced on the connection.
- Reveal: `secret_admin` + step-up, MFA for production/restricted, audited before the response, `no-store`.
- Break-glass: `break_glass` role + MFA + sign-in within 5 minutes + justification; no prior approval, flagged and filterable; the worker re-checks the role.
- AWS KMS keyring (GenerateMac, ECDSA P-256 checkpoints with local verification, fallback to the previous keyring).
- Audit export of each checkpointed batch to S3 Object Lock (JSONL + signed checkpoint, explicit retention, append-only export ledger).
- CloudFormation: connector role (`deployments/aws/connector-role.yaml`) and audit bucket (`deployments/aws/audit-bucket.yaml`); guide `docs/guides/aws.md`; ADR-0010.
- Web UI: secrets inventory, secret detail (versions, reveal with 30-second auto-hide), change requests (propose, approve/reject showing the binding hash, cancel, break-glass filter), audit log with verification, settings (connections, environments, role bindings).
- Tests: connector, KMS and export against Moto; HTTP flow (shadow create, labelled update, rejection, reveal checks, discovery) and break-glass, with mutation checks on the reveal and break-glass gates. Dev run with Keycloak + Moto: staging create/update/reveal succeeded, production change denied for lack of MFA as designed, no values in the database or logs.

Open before tagging v0.1.0-alpha: run the slice against a real AWS test account (IAM/ExternalId enforcement, Object Lock, KMS); browser test of the new UI; CI run on GitHub. Done since: the sweeper for orphaned `secretmesh-staging/` secrets (see "Sweeper" below).

### Sweeper

Discovery now removes shadow staging secrets that no live change request owns (`connectors.StagingSweeper`, run after each periodic sync). It only touches secrets with the `secretmesh-staging/<request id>` name and the `secretmesh:staging` tag, and only after a one-hour grace period, so a request still being created is never swept. Staged versions labelled `SECRETMESH_PENDING` on existing secrets are not swept yet.

## M5 delivered

- Azure Key Vault and Google Cloud Secret Manager connectors (`internal/connectors/azure`, `internal/connectors/gcp`), hand-written REST, keyless identity (Azure workload/managed identity; GCP ADC plus service-account impersonation), marker-secret ownership proof, shadow staging with a sweeper, reversible delete. Design in ADR-0012; guides `docs/guides/azure.md` and `docs/guides/gcp.md`; role templates in `deployments/azure` and `deployments/gcp`.
- `internal/connectors/contract`: one behavioural suite run by the fake, AWS (LocalStack and Moto), Azure and GCP connectors. It found and fixed an AWS error-mapping bug.
- Connection creation for all three clouds (generated external ID, strict validation, no credentials accepted); connection form in the UI; both providers off by default.
- Open before calling M5 done: run each connector against a live account (the fakes are written from the documented APIs and can differ); the full approval flow over HTTP currently runs on the fake and AWS providers only, with Azure and GCP covered by the contract suite.

## M4 delivered

- Rotation policies per secret (`native` via the provider's rotation function, `manual` with reminders), secret owners, rotate-now (step-up; MFA in production), rotation history.
- Plugin contract (Validate/Rotate/Verify/Recover) with native (AWS `RotateSecret`, `ClientRequestToken` = execution ID, `AWSPENDING` cleanup) and manual plugins.
- Scheduler on River with deduplicated reminders, due notices and three-step escalation (owner → security → org admins); resumable runner (scheduled → rotating → verifying → done) with lookup-before-start, snooze while the provider works, verify timeout, reconciler; rotation gate-4 policy (`policies/rotation.rego`); rotations and change requests exclude each other. Approved updates and provider-side version changes count as rotations.
- Notifications outbox with per-channel deliveries and retries: email (deployment SMTP, STARTTLS required) and Slack (webhook URL kept as a secret in the customer's vault, prefix allow-list, no redirects). Events: approval requested, change outcome, break-glass, rotation reminder/due/overdue/failed.
- UI: rotation panel and owner on the secret page, next-rotation column, notification channels and delivery log in Settings. Mailpit in the dev stack. ADR-0011 and guide.
- Tests: worker killed mid-rotation through River (exit criterion) and lost-response recovery without double rotation; failure, timeout and missing-function paths; reminders and escalation recipients; email/Slack delivery, retries, webhook allow-list, redirect and header-injection checks; zero secret values in notifications. AWS rotation calls against Moto (Moto finishes rotations instantly, so completion is covered by the fake provider). Mutation checks on the new gates.

Open: native rotation against a real AWS rotation function; Teams channel; notification preferences per user.

## Post-v0.1: SaaS track

Keep SaaS-ready now (cheap): `organization_id` + RLS on every table, no global cloud credentials, per-tenant KMS key for HMAC, executor identity separate from API identity.

Then:
1. Multi-tenant control plane hardening, tenant onboarding and billing boundaries.
2. Customer connector agent (outbound mTLS, signed scoped jobs) – required so SaaS never holds cloud credentials and staged values never transit the SaaS plane.
3. Dedicated-tenant deployments for enterprise.

## Week-1 tasks

1. Name: **SecretMesh** (decided). Use `secretmesh` for Go module path, binaries, images, Helm chart and DB names.
2. Write ADR-001…007 into `docs/adr/`.
3. STRIDE threat model in `docs/threat-model/`.
4. Spike: AWS staging label + first-version behaviour on LocalStack and a real account.
5. Scaffold repo, compose stack, CI, OpenAPI stub.
