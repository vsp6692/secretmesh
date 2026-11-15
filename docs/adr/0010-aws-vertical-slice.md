# 0010. AWS vertical slice: connector, staging, KMS keyring, audit export and break-glass

Status: Accepted
Date: 2026-11-12

## Context

M3 connects SecretMesh to a real provider, AWS Secrets Manager. It also delivers the M2 items that needed the AWS SDK: a KMS-backed keyring, off-database audit export and break-glass. ADR-0003 says pending values are staged in the cloud vault and nothing stays in SecretMesh. This ADR records how that maps to Secrets Manager, and the trust boundaries around it.

## Decision

**Connector identity.**
- SecretMesh runs with its own workload identity (the default AWS credential chain) and never accepts credentials in connection config.
- Each connection names a customer IAM role. SecretMesh assumes it with an `ExternalId` that SecretMesh generates (`secretmesh-<random>`) and the caller cannot choose, which prevents confused-deputy use of another tenant's role.
- Sessions last 15 minutes and are named `secretmesh-<connection>`, so CloudTrail shows which connection acted.
- Connection config accepts only `role_arn`, `region` and `external_id`. Endpoint overrides exist only as a process-wide setting for local emulators.
- `deployments/aws/connector-role.yaml` is the reference role: trust limited to the SecretMesh principal and `sts:ExternalId`, and permissions limited to the configured name prefix plus `secretmesh-staging/*`.

**Staging (ADR-0003 on Secrets Manager).**
- **Update:** `PutSecretValue` creates a new version labelled only `SECRETMESH_PENDING`, with the request ID as `ClientRequestToken`. Consumers keep reading `AWSCURRENT`. Promotion moves `AWSCURRENT` to that version, then removes the pending label. A rejected or expired request just loses its label; AWS removes unlabelled versions by itself.
- **Create:** the value goes into a shadow secret `secretmesh-staging/<request>`, tagged `secretmesh:staging`. Promotion creates the real secret with the journal ID as `ClientRequestToken`, so retries are idempotent. A create that finds an existing secret with a different token fails as `provider_conflict`; it never overwrites. The shadow secret is force-deleted once the request finishes.
- **Delete:** scheduled deletion with a 7-day recovery window.
- Staging secrets never appear in discovery.
- Reads that check the result ask for `AWSCURRENT` explicitly.

**Discovery.**
- `ListSecrets` imports metadata only, never values.
- Environment and classification come from the `secretmesh:environment` and `secretmesh:classification` tags, falling back to the connection's default environment and `confidential`.
- Secrets without an environment are counted as unassigned and skipped.
- Secrets that disappear are marked deleted.
- Sync runs every 15 minutes per connection, or on demand by a `cloud_admin`.

**Reveal.**
- Requires:
  - `secret.reveal` (granted to `secret_admin`) in the secret's environment;
  - step-up authentication;
  - MFA for production or restricted secrets.
- The value is read from the provider for each request and sent with `Cache-Control: no-store`; it is never stored.
- The `secret.revealed` audit event is committed before the response is written. If auditing fails, nothing is revealed.

**Keyring.**
- `SECRETMESH_KEYRING=aws-kms` uses:
  - an `HMAC_256` KMS key for approval MACs, via `GenerateMac` over `secretmesh/v1/<purpose>/<org>\n<hex SHA-256(data)>`. The hashing is needed because KMS accepts at most 4 KiB; the purpose and organization keep MACs domain-separated per tenant.
  - an `ECC_NIST_P256` key for checkpoint signatures. Verification uses the cached public key and needs no KMS call.
- At startup, key usage and key spec are checked with `DescribeKey`.
- The local keyring stays as the verification fallback, so checkpoints signed before the switch still verify.

**Audit export.**
- After each signed checkpoint, the events since the previous export, plus that checkpoint, are written as one JSONL object to an S3 bucket with Object Lock. The object gets an explicit retention date and a SHA-256 checksum.
- Startup refuses a bucket without Object Lock.
- The export ledger (`audit_exports`) is append-only, like the audit log.
- An optional, write-only export role keeps audit storage permissions apart from connector permissions. See `deployments/aws/audit-bucket.yaml`.

**Break-glass.**
- An emergency change that skips prior approval. It requires all of:
  - the `break_glass` role in the environment;
  - an MFA session;
  - a sign-in within the last 5 minutes;
  - a reason of at least 20 characters.
- It is audited as `change_request.break_glass` and can be filtered (`?break_glass=true`) for after-the-fact review.
- The worker re-checks the role when it executes. If the role was revoked, the policy denies the change (`break_glass_requires_mfa`) and nothing reaches the provider.

## Consequences

- The deployment holds no customer AWS credentials. A leaked SecretMesh identity still needs each connection's ExternalId and the customer's trust policy.
- Updates are visible as extra versions in Secrets Manager, and creates as short-lived `secretmesh-staging/` secrets. Customers' IAM and SCPs must allow both.
- A failed force-delete can leave a shadow secret behind. A tag-based sweeper for orphans is still to do.
- With the KMS keyring, approving and checkpointing depend on KMS availability. Verification does not.
- Object Lock in COMPLIANCE mode cannot be shortened, even by the account root. Retention is a commitment.
- Verified against Moto 5.2.5 (Secrets Manager, STS, KMS, S3) only. A real AWS account has not been tested yet; IAM policy evaluation, ExternalId enforcement and Object Lock behaviour still need confirmation there.
