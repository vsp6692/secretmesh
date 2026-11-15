# 0012. Azure Key Vault and Google Cloud Secret Manager connectors

Status: Accepted
Date: 2026-11-15

## Context

M5 adds Azure and Google Cloud next to AWS (ADR-0010). The approval workflow already assumes four things of every provider (ADR-0003, ADR-0007): staged values are invisible to consumers, promotion is idempotent per journal key, finished requests leave no staging behind, and discovery returns metadata only. The clouds differ in how they authenticate, in how versions are labelled, and in what "delete" means, so the connectors have to hide those differences without weakening any of the four rules.

Neither connector has run against a live account yet. Both are verified against in-process fakes of the documented REST APIs.

## Decision

**One behavioural contract.** `internal/connectors/contract` is a test suite that every `SecretStore` must pass: create and update invisible until promotion, idempotent promotion, lookups, discards, create conflicts, delete, awkward values (binary-safe, unicode, 8 KB), staging hidden from discovery, and the staging sweeper. The fake, AWS (LocalStack and Moto), Azure and GCP all run it. It found a real AWS bug (reading a soft-deleted secret returned the wrong error class), so a new provider cannot silently drift.

**Identity: SecretMesh's own workload identity, no stored credentials.**
- Connection settings accept only identifiers (`vault_url` and `tenant_id`; `project_id` and `service_account`) and the generated `external_id`. Anything else is rejected, including anything that looks like a credential or an endpoint.
- Azure: a chain of workload identity (federated, per customer tenant) then managed identity. No environment credentials, client secrets or CLI.
- GCP: Application Default Credentials, then impersonation of the customer's service account through `generateAccessToken` (15-minute tokens). A service account key file as SecretMesh's own identity is refused at startup unless a development flag is set.
- Both providers are off by default (`SECRETMESH_ENABLE_AZURE_CONNECTOR`, `SECRETMESH_ENABLE_GCP_CONNECTOR`), because the identity only exists where the deployment runs on, or federates with, that cloud.

**Ownership proof (confused-deputy defence).** AWS has the role trust policy's `ExternalId`. Azure and GCP have no equivalent, and a multi-tenant SecretMesh uses one identity for many customers, so a tenant could otherwise point a connection at another customer's vault or project. Each connection gets a SecretMesh-generated `external_id`. The customer stores it as the value of a secret named `secretmesh-external-id` in the vault or project. Before any operation, and again every 15 minutes, the connector reads the marker and compares it in constant time. A missing or different value is `access denied` and nothing is listed or written. The marker is not a credential; it only proves the customer configured this connection.

**Staging (ADR-0003).** Both providers use a shadow secret `smstaging-<request id>` in the same vault or project, for creates and updates, tagged or labelled as staging. Promotion reads the staged value and writes it to the target. The executor discards staging afterwards, and a periodic sweeper deletes staging secrets that no live request owns. `secretmesh-external-id` and `smstaging-*` are reserved: they cannot be targets and are never discovered.

**Idempotency.**
- Azure: every promoted version carries the tag `secretmesh-op=<journal key>`; a retry finds it and creates no second version.
- GCP versions cannot be tagged, so the secret's annotations record the protocol: an intent annotation before `versions:add`, then an applied annotation with the version number. A retry resumes from whichever step completed, comparing payloads when it cannot tell.

**Delete is reversible.** Azure uses Key Vault soft delete and never purges targets. GCP's delete destroys every version, so SecretMesh instead labels the secret as deleted and disables every version. It never calls destroy. A deleted name blocks re-creation until an administrator purges it by hand.

**HTTP hygiene (all hand-written REST).** HTTPS only (plain HTTP only with an emulator endpoint override), redirects are never followed and any 3xx is an error (a bearer token must not follow a redirect), the token goes only to the configured host, paging links must stay on that host, response bodies are capped at 2 MiB, secret values never reach logs or errors, and provider error bodies are never echoed: only the status and the provider's error code. GCP also sends and verifies CRC32C on payloads. Azure rejects values over 25 KiB at staging time.

**Least privilege.** Reference definitions are in `deployments/azure/connector-role.bicep` and `deployments/gcp/connector-role.tf`. Key Vault RBAC cannot limit access by secret name, so the guide advises a dedicated vault. GCP uses a custom role and an optional IAM condition on a name prefix.

## Consequences

- The deployment holds no customer cloud credentials. A leaked SecretMesh identity still needs each customer's trust grant and marker secret.
- Customers must create the marker secret and grant the role; the UI and the guides say so.
- Azure staging values stay soft-deleted in the customer's vault for the retention period when purge protection is on. They are still only in the customer's cloud.
- Azure discovery cannot report the current version (the list API has no version), so changes made outside SecretMesh are not counted as rotations there.
- GCP discovery costs one extra metadata call per secret. Organization policies that require CMEK or restrict locations will block staging secrets, which use automatic replication.
- Neither provider supports native rotation; rotation policies fall back to `manual` reminders.
- Open until tested live: Azure's `SecretDisabled` error shape, purge timing after delete, Bicep role scope and the ABAC purge condition; GCP's etag-mismatch status, whether `versions/latest` serves a disabled version, and IAM condition behaviour on list calls.
