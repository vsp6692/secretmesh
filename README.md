# SecretMesh

Multi-cloud secrets governance for AWS Secrets Manager, Azure Key Vault and Google Cloud Secret Manager.

A personal project by [@vsp6692](https://github.com/vsp6692), built and maintained in my spare time.

SecretMesh is a control plane: it manages inventory, policies, approvals, rotation and audit. **Secret values never leave your own cloud vaults and are never persisted by SecretMesh.** Its database holds only metadata.

> Status: personal project in early development (milestone M5: AWS, Azure and Google Cloud connectors; AWS tested against emulators, Azure and GCP against in-process fakes only). Not ready for production use. See [PLAN.md](PLAN.md).

## Repository layout

| Path | Contents |
|------|----------|
| `apps/api` | Go API server (`secretmesh-api serve` / `migrate`) |
| `apps/web` | Next.js web app; proxies `/api` and `/auth` to the API |
| `internal/` | Application modules: `config`, `auth`, `identity`, `tenancy`, `inventory`, `approvals`, `execution`, `audit`, `connectors`, `keys`, `policy`, `workflows`, `httpapi`, `platform` |
| `policies/` | OPA execution policy (embedded) |
| `pkg/sensitive` | `sensitive.Value`, a type for secret material that never prints, logs or serializes its contents |
| `pkg/telemetry` | Structured logging with key-based redaction |
| `contracts/openapi` | OpenAPI 3.1 contract; Go server code is generated from it |
| `migrations/` | PostgreSQL migrations (goose, embedded in the binary) |
| `deployments/docker` | Local dependencies (Postgres, Keycloak, Moto AWS emulator) and Dockerfiles |
| `docs/adr` | Architecture decision records |
| `docs/guides` | Operator guides (identity provider, AWS, Azure, Google Cloud) |

## Development

Requirements: Go 1.27+, Node.js 24+, Docker with Compose.

```sh
make dev
```

This copies `.env.example` to `.env`, starts Postgres and Keycloak, applies migrations and runs the API (`:8080`) and the web app (`:3000`).

Open http://localhost:3000 and sign in:

| User | Password | Result |
|------|----------|--------|
| `admin` | `admin` | Bootstrap admin of the *Acme Technologies* organization |
| `developer` | `developer` | No organizations until the admin invites `developer@secretmesh.local` |

Keycloak admin console: http://localhost:8081 (`admin` / `admin`).

Other targets (`make help`):

```sh
make test               # unit tests; DB and AWS tests skip without their services
make test-integration   # full suite on LocalStack and Moto (throwaway Docker stack, no skips allowed)
make lint               # golangci-lint, eslint, tsc
make security           # gitleaks + govulncheck
make generate           # regenerate Go code from the OpenAPI contract
make hooks              # install the pre-commit, commit-msg and pre-push hooks
make verify             # everything CI checks
```

### Database roles

The API never connects as the schema owner:

- `secretmesh_migrator` owns the schema and is used only by `secretmesh-api migrate`.
- `secretmesh_app` has DML privileges only and `NOBYPASSRLS`, so Row-Level Security applies to it.

See [`deployments/docker/postgres/init.sql`](deployments/docker/postgres/init.sql). The API refuses to start if its role is a superuser, has `BYPASSRLS` or owns tables.

### Tenancy and access

- Every tenant table has Row-Level Security. The tenant comes from the verified identity and is set per transaction ([ADR-0008](docs/adr/0008-tenant-context-and-principals.md)).
- Roles: `org_admin` and `member`. Admins invite people by email. Invitations are accepted when someone signs in with that verified email.
- API tokens (`Authorization: Bearer smt_...`) belong to one organization. They have explicit scopes and an expiry, and never exceed their creator's current role.
- Creating tokens and changing security settings requires a sign-in within the last 5 minutes (step-up). Organizations can require MFA.
- Identity provider setup (Keycloak, Google, Entra ID): [docs/guides/oidc.md](docs/guides/oidc.md).
- AWS connector, KMS keyring and audit export: [docs/guides/aws.md](docs/guides/aws.md).
- Azure Key Vault connector: [docs/guides/azure.md](docs/guides/azure.md). Google Cloud Secret Manager connector: [docs/guides/gcp.md](docs/guides/gcp.md).
- Rotation policies, owners and notification channels: [docs/guides/rotation-and-notifications.md](docs/guides/rotation-and-notifications.md).

### Changes, approvals and audit

Secrets change through change requests ([ADR-0009](docs/adr/0009-governance-gate-chain.md)):

1. A member with a role binding (`developer`, `secret_admin`) submits a create, update or delete. The value goes straight to the provider's staging area; SecretMesh keeps only a keyed MAC of it.
2. The approval policy sets how many approvals are needed (by default 1 for production, 2 for production deletes). Approvers need an `approver` binding, a sign-in within the last 5 minutes, and must confirm the request's binding hash. Requesters cannot approve their own changes.
3. The worker re-checks identity, authorization and approvals against the database, evaluates the OPA policy in `policies/execution.rego`, journals the intent, verifies the staged value and promotes it.
4. Every step is recorded in a per-organization hash-chained audit log with signed checkpoints (`GET /api/v1/orgs/{id}/audit/verification`).

Organization admins have no secret permissions until they bind themselves. In the dev stack the in-memory `fake` provider is enabled (`SECRETMESH_ENABLE_FAKE_CONNECTOR=true`), and production changes are denied because the dev Keycloak has no MFA (`production_requires_mfa`). Supply your own policy with `SECRETMESH_EXECUTION_POLICY_FILE` if needed.

### Configuration

All settings are environment variables prefixed `SECRETMESH_` and documented in [`.env.example`](.env.example). Credentials (`SECRETMESH_DATABASE_URL`, `SECRETMESH_MIGRATIONS_DATABASE_URL`, `SECRETMESH_OIDC_CLIENT_SECRET`) also accept a `_FILE` suffix pointing to a mounted secret.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
