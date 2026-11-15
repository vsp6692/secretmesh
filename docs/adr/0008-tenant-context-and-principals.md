# 0008. Tenant context, principals and API tokens

Status: Accepted
Date: 2026-11-12

## Context

ADR-0002 requires RLS with tenant context taken from the verified identity. Some lookups must happen before any tenant is known: login, API token authentication, accepting invitations and creating the bootstrap organization. Programmatic access needs credentials that can be scoped and revoked, and sensitive operations need recent, possibly multi-factor, authentication.

## Decision

**Tenant context.**
- Two transaction-local settings, `secretmesh.user_id` and `secretmesh.organization_id`, set with `set_config(..., true)` inside the transaction that runs the queries (`postgres.Tx`). They are never read from request input; middleware sets them from the authenticated principal, and the organization only after membership is verified.
- If either setting is unset, policies match no rows (fail closed). Pooled connections cannot carry context between transactions.
- `users`, `organizations` and `memberships` are visible to the current user (self and own memberships) and to the current organization (its members). All other tenant tables are visible only to the current organization.
- `sessions` and `oidc_login_states` hold no tenant data and have no RLS. A test enforces that every other table has RLS enabled.

**Pre-tenant lookups** go through a small set of `SECURITY DEFINER` functions owned by the migrator, which bypass RLS as table owner: `secretmesh_login_user`, `secretmesh_authenticate_api_token`, `secretmesh_accept_invitations` and `secretmesh_ensure_organization`. Each has a fixed `search_path`, does one narrow thing, and is reviewed like an API endpoint. Tables do not use `FORCE ROW LEVEL SECURITY`.

**Principals.**
- A user session acts within an organization with that membership's role.
- An API token (`smt_` + 32 random bytes) is bound to one organization. Only its SHA-256 hash is stored. It has an expiry (at most 365 days) and explicit scopes. Its effective permissions are its scopes intersected with its creator's *current* role. It stops working when revoked, expired, or when its creator leaves the organization.
- Tokens cannot manage tokens or call user-only endpoints.

**MFA and step-up.**
- A session records `auth_time` and whether the login satisfied MFA. MFA is satisfied when the ID token's `amr` or `acr` contains a configured value.
- An organization can require MFA for all of its sessions.
- Sensitive operations (creating API tokens, enabling the MFA requirement; later reveal and approve) require `auth_time` within 5 minutes. Re-authentication uses `prompt=login` and `max_age=0`. An IdP that omits `auth_time` cannot satisfy step-up (fail closed).

**CSRF.** All routes use Go's `http.CrossOriginProtection` (Sec-Fetch-Site / Origin) on top of `SameSite=Lax` session cookies.

## Consequences

- A missing `WHERE organization_id` cannot leak data across tenants, as long as the query runs as the runtime role through `postgres.Tx`. The API refuses to start if its database role is a superuser, has `BYPASSRLS`, or owns tables.
- The definer functions are the trusted surface for cross-tenant access; adding one needs review.
- Workers (M2+) must establish tenant context explicitly per job.
- Invitations are accepted automatically when a user with a matching *verified* email signs in. IdPs that do not send `email_verified` (e.g. Entra ID) need `SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED=true`, which is allowed only for single-tenant issuers.
