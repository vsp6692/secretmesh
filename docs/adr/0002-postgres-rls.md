# 0002. PostgreSQL with Row-Level Security and split roles

Status: Accepted
Date: 2026-11-11

## Context

Self-hosted v0.1 is single-tenant in practice, but SaaS follows. Retrofitting tenant isolation later is error-prone.

## Decision

- Every tenant-owned table carries `organization_id` from its first migration.
- Row-Level Security policies on every tenant-owned table (from M1). Tenant context is set per transaction from the verified identity (`SET LOCAL`), never from request headers.
- Two database roles: `secretmesh_migrator` owns the schema and runs migrations; `secretmesh_app` has DML only, does not own tables and has `NOBYPASSRLS`.
- Automated tests attempt cross-tenant reads and writes.

## Consequences

The application role cannot alter schema or bypass RLS even if compromised. Background workers must establish tenant context explicitly. Operators must create both roles (documented in `deployments/docker/postgres/init.sql`).
