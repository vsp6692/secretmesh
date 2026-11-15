# 0001. Go modular monolith with isolated workers

Status: Accepted
Date: 2026-11-11

## Context

SecretMesh is built by a single developer initially. Microservices per module would multiply deployment, observability and failure modes without benefit at this scale.

## Decision

- Backend in Go, one module (`github.com/secretmesh/secretmesh`) with strong package boundaries under `internal/`.
- Binaries in `apps/` (`api` now; `worker`, `scheduler`, `cli` later). Workers that hold cloud identities run as separate processes so their credentials and blast radius are isolated from the API.
- Frontend in Next.js + TypeScript, served on the same origin as the API via rewrites.
- Cloud SDKs only inside connector packages; business logic depends on provider-neutral interfaces.

## Consequences

Simple local development and deployment. Module boundaries must be enforced by review (and later by lint rules) because the compiler will not stop cross-module imports inside `internal/`.
