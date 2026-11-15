# 0006. Embedded OPA for execution policy

Status: Accepted
Date: 2026-11-11

## Context

Level 4 (execution policy) uses OPA/Rego. Running OPA as a sidecar adds a network hop and a deployment component.

## Decision

Embed OPA as a Go library. Policies live in `policies/`, are bundled at build time (with optional operator-supplied bundles later), and are evaluated in the worker immediately before every cloud operation, not only at the API.

## Consequences

No extra service; policy evaluation cannot be bypassed by calling a worker directly. Policy updates require a restart until bundle loading is added.
