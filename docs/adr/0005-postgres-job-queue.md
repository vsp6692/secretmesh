# 0005. Postgres-backed job queue instead of Temporal (MVP)

Status: Accepted
Date: 2026-11-11

## Context

The blueprint selects Temporal for durable workflows. For a solo developer shipping self-hosted first, Temporal adds a cluster (and its database) to every installation.

## Decision

Use a PostgreSQL-backed job queue (River) for v0.1, behind an internal `workflows` interface. Job arguments contain only references and metadata, never secret values. Revisit Temporal for SaaS scale.

## Consequences

One fewer stateful system to operate. Long-running, multi-step workflows (rotation) are modelled as explicit state machines in our tables plus idempotent jobs. Migrating later is contained to the `workflows` package.
