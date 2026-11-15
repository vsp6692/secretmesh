# 0007. Execution journal and reconciler

Status: Accepted
Date: 2026-11-11

## Context

A cloud operation can succeed while the subsequent database or audit write fails (or the worker crashes). A sensitive operation must never complete without a durable audit record.

## Decision

- Before every mutating cloud call, write an intent row (operation, target, idempotency key, approval reference) to an execution journal.
- After the call, record the provider request ID and version ID, write the audit event and mark the intent complete in one transaction.
- A reconciler scans incomplete intents, queries provider state and either completes them (writing the audit event) or marks them failed.

## Consequences

Every cloud mutation is accounted for even across crashes. Connectors must expose enough read operations to reconcile, and all mutating calls must be idempotent.
