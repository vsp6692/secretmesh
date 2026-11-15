# 0004. Approval binding and tamper check

Status: Accepted
Date: 2026-11-11

## Context

An approval must authorize exactly one operation on exactly one value. A plain SHA-256 of a low-entropy secret stored in the database could be brute-forced offline, violating zero secret persistence.

## Decision

- An approval binds: tenant, target secret, operation, staging reference, provider version ID, nonce and expiry.
- At submission, compute `HMAC-SHA256(key, canonical(payload))` with a per-tenant key held in a KMS (never in the database). Store only the MAC.
- Before promotion, the worker reads the staged value, recomputes the MAC and refuses to promote on mismatch.
- Requester cannot approve; approvers authenticate independently; approvals expire and cannot be reused.

## Consequences

Database theft does not allow offline guessing of secret values. Tampering with the staged value between approval and promotion is detected. Requires KMS access from API and worker.
