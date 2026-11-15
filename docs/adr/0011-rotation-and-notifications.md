# 0011. Rotation engine and notifications

Status: Accepted
Date: 2026-11-12

## Context

M4 adds secret rotation and notifications. Blueprint §7 asks SecretMesh to own the rotation schedule and governance, use provider-native rotation where appropriate, recover from failures, and remind and escalate. ADR-0003 still applies: secret values stay in the customer's vault and never in SecretMesh, and this includes newly generated values and notification credentials.

## Decision

**Strategies and plugin contract.**
- Each secret can have one rotation policy: strategy, interval, reminder days, escalation days, enabled.
- A plugin implements `Validate`, `Rotate`, `Verify` and `Recover`. Every call that acts on the provider takes the rotation execution's ID as its idempotency key. The blueprint's `Prepare` step is folded into `Rotate`, because preparing the new version is the provider's job.
- **native**: the provider rotates, using AWS Secrets Manager `RotateSecret` with the execution ID as `ClientRequestToken`. The secret must already have a rotation function, so SecretMesh never deploys code into customer accounts. The new value is generated inside the provider.
- **manual**: for credentials only people can rotate. SecretMesh tracks the schedule, then reminds and escalates.
- What counts as a rotation, for either strategy: a successful native rotation, an approved update, or discovery finding a new current version (which covers the provider's own schedule). Any of these moves the next due date.
- Database, certificate and other external strategies are later plugins.

**Scheduler.**
- A periodic job (every minute) scans enabled policies through a SECURITY DEFINER pre-filter, then works in each organization's scope with its own clock.
- Native policies that are due get one execution per due date (a unique index), and only one open execution per secret.
- Manual policies get:
  - one reminder: the closest step that has passed;
  - a "due" notice;
  - escalation that widens at each step: the owner, then also the security team, then also organization admins.
- Every notification has a dedupe key, so ticks are idempotent and downtime never causes a burst of notifications.

**Runner (resumable).**
- An execution moves scheduled → rotating → verifying → succeeded/failed. Each transition is committed before the next provider call.
- In the rotating state the runner first asks the provider whether the attempt exists, and only then starts it. A worker killed at any point is resumed by River's retry or by a reconciler (open executions untouched for 5 minutes), and the provider never rotates twice.
- While the provider is still rotating, the job snoozes.
- After `SECRETMESH_ROTATION_VERIFY_TIMEOUT` (default 30 minutes), or when the provider reports failure, the runner calls `Recover`, which removes `AWSPENDING` so that a later attempt can run, and marks the execution failed.
- `Recover` never restores an old credential.

**Gate 4 for rotation.**
- `policies/rotation.rego` (package `secretmesh.rotation`) is evaluated from database state right before the provider is first called.
- Scheduled rotations are authorized by the enabled policy itself (the blueprint's "automated policy" option). A person setting a policy needs `secret.manage` (granted to `secret_admin`) plus step-up.
- Rotate-now is bound to the requester, who must still be a member with `secret.manage`. Production needs MFA.
- A rotation is denied while a change request is open for the secret, and a change request is refused while a rotation is open. Neither can overwrite the other.
- The policy can be replaced like the execution policy.

**Notifications.**
- An outbox (`notifications`, `notification_deliveries`) is written in the same transaction as the event.
- A delivery job (every 15 seconds) sends each delivery while holding its row lock. It retries with exponential backoff, up to 5 attempts. Permanent errors fail immediately.
- Events:
  - approval requested (to the environment's approvers, excluding the requester);
  - change outcome (to the requester);
  - break-glass (to the security team and organization admins);
  - rotation reminder, due, overdue and failed.
- Notifications carry names, environments, dates and links, never values. Email subjects are folded onto one line to prevent header injection.
- **Email**: SMTP is deployment configuration. STARTTLS is required unless implicit TLS is used, and plaintext is allowed only to loopback (Mailpit in development). Each recipient gets their own message.
- **Slack**: a channel stores only the ID of a secret in the organization's vault whose value is the incoming webhook URL. The URL is read through the connector at send time and is never persisted or logged.
  - Webhooks must match `SECRETMESH_SLACK_WEBHOOK_PREFIXES` (default `https://hooks.slack.com/`).
  - Redirects are not followed, and errors never include the URL.
  - Whoever creates the channel must be able to read that secret.
- Channels are managed with `notifications.manage` (granted to `security_admin`).

## Consequences

- No rotated value or webhook URL is stored by SecretMesh. The zero-persistence test covers the new tables.
- Native rotation depends on a correctly configured rotation function, which SecretMesh validates when the policy is set and again before each run. It cannot detect a function that "succeeds" without actually changing the credential the application uses.
- Moto cannot run rotation functions: it accepts `RotateSecret` and finishes it immediately. Rotation completion, failure and timeout are tested with the fake provider. The AWS calls (token idempotency, version labels, abandoning) are tested against Moto, but real AWS still needs to be confirmed.
- Running the scheduler on the provider's own schedule as well (AWS rotation rules) is allowed. Discovery records those rotations, but customers should normally choose one scheduler.
- Email recipients are resolved when the notification is created, so people who lose a role after that still receive it. Addresses are read when the notification is sent.
