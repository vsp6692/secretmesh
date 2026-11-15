# Rotation and notifications

See ADR-0011 for the design.

## Secret owners

Set an owner on a secret's page, or with `PATCH /orgs/{org}/secrets/{id}` and `{"owner_user_id": "..."}`. Only someone with `secret_admin` in the secret's environment can do this, and the owner must be able to read the secret. Rotation reminders and escalations go to the owner first. Without an owner, they go to everyone with `secret_admin` there.

## Rotation policies

A `secret_admin` sets the policy on the secret's page or with `PUT /orgs/{org}/secrets/{id}/rotation-policy`. This needs a recent sign-in.

| Field | Meaning |
|-------|---------|
| `strategy` | `native`: SecretMesh starts the provider's own rotation on schedule. `manual`: SecretMesh reminds and escalates until the value changes |
| `interval_days` | Days between rotations, counted from the last rotation |
| `reminder_days` | Days before the due date to remind (manual). Default `7,3,1` |
| `escalation_days` | Days after the due date to escalate. Default `1,3,7`: the owner, then also the security team, then also organization admins |
| `enabled` | Disabled policies neither rotate nor remind. Rotate-now still works |

What counts as a rotation, whichever strategy is set:
- a successful native rotation;
- an approved change with a new value;
- a new current version found by discovery (for example, AWS's own rotation schedule).

### Native rotation on AWS

1. Configure rotation on the secret in AWS: a rotation function from the AWS templates for RDS, Redshift or DocumentDB, your own Lambda, or managed rotation. SecretMesh does not deploy rotation code.
2. The connector role needs `secretsmanager:RotateSecret`. It is included in `deployments/aws/connector-role.yaml`.
3. Set a `native` policy. SecretMesh checks that the secret has rotation configured.

When a rotation is due, SecretMesh calls `RotateSecret` with an idempotency token and then watches the version labels until the new version is `AWSCURRENT`.
- A rotation that doesn't finish within `SECRETMESH_ROTATION_VERIFY_TIMEOUT` (default `30m`) is abandoned. SecretMesh removes `AWSPENDING` so that the next attempt can run, and reports the failure.
- The current value is never touched by a failed rotation.

**Rotate now** starts one immediately. It needs a recent sign-in, and MFA for production secrets.

Rotations and change requests exclude each other: you can't submit a change while a rotation is running, and a rotation that comes due while a change is open is refused. The refusal is reported and escalated if the secret stays overdue.

## Notifications

| Event | Who |
|-------|-----|
| Approval requested | Approvers for the environment, except the requester |
| Change applied, failed, rejected or expired | The requester |
| Break-glass change | Security team and organization admins |
| Rotation reminder and due (manual) | Owner |
| Rotation overdue | Widening at each step: owner, then also the security team, then also organization admins |
| Rotation failed | Owner, security team and whoever asked for it |

Notifications contain names, environments, dates and a link, never values.

### Channels

A `security_admin` manages channels under **Settings → Notifications**. Each channel has a **Send test** button, and recent deliveries with their errors are listed there. Failed deliveries are retried up to 5 times, with backoff.

**Email** sends one message per recipient. Configure SMTP for the deployment:

| Setting | |
|---------|--|
| `SECRETMESH_SMTP_ADDR` | `host:port` (email is disabled without it) |
| `SECRETMESH_SMTP_FROM` | Sender address |
| `SECRETMESH_SMTP_USERNAME` / `SECRETMESH_SMTP_PASSWORD` (or `_FILE`) | Optional authentication |
| `SECRETMESH_SMTP_TLS` | `starttls` (default, required), `tls` (implicit, port 465) or `none` (loopback only) |

**Slack** uses an incoming webhook:
1. Create the incoming webhook in Slack.
2. Store its URL as a secret in your vault, through a change request like any other secret.
3. Add a Slack channel that points at that secret. You need read access to it.

SecretMesh reads the URL only when sending and never stores or logs it. It only posts to URLs starting with `SECRETMESH_SLACK_WEBHOOK_PREFIXES` (default `https://hooks.slack.com/`).

### Local development

`make deps-up` starts Mailpit. `.env` sends email to it, and you can read it at http://localhost:8025.
