-- SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

-- +goose Up

-- M4: rotation policies and executions, secret owners, and notifications
-- (ADR-0011).

ALTER TABLE secrets
    ADD COLUMN owner_user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN last_rotated_at TIMESTAMPTZ;

-- One rotation policy per secret. "native" asks the provider to rotate (AWS
-- Secrets Manager rotation functions); "manual" only reminds and escalates
-- until someone changes the value.
CREATE TABLE rotation_policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    secret_id         UUID NOT NULL,
    strategy          TEXT NOT NULL CHECK (strategy IN ('native', 'manual')),
    interval_days     INTEGER NOT NULL CHECK (interval_days BETWEEN 1 AND 3650),
    reminder_days     INTEGER[] NOT NULL DEFAULT '{7,3,1}',
    escalation_days   INTEGER[] NOT NULL DEFAULT '{1,3,7}',
    enabled           BOOLEAN NOT NULL DEFAULT true,
    next_rotation_at  TIMESTAMPTZ NOT NULL,
    created_by        UUID REFERENCES users (id) ON DELETE SET NULL,
    updated_by        UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, secret_id) REFERENCES secrets (organization_id, id) ON DELETE CASCADE,
    UNIQUE (secret_id),
    UNIQUE (organization_id, id),
    CHECK (cardinality(reminder_days) <= 10 AND cardinality(escalation_days) <= 3)
);

-- One automated rotation attempt. Its ID is the provider idempotency key
-- (e.g. ClientRequestToken), so a resumed attempt never rotates twice.
CREATE TABLE rotation_executions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    secret_id            UUID NOT NULL,
    trigger              TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    requested_by         UUID REFERENCES users (id) ON DELETE SET NULL,
    requester_mfa        BOOLEAN NOT NULL DEFAULT false,
    status               TEXT NOT NULL DEFAULT 'scheduled'
                         CHECK (status IN ('scheduled', 'rotating', 'verifying', 'succeeded', 'failed')),
    due_at               TIMESTAMPTZ NOT NULL,
    provider_version_id  TEXT,
    cloud_request_id     TEXT,
    error_code           TEXT,
    rotate_started_at    TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, secret_id) REFERENCES secrets (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id)
);

-- At most one open attempt per secret, and one scheduled attempt per due date.
CREATE UNIQUE INDEX rotation_executions_open_idx ON rotation_executions (secret_id)
    WHERE status IN ('scheduled', 'rotating', 'verifying');
CREATE UNIQUE INDEX rotation_executions_slot_idx ON rotation_executions (secret_id, due_at)
    WHERE trigger = 'schedule';
CREATE INDEX rotation_executions_secret_idx ON rotation_executions (organization_id, secret_id, created_at DESC);

-- Notification channels. Email recipients are resolved from roles; SMTP is
-- deployment configuration. A Slack channel stores only the ID of a secret
-- in the organization's vault that holds the webhook URL.
CREATE TABLE notification_channels (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind             TEXT NOT NULL CHECK (kind IN ('email', 'slack')),
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    config           JSONB NOT NULL DEFAULT '{}',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

-- Outbox. Notifications never contain secret values. dedupe_key makes
-- reminders and escalations idempotent across scheduler runs.
CREATE TABLE notifications (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    event            TEXT NOT NULL,
    dedupe_key       TEXT NOT NULL,
    subject          TEXT NOT NULL,
    body             TEXT NOT NULL,
    link_path        TEXT NOT NULL DEFAULT '',
    recipients       UUID[] NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, dedupe_key),
    UNIQUE (organization_id, id)
);

CREATE TABLE notification_deliveries (
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    notification_id  UUID NOT NULL,
    channel_id       UUID NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error       TEXT,
    sent_at          TIMESTAMPTZ,
    PRIMARY KEY (notification_id, channel_id),
    FOREIGN KEY (organization_id, notification_id) REFERENCES notifications (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, channel_id) REFERENCES notification_channels (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX notification_deliveries_due_idx ON notification_deliveries (next_attempt_at) WHERE status = 'pending';

ALTER TABLE rotation_policies       ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_executions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels   ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications           ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY rotation_policies_tenant ON rotation_policies FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY rotation_executions_tenant ON rotation_executions FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY notification_channels_tenant ON notification_channels FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY notifications_tenant ON notifications FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY notification_deliveries_tenant ON notification_deliveries FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));

-- Cross-tenant scans for background jobs. They return identifiers only;
-- the work itself runs inside each organization's scope.

-- +goose StatementBegin
CREATE FUNCTION secretmesh_rotation_policies_due()
RETURNS TABLE (organization_id UUID, policy_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p.organization_id, p.id FROM public.rotation_policies p
    JOIN public.secrets s ON s.id = p.secret_id AND s.status = 'active'
    -- A day of slack: this is only a pre-filter, the scheduler decides
    -- exactly with its own clock.
    WHERE p.enabled
      AND p.next_rotation_at <= now() + make_interval(days =>
          coalesce((SELECT max(d) FROM unnest(p.reminder_days) AS d), 0) + 1)
    ORDER BY p.next_rotation_at;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION secretmesh_stale_rotations(p_older_than INTERVAL, p_limit INTEGER)
RETURNS TABLE (organization_id UUID, execution_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT e.organization_id, e.id FROM public.rotation_executions e
    WHERE e.status IN ('scheduled', 'rotating', 'verifying') AND e.updated_at < now() - p_older_than
    ORDER BY e.updated_at LIMIT p_limit;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION secretmesh_notification_deliveries_due(p_limit INTEGER)
RETURNS TABLE (organization_id UUID, notification_id UUID, channel_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT d.organization_id, d.notification_id, d.channel_id FROM public.notification_deliveries d
    WHERE d.status = 'pending' AND d.next_attempt_at <= now()
    ORDER BY d.next_attempt_at LIMIT p_limit;
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION secretmesh_notification_deliveries_due(INTEGER);
DROP FUNCTION secretmesh_stale_rotations(INTERVAL, INTEGER);
DROP FUNCTION secretmesh_rotation_policies_due();
DROP TABLE notification_deliveries;
DROP TABLE notifications;
DROP TABLE notification_channels;
DROP TABLE rotation_executions;
DROP TABLE rotation_policies;
ALTER TABLE secrets DROP COLUMN last_rotated_at, DROP COLUMN owner_user_id;
