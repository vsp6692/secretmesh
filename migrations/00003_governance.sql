-- +goose Up

-- M2: inventory metadata, role bindings, approvals, execution journal and the
-- hash-chained audit ledger (ADR-0003, 0004, 0007, 0009). No table stores a
-- secret value; change requests hold only references and a keyed MAC.

CREATE TABLE environments (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name             TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    kind             TEXT NOT NULL CHECK (kind IN ('development', 'staging', 'production')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

-- Cloud connections. config holds non-secret settings only (role ARNs, vault
-- URLs); SecretMesh never stores cloud credentials.
CREATE TABLE connections (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name             TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    provider         TEXT NOT NULL CHECK (provider IN ('fake', 'aws', 'azure', 'gcp')),
    config           JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

-- Secret metadata. The value lives only in the provider.
CREATE TABLE secrets (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    connection_id        UUID NOT NULL,
    environment_id       UUID NOT NULL,
    name                 TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    provider_ref         TEXT NOT NULL,
    classification       TEXT NOT NULL CHECK (classification IN ('internal', 'confidential', 'restricted')),
    current_version      TEXT,
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, connection_id) REFERENCES connections (organization_id, id),
    FOREIGN KEY (organization_id, environment_id) REFERENCES environments (organization_id, id),
    UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX secrets_active_name_idx ON secrets (connection_id, name) WHERE status = 'active';

-- Role bindings (RBAC scoped by environment, ADR-0009). A NULL environment
-- means organization-wide. Bindings disappear with the membership.
CREATE TABLE role_bindings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL,
    user_id          UUID NOT NULL,
    role             TEXT NOT NULL CHECK (role IN
                       ('cloud_admin', 'security_admin', 'secret_admin', 'developer', 'approver', 'auditor')),
    environment_id   UUID,
    created_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES memberships (organization_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id) REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    UNIQUE NULLS NOT DISTINCT (organization_id, user_id, role, environment_id)
);

CREATE INDEX role_bindings_user_idx ON role_bindings (organization_id, user_id);

-- Approval requirements; absent row means the built-in defaults.
CREATE TABLE approval_policies (
    organization_id  UUID PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    rules            JSONB NOT NULL,
    updated_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A requested change to one secret. The proposed value is staged in the
-- provider (staging_ref); value_mac is HMAC-SHA256 under a per-tenant key
-- (ADR-0004). binding_hash covers every field that defines the operation.
CREATE TABLE change_requests (
    id                   UUID PRIMARY KEY,
    organization_id      UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    operation            TEXT NOT NULL CHECK (operation IN ('create', 'update', 'delete')),
    status               TEXT NOT NULL CHECK (status IN
                           ('pending', 'approved', 'rejected', 'cancelled', 'expired', 'executing', 'succeeded', 'failed')),
    secret_id            UUID,
    connection_id        UUID NOT NULL,
    environment_id       UUID NOT NULL,
    environment_kind     TEXT NOT NULL,
    secret_name          TEXT NOT NULL,
    classification       TEXT NOT NULL,
    provider_ref         TEXT,
    staging_ref          TEXT,
    staging_version      TEXT,
    value_mac            BYTEA CHECK (value_mac IS NULL OR length(value_mac) = 32),
    nonce                BYTEA NOT NULL CHECK (length(nonce) = 16),
    binding_hash         BYTEA NOT NULL CHECK (length(binding_hash) = 32),
    required_approvals   INTEGER NOT NULL CHECK (required_approvals BETWEEN 0 AND 5),
    reason               TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
    requested_by         UUID NOT NULL REFERENCES users (id),
    requester_token_id   UUID,
    requester_mfa        BOOLEAN NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,
    completed_at         TIMESTAMPTZ,
    failure_code         TEXT,
    provider_version_id  TEXT,
    cloud_request_id     TEXT,
    FOREIGN KEY (organization_id, secret_id) REFERENCES secrets (organization_id, id),
    FOREIGN KEY (organization_id, connection_id) REFERENCES connections (organization_id, id),
    FOREIGN KEY (organization_id, environment_id) REFERENCES environments (organization_id, id),
    UNIQUE (organization_id, id),
    -- Create requests get their secret_id once the secret exists.
    CHECK (operation = 'create' OR secret_id IS NOT NULL),
    CHECK ((operation = 'delete') = (value_mac IS NULL))
);

-- At most one open change per secret (or per new secret name), so concurrent
-- edits cannot race each other.
CREATE UNIQUE INDEX change_requests_open_secret_idx ON change_requests (secret_id)
    WHERE status IN ('pending', 'approved', 'executing') AND secret_id IS NOT NULL;
CREATE UNIQUE INDEX change_requests_open_create_idx ON change_requests (connection_id, secret_name)
    WHERE status IN ('pending', 'approved', 'executing') AND operation = 'create';
CREATE INDEX change_requests_org_status_idx ON change_requests (organization_id, status, created_at DESC);
CREATE INDEX change_requests_expiry_idx ON change_requests (expires_at) WHERE status IN ('pending', 'approved');

CREATE TABLE approval_decisions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL,
    change_request_id   UUID NOT NULL,
    approver_id         UUID NOT NULL REFERENCES users (id),
    decision            TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    -- The binding hash the approver saw and approved.
    approved_hash       BYTEA NOT NULL CHECK (length(approved_hash) = 32),
    approver_mfa        BOOLEAN NOT NULL,
    approver_auth_time  TIMESTAMPTZ NOT NULL,
    comment             TEXT NOT NULL DEFAULT '' CHECK (length(comment) <= 1000),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, change_request_id) REFERENCES change_requests (organization_id, id),
    UNIQUE (change_request_id, approver_id)
);

-- Execution journal (ADR-0007): the intent row is committed before the
-- provider call; its id is the provider idempotency key.
CREATE TABLE execution_journal (
    id                   UUID PRIMARY KEY,
    organization_id      UUID NOT NULL,
    change_request_id    UUID NOT NULL UNIQUE,
    operation            TEXT NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('intent', 'completed', 'failed')),
    provider_request_id  TEXT,
    provider_version_id  TEXT,
    error_code           TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at         TIMESTAMPTZ,
    FOREIGN KEY (organization_id, change_request_id) REFERENCES change_requests (organization_id, id)
);

CREATE INDEX execution_journal_intent_idx ON execution_journal (created_at) WHERE status = 'intent';

-- ---- Audit ledger ----
--
-- One hash chain per organization: hash = SHA-256(prev_hash || canonical event).
-- audit_heads serializes appends. Events and checkpoints are append-only for
-- every role except the schema owner (triggers below); signed checkpoints make
-- tampering by the owner detectable.

CREATE TABLE audit_heads (
    organization_id  UUID PRIMARY KEY REFERENCES organizations (id),
    seq              BIGINT NOT NULL,
    hash             BYTEA NOT NULL CHECK (length(hash) = 32)
);

CREATE TABLE audit_events (
    organization_id    UUID NOT NULL REFERENCES organizations (id),
    seq                BIGINT NOT NULL CHECK (seq > 0),
    id                 UUID NOT NULL UNIQUE,
    occurred_at        TIMESTAMPTZ NOT NULL,
    actor_type         TEXT NOT NULL CHECK (actor_type IN ('user', 'api_token', 'system')),
    actor_id           UUID,
    actor_token_id     UUID,
    action             TEXT NOT NULL,
    resource_type      TEXT NOT NULL,
    resource_id        TEXT NOT NULL,
    decision           TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'none')),
    change_request_id  UUID,
    cloud_request_id   TEXT NOT NULL DEFAULT '',
    details            JSONB NOT NULL DEFAULT '{}',
    prev_hash          BYTEA NOT NULL CHECK (length(prev_hash) = 32),
    hash               BYTEA NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (organization_id, seq)
);

CREATE TABLE audit_checkpoints (
    organization_id  UUID NOT NULL REFERENCES organizations (id),
    seq              BIGINT NOT NULL,
    head_hash        BYTEA NOT NULL CHECK (length(head_hash) = 32),
    created_at       TIMESTAMPTZ NOT NULL,
    key_id           TEXT NOT NULL,
    signature        BYTEA NOT NULL,
    PRIMARY KEY (organization_id, seq)
);

-- +goose StatementBegin
CREATE FUNCTION secretmesh_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION secretmesh_append_only();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION secretmesh_append_only();
CREATE TRIGGER audit_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION secretmesh_append_only();
CREATE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION secretmesh_append_only();

-- ---- Row-Level Security ----

ALTER TABLE environments       ENABLE ROW LEVEL SECURITY;
ALTER TABLE connections        ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets            ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_bindings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_policies  ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_requests    ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_journal  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_heads        ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints  ENABLE ROW LEVEL SECURITY;

CREATE POLICY environments_tenant ON environments FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY connections_tenant ON connections FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY secrets_tenant ON secrets FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY role_bindings_tenant ON role_bindings FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY approval_policies_tenant ON approval_policies FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY change_requests_tenant ON change_requests FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY approval_decisions_tenant ON approval_decisions FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY execution_journal_tenant ON execution_journal FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_heads_tenant ON audit_heads FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id())) WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_events_select ON audit_events FOR SELECT
    USING (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_events_insert ON audit_events FOR INSERT
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_checkpoints_select ON audit_checkpoints FOR SELECT
    USING (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_checkpoints_insert ON audit_checkpoints FOR INSERT
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));

-- ---- Pre-tenant lookups (SECURITY DEFINER, ADR-0008) ----

-- Invitation acceptance moves to the application, so that each membership is
-- created together with its audit event under the organization's scope. This
-- function only finds the candidate invitations.
DROP FUNCTION secretmesh_accept_invitations(UUID);

-- +goose StatementBegin
CREATE FUNCTION secretmesh_open_invitations(p_user_id UUID)
RETURNS TABLE (organization_id UUID, invitation_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT i.organization_id, i.id
    FROM public.invitations i
    JOIN public.users u ON lower(i.email) = lower(u.email)
    WHERE u.id = p_user_id AND u.email_verified AND u.status = 'active'
      AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now();
$$;
-- +goose StatementEnd

-- Background jobs find due work across tenants, then process each item
-- under its own organization's scope. These return identifiers only.

-- +goose StatementBegin
CREATE FUNCTION secretmesh_expired_change_requests(p_limit INTEGER)
RETURNS TABLE (organization_id UUID, change_request_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.organization_id, c.id FROM public.change_requests c
    WHERE c.status IN ('pending', 'approved') AND c.expires_at <= now()
    ORDER BY c.expires_at LIMIT p_limit;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION secretmesh_stale_executions(p_older_than INTERVAL, p_limit INTEGER)
RETURNS TABLE (organization_id UUID, change_request_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT j.organization_id, j.change_request_id FROM public.execution_journal j
    WHERE j.status = 'intent' AND j.created_at < now() - p_older_than
    ORDER BY j.created_at LIMIT p_limit;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION secretmesh_audit_checkpoints_due()
RETURNS TABLE (organization_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT h.organization_id FROM public.audit_heads h
    WHERE h.seq > coalesce((SELECT max(c.seq) FROM public.audit_checkpoints c
                            WHERE c.organization_id = h.organization_id), 0);
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION secretmesh_audit_checkpoints_due();
DROP FUNCTION secretmesh_stale_executions(INTERVAL, INTEGER);
DROP FUNCTION secretmesh_expired_change_requests(INTEGER);
DROP FUNCTION secretmesh_open_invitations(UUID);

-- +goose StatementBegin
CREATE FUNCTION secretmesh_accept_invitations(p_user_id UUID)
RETURNS INTEGER
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH u AS (
        SELECT id, email FROM public.users
        WHERE id = p_user_id AND email_verified AND status = 'active'
    ), accepted AS (
        UPDATE public.invitations i
        SET accepted_at = now(), accepted_by = u.id
        FROM u
        WHERE lower(i.email) = lower(u.email)
          AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
        RETURNING i.organization_id, i.role, u.id AS user_id
    ), inserted AS (
        INSERT INTO public.memberships (organization_id, user_id, role)
        SELECT organization_id, user_id, role FROM accepted
        ON CONFLICT (organization_id, user_id) DO NOTHING
        RETURNING 1
    )
    SELECT count(*)::integer FROM inserted;
$$;
-- +goose StatementEnd

DROP TABLE audit_checkpoints;
DROP TABLE audit_events;
DROP TABLE audit_heads;
DROP FUNCTION secretmesh_append_only();
DROP TABLE execution_journal;
DROP TABLE approval_decisions;
DROP TABLE change_requests;
DROP TABLE approval_policies;
DROP TABLE role_bindings;
DROP TABLE secrets;
DROP TABLE connections;
DROP TABLE environments;
