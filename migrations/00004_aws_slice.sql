-- SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

-- +goose Up

-- M3: provider discovery, break-glass changes and off-database audit export
-- (ADR-0010).

-- Discovered secrets without a secretmesh:environment tag land here.
ALTER TABLE connections ADD COLUMN default_environment_id UUID;
ALTER TABLE connections ADD CONSTRAINT connections_default_environment_fk
    FOREIGN KEY (organization_id, default_environment_id) REFERENCES environments (organization_id, id);
ALTER TABLE connections ADD COLUMN last_synced_at TIMESTAMPTZ;
ALTER TABLE connections ADD COLUMN last_sync_error TEXT;

-- Non-secret provider metadata (description, tags, KMS key, rotation state).
ALTER TABLE secrets
    ADD COLUMN origin TEXT NOT NULL DEFAULT 'created' CHECK (origin IN ('created', 'discovered')),
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    ADD COLUMN tags JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN provider_metadata JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN last_seen_at TIMESTAMPTZ;

CREATE UNIQUE INDEX secrets_active_ref_idx ON secrets (connection_id, provider_ref) WHERE status = 'active';

-- Break-glass: an emergency change without prior approval, by a holder of the
-- break_glass role with an MFA session and a written justification.
ALTER TABLE change_requests ADD COLUMN break_glass BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE role_bindings DROP CONSTRAINT role_bindings_role_check;
ALTER TABLE role_bindings ADD CONSTRAINT role_bindings_role_check CHECK (role IN
    ('cloud_admin', 'security_admin', 'secret_admin', 'developer', 'approver', 'auditor', 'break_glass'));

-- Audit batches exported to write-once storage (S3 Object Lock). Each covers
-- events up to a signed checkpoint.
CREATE TABLE audit_exports (
    organization_id  UUID NOT NULL REFERENCES organizations (id),
    from_seq         BIGINT NOT NULL,
    to_seq           BIGINT NOT NULL,
    location         TEXT NOT NULL,
    object_version   TEXT NOT NULL DEFAULT '',
    retain_until     TIMESTAMPTZ NOT NULL,
    exported_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, to_seq),
    CHECK (from_seq >= 1 AND to_seq >= from_seq)
);

ALTER TABLE audit_exports ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_exports_select ON audit_exports FOR SELECT
    USING (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY audit_exports_insert ON audit_exports FOR INSERT
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE TRIGGER audit_exports_append_only BEFORE UPDATE OR DELETE ON audit_exports
    FOR EACH ROW EXECUTE FUNCTION secretmesh_append_only();

-- +goose StatementBegin
CREATE FUNCTION secretmesh_audit_exports_due()
RETURNS TABLE (organization_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.organization_id FROM public.audit_checkpoints c
    GROUP BY c.organization_id
    HAVING max(c.seq) > coalesce((SELECT max(e.to_seq) FROM public.audit_exports e
                                  WHERE e.organization_id = c.organization_id), 0);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION secretmesh_connections_to_sync(p_older_than INTERVAL)
RETURNS TABLE (organization_id UUID, connection_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.organization_id, c.id FROM public.connections c
    WHERE c.status = 'active' AND c.provider <> 'fake'
      AND (c.last_synced_at IS NULL OR c.last_synced_at < now() - p_older_than);
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION secretmesh_connections_to_sync(INTERVAL);
DROP FUNCTION secretmesh_audit_exports_due();
DROP TABLE audit_exports;
ALTER TABLE role_bindings DROP CONSTRAINT role_bindings_role_check;
ALTER TABLE role_bindings ADD CONSTRAINT role_bindings_role_check CHECK (role IN
    ('cloud_admin', 'security_admin', 'secret_admin', 'developer', 'approver', 'auditor'));
ALTER TABLE change_requests DROP COLUMN break_glass;
DROP INDEX secrets_active_ref_idx;
ALTER TABLE secrets DROP COLUMN last_seen_at, DROP COLUMN provider_metadata, DROP COLUMN tags,
    DROP COLUMN description, DROP COLUMN origin;
ALTER TABLE connections DROP COLUMN last_sync_error, DROP COLUMN last_synced_at;
ALTER TABLE connections DROP CONSTRAINT connections_default_environment_fk;
ALTER TABLE connections DROP COLUMN default_environment_id;
