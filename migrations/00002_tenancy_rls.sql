-- +goose Up

-- Row-Level Security and tenant context (ADR-0002, ADR-0008).
--
-- The runtime role sets two transaction-local settings from the verified
-- identity: secretmesh.user_id and secretmesh.organization_id. When a setting
-- is absent the helper functions return NULL and every policy matches nothing.

CREATE FUNCTION secretmesh_user_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT nullif(current_setting('secretmesh.user_id', true), '')::uuid $$;

CREATE FUNCTION secretmesh_org_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT nullif(current_setting('secretmesh.organization_id', true), '')::uuid $$;

-- ---- Schema changes ----

ALTER TABLE organizations ADD COLUMN require_mfa BOOLEAN NOT NULL DEFAULT false;

-- auth_time is NULL when the identity provider did not report it; such
-- sessions can never satisfy step-up.
ALTER TABLE sessions
    ADD COLUMN auth_time TIMESTAMPTZ,
    ADD COLUMN mfa BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE oidc_login_states
    ADD COLUMN step_up BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN return_to TEXT NOT NULL DEFAULT '/',
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE invitations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email            TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND position('@' IN email) > 1),
    role             TEXT NOT NULL CHECK (role IN ('org_admin', 'member')),
    invited_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    accepted_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    revoked_at       TIMESTAMPTZ
);

-- At most one open invitation per email and organization.
CREATE UNIQUE INDEX invitations_open_idx ON invitations (organization_id, lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_email_idx ON invitations (lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Only SHA-256 hashes of API tokens are stored.
CREATE TABLE api_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    token_hash       BYTEA NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Non-secret leading characters, shown so users can recognise a token.
    display_prefix   TEXT NOT NULL CHECK (length(display_prefix) <= 16),
    scopes           TEXT[] NOT NULL CHECK (cardinality(scopes) > 0),
    created_by       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    last_used_at     TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX api_tokens_org_idx ON api_tokens (organization_id);

-- ---- Row-Level Security ----

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships   ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens    ENABLE ROW LEVEL SECURITY;

-- Memberships: a user sees their own memberships; an organization sees and
-- manages its members. Policies on other tables build on this one, so it must
-- not reference them.
CREATE POLICY memberships_select ON memberships FOR SELECT
    USING (organization_id = (SELECT secretmesh_org_id()) OR user_id = (SELECT secretmesh_user_id()));
CREATE POLICY memberships_insert ON memberships FOR INSERT
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY memberships_update ON memberships FOR UPDATE
    USING (organization_id = (SELECT secretmesh_org_id()))
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));
CREATE POLICY memberships_delete ON memberships FOR DELETE
    USING (organization_id = (SELECT secretmesh_org_id()));

-- Organizations: visible as the current organization or through the current
-- user's memberships; only the current organization can be modified. Creation
-- goes through secretmesh_ensure_organization.
CREATE POLICY organizations_select ON organizations FOR SELECT
    USING (id = (SELECT secretmesh_org_id())
        OR id IN (SELECT m.organization_id FROM memberships m WHERE m.user_id = (SELECT secretmesh_user_id())));
CREATE POLICY organizations_update ON organizations FOR UPDATE
    USING (id = (SELECT secretmesh_org_id()))
    WITH CHECK (id = (SELECT secretmesh_org_id()));

-- Users: visible to themselves and to organizations they belong to. Writes go
-- through secretmesh_login_user.
CREATE POLICY users_select ON users FOR SELECT
    USING (id = (SELECT secretmesh_user_id())
        OR EXISTS (SELECT 1 FROM memberships m
                   WHERE m.user_id = users.id AND m.organization_id = (SELECT secretmesh_org_id())));

CREATE POLICY invitations_tenant ON invitations FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id()))
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));

CREATE POLICY api_tokens_tenant ON api_tokens FOR ALL
    USING (organization_id = (SELECT secretmesh_org_id()))
    WITH CHECK (organization_id = (SELECT secretmesh_org_id()));

-- ---- Pre-tenant lookups (SECURITY DEFINER, ADR-0008) ----
--
-- These run as the schema owner, which bypasses RLS. Keep them narrow, with a
-- fixed search_path and schema-qualified names.

-- Creates or refreshes the user identified by (issuer, subject) after a
-- successful OIDC login.
-- +goose StatementBegin
CREATE FUNCTION secretmesh_login_user(
    p_issuer TEXT, p_subject TEXT, p_email TEXT, p_email_verified BOOLEAN, p_display_name TEXT)
RETURNS TABLE (user_id UUID, user_status TEXT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO public.users AS u (issuer, subject, email, email_verified, display_name, last_login_at)
    VALUES (p_issuer, p_subject, p_email, p_email_verified, p_display_name, now())
    ON CONFLICT (issuer, subject) DO UPDATE SET
        email          = EXCLUDED.email,
        email_verified = EXCLUDED.email_verified,
        display_name   = EXCLUDED.display_name,
        last_login_at  = now(),
        updated_at     = now()
    RETURNING u.id, u.status;
$$;
-- +goose StatementEnd

-- Converts open invitations for the user's verified email into memberships.
-- Returns the number of memberships created.
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

-- Resolves a presented API token hash to its organization, creator and the
-- creator's current role. Returns no row if the token is revoked or expired,
-- the creator is disabled or no longer a member, or the organization is not
-- active.
-- +goose StatementBegin
CREATE FUNCTION secretmesh_authenticate_api_token(p_token_hash BYTEA)
RETURNS TABLE (token_id UUID, organization_id UUID, created_by UUID, creator_role TEXT, scopes TEXT[])
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.id, t.organization_id, t.created_by, m.role, t.scopes
    FROM public.api_tokens t
    JOIN public.organizations o ON o.id = t.organization_id AND o.status = 'active'
    JOIN public.users u ON u.id = t.created_by AND u.status = 'active'
    JOIN public.memberships m ON m.organization_id = t.organization_id AND m.user_id = t.created_by
    WHERE t.token_hash = p_token_hash AND t.revoked_at IS NULL AND t.expires_at > now();

    IF FOUND THEN
        -- Coarse last-use tracking; at most one write per token per minute.
        UPDATE public.api_tokens SET last_used_at = now()
        WHERE token_hash = p_token_hash
          AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');
    END IF;
END;
$$;
-- +goose StatementEnd

-- Creates the organization if no organization has the slug. An existing
-- organization keeps its name. Used for the configured bootstrap organization.
-- +goose StatementBegin
CREATE FUNCTION secretmesh_ensure_organization(p_slug TEXT, p_name TEXT)
RETURNS TABLE (organization_id UUID, organization_name TEXT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO public.organizations AS o (slug, name) VALUES (p_slug, p_name)
    ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug
    RETURNING o.id, o.name;
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION secretmesh_ensure_organization(TEXT, TEXT);
DROP FUNCTION secretmesh_authenticate_api_token(BYTEA);
DROP FUNCTION secretmesh_accept_invitations(UUID);
DROP FUNCTION secretmesh_login_user(TEXT, TEXT, TEXT, BOOLEAN, TEXT);

DROP POLICY api_tokens_tenant ON api_tokens;
DROP POLICY invitations_tenant ON invitations;
DROP POLICY users_select ON users;
DROP POLICY organizations_update ON organizations;
DROP POLICY organizations_select ON organizations;
DROP POLICY memberships_delete ON memberships;
DROP POLICY memberships_update ON memberships;
DROP POLICY memberships_insert ON memberships;
DROP POLICY memberships_select ON memberships;

ALTER TABLE memberships   DISABLE ROW LEVEL SECURITY;
ALTER TABLE users         DISABLE ROW LEVEL SECURITY;
ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;

DROP TABLE api_tokens;
DROP TABLE invitations;

ALTER TABLE oidc_login_states DROP COLUMN created_at, DROP COLUMN return_to, DROP COLUMN step_up;
ALTER TABLE sessions DROP COLUMN mfa, DROP COLUMN auth_time;
ALTER TABLE organizations DROP COLUMN require_mfa;

DROP FUNCTION secretmesh_org_id();
DROP FUNCTION secretmesh_user_id();
