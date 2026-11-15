-- SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

-- +goose Up

-- Tenant-owned tables carry organization_id from day one; Row-Level Security
-- policies are added in M1. The application connects as a role that does not
-- own these tables and has no BYPASSRLS (see deployments/docker/postgres/init.sql).

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug        TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users are global identities; organization access is granted via memberships.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer          TEXT NOT NULL,
    subject         TEXT NOT NULL,
    email           TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    display_name    TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    UNIQUE (issuer, subject)
);

CREATE INDEX users_email_idx ON users (lower(email));

CREATE TABLE memberships (
    organization_id  UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role             TEXT NOT NULL CHECK (role IN ('org_admin', 'member')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX memberships_user_idx ON memberships (user_id);

-- Only SHA-256 hashes of session tokens are stored.
CREATE TABLE sessions (
    id_hash     BYTEA PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Single-use OIDC authorization request state, valid for a few minutes.
CREATE TABLE oidc_login_states (
    state_hash     BYTEA PRIMARY KEY CHECK (length(state_hash) = 32),
    nonce          TEXT NOT NULL,
    code_verifier  TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX oidc_login_states_expires_idx ON oidc_login_states (expires_at);

-- +goose Down

DROP TABLE oidc_login_states;
DROP TABLE sessions;
DROP TABLE memberships;
DROP TABLE users;
DROP TABLE organizations;
