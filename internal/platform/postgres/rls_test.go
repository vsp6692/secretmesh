// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/platform/postgres/pgtest"
)

// Tables without RLS. They must not hold tenant data: sessions and login
// states are pre-tenant, and River's job tables carry only identifiers
// (ADR-0005), never secret values.
var noRLS = []string{
	"goose_db_version", "sessions", "oidc_login_states",
	"river_job", "river_migration", "river_queue", "river_leader", "river_notification",
	"river_client", "river_client_queue",
}

// Tenant tables checked by the isolation tests. Keep in sync with migrations.
var tenantTables = []string{"organizations", "users", "memberships", "invitations", "api_tokens"}

func TestEveryTableHasRLS(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()

	rows, err := db.Owner.Query(ctx, `
		SELECT c.relname, c.relrowsecurity,
		       EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		t.Fatal(err)
	}
	type table struct {
		name        string
		rls, tenant bool
	}
	tables, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (table, error) {
		var tb table
		return tb, r.Scan(&tb.name, &tb.rls, &tb.tenant)
	})
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, tb := range tables {
		seen[tb.name] = true
		exempt := slices.Contains(noRLS, tb.name)
		switch {
		case exempt && tb.tenant:
			t.Errorf("%s has organization_id but is exempt from RLS", tb.name)
		case !exempt && !tb.rls:
			t.Errorf("%s does not have Row-Level Security enabled", tb.name)
		}
	}
	for _, name := range tenantTables {
		if !seen[name] {
			t.Errorf("tenant table %s missing; update tenantTables", name)
		}
	}
}

func TestRuntimeRoleCheck(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()

	if err := postgres.CheckRuntimeRole(ctx, db.App); err != nil {
		t.Fatalf("app role rejected: %v", err)
	}
	if err := postgres.CheckRuntimeRole(ctx, db.Owner); !errors.Is(err, postgres.ErrUnsafeRole) {
		t.Fatalf("owner role accepted: %v", err)
	}
	if _, err := db.App.Exec(ctx, `ALTER TABLE organizations DISABLE ROW LEVEL SECURITY`); err == nil {
		t.Fatal("app role could disable RLS")
	}
}

type fixture struct {
	orgA, orgB    uuid.UUID
	userA, userB  uuid.UUID
	inviteB, tokB uuid.UUID
}

// arrange creates two organizations, each with one member, one invitation
// and one API token, using the owner role (which bypasses RLS).
func arrange(t *testing.T, owner *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	var f fixture
	q := func(sql string, args []any, dest ...any) {
		t.Helper()
		if err := owner.QueryRow(ctx, sql, args...).Scan(dest...); err != nil {
			t.Fatalf("arrange: %v", err)
		}
	}
	for _, x := range []struct {
		slug        string
		org, user   *uuid.UUID
		invite, tok *uuid.UUID
	}{
		{"org-a", &f.orgA, &f.userA, new(uuid.UUID), new(uuid.UUID)},
		{"org-b", &f.orgB, &f.userB, &f.inviteB, &f.tokB},
	} {
		q(`INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id`, []any{x.slug}, x.org)
		q(`INSERT INTO users (issuer, subject, email, email_verified) VALUES ('iss', $1, $1 || '@example.com', true) RETURNING id`,
			[]any{x.slug}, x.user)
		q(`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'org_admin') RETURNING user_id`,
			[]any{*x.org, *x.user}, new(uuid.UUID))
		q(`INSERT INTO invitations (organization_id, email, role, expires_at)
		   VALUES ($1, 'invitee-' || $2 || '@example.com', 'member', now() + interval '1 day') RETURNING id`,
			[]any{*x.org, x.slug}, x.invite)
		q(`INSERT INTO api_tokens (organization_id, name, token_hash, display_prefix, scopes, created_by, expires_at)
		   VALUES ($1, 't', sha256($2::bytea), 'smt_x', '{org:read}', $3, now() + interval '1 day') RETURNING id`,
			[]any{*x.org, x.slug, *x.user}, x.tok)
	}
	return f
}

// count returns the rows of table visible under scope.
func count(t *testing.T, pool *pgxpool.Pool, scope postgres.Scope, table string) int {
	t.Helper()
	var n int
	ctx := postgres.WithScope(context.Background(), scope)
	err := postgres.Tx(ctx, pool, func(tx pgx.Tx) error {
		// Table names come from the fixed tenantTables list.
		return tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n) // nosemgrep: go.lang.security.audit.sqli.pgx-sqli.pgx-sqli
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestTenantIsolation(t *testing.T) {
	db := pgtest.New(t)
	f := arrange(t, db.Owner)

	t.Run("no scope sees nothing", func(t *testing.T) {
		for _, table := range tenantTables {
			if n := count(t, db.App, postgres.Scope{}, table); n != 0 {
				t.Errorf("%s: %d rows visible without tenant scope", table, n)
			}
		}
	})

	t.Run("organization scope sees only its own rows", func(t *testing.T) {
		scope := postgres.Scope{OrganizationID: f.orgA}
		for _, table := range tenantTables {
			if n := count(t, db.App, scope, table); n != 1 {
				t.Errorf("%s: %d rows visible to org A, want 1", table, n)
			}
		}
	})

	t.Run("user scope sees only own memberships and organizations", func(t *testing.T) {
		scope := postgres.Scope{UserID: f.userA}
		want := map[string]int{"organizations": 1, "users": 1, "memberships": 1, "invitations": 0, "api_tokens": 0}
		for table, w := range want {
			if n := count(t, db.App, scope, table); n != w {
				t.Errorf("%s: %d rows visible to user A, want %d", table, n, w)
			}
		}
	})

	t.Run("cross-tenant writes fail closed", func(t *testing.T) {
		ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: f.orgA})

		// Updates and deletes of another tenant's rows match nothing.
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE invitations SET revoked_at = now() WHERE id = $1`, []any{f.inviteB}},
			{`UPDATE api_tokens SET revoked_at = now() WHERE id = $1`, []any{f.tokB}},
			{`UPDATE organizations SET require_mfa = true WHERE id = $1`, []any{f.orgB}},
			{`UPDATE memberships SET role = 'member' WHERE organization_id = $1`, []any{f.orgB}},
			{`DELETE FROM memberships WHERE organization_id = $1`, []any{f.orgB}},
			{`DELETE FROM api_tokens WHERE organization_id = $1`, []any{f.orgB}},
			{`UPDATE users SET display_name = 'pwned' WHERE id = $1`, []any{f.userB}},
		} {
			err := postgres.Tx(ctx, db.App, func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, stmt.sql, stmt.args...)
				if err == nil && tag.RowsAffected() != 0 {
					t.Errorf("%q affected %d rows of another tenant", stmt.sql, tag.RowsAffected())
				}
				return err
			})
			if err != nil {
				t.Errorf("%q: %v", stmt.sql, err)
			}
		}

		// Inserting rows into another tenant is rejected by WITH CHECK.
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'org_admin')`, []any{f.orgB, f.userA}},
			{`INSERT INTO invitations (organization_id, email, role, expires_at) VALUES ($1, 'x@example.com', 'org_admin', now() + interval '1 day')`, []any{f.orgB}},
			{`UPDATE memberships SET organization_id = $1 WHERE user_id = $2`, []any{f.orgB, f.userA}},
		} {
			err := postgres.Tx(ctx, db.App, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, stmt.sql, stmt.args...)
				return err
			})
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("%q: want RLS violation (42501), got %v", stmt.sql, err)
			}
		}

		// Organization B is untouched.
		var revoked bool
		var role string
		if err := db.Owner.QueryRow(context.Background(), `
			SELECT (SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id = $1),
			       (SELECT role FROM memberships WHERE organization_id = $2 AND user_id = $3)`,
			f.tokB, f.orgB, f.userB).Scan(&revoked, &role); err != nil {
			t.Fatal(err)
		}
		if revoked || role != "org_admin" {
			t.Fatalf("organization B was modified: revoked=%v role=%s", revoked, role)
		}
	})

	t.Run("scope does not leak to pooled connections", func(t *testing.T) {
		ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: f.orgA})
		if err := postgres.Tx(ctx, db.App, func(pgx.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		// Same pool, outside any scoped transaction.
		for range 5 {
			var n int
			if err := db.App.QueryRow(context.Background(), `SELECT count(*) FROM organizations`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatalf("tenant scope leaked: %d organizations visible", n)
			}
		}
	})
}
