// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package pgtest provisions an isolated, migrated PostgreSQL database per test.
//
// Tests using it are skipped unless SECRETMESH_TEST_DATABASE_URL points to a
// server where the connecting role may create databases and roles.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// DB is a throwaway database with the same role split as production
// (deployments/docker/postgres/init.sql).
type DB struct {
	// App connects as the runtime role: DML only, NOBYPASSRLS, owns nothing.
	App *pgxpool.Pool
	// Owner connects as the schema owner and bypasses RLS. Use it only to
	// arrange or inspect state, never as the system under test.
	Owner *pgxpool.Pool
}

// New creates a fresh database and roles, applies migrations as the owner and
// returns pools for both roles. Everything is dropped when the test finishes.
func New(t testing.TB) *DB {
	t.Helper()

	url := os.Getenv("SECRETMESH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SECRETMESH_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := "sm_test_" + randomHex(6)
	owner, app := name+"_owner", name+"_app"
	ownerPass, appPass := randomHex(16), randomHex(16)

	// DDL cannot be parameterized. Names and passwords are random hex; names
	// are additionally quoted via pgx.Identifier.
	q := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	server, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	exec(ctx, t, server,
		"CREATE ROLE "+q(owner)+" LOGIN PASSWORD '"+ownerPass+"'",
		"CREATE ROLE "+q(app)+" LOGIN PASSWORD '"+appPass+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS",
		"CREATE DATABASE "+q(name)+" OWNER "+q(owner),
	)

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	cfg.ConnConfig.Database = name
	// Keep in sync with deployments/docker/postgres/init.sql.
	exec(ctx, t, cfg.ConnConfig,
		"ALTER SCHEMA public OWNER TO "+q(owner),
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
		"GRANT USAGE ON SCHEMA public TO "+q(app),
		"ALTER DEFAULT PRIVILEGES FOR ROLE "+q(owner)+" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "+q(app),
		"ALTER DEFAULT PRIVILEGES FOR ROLE "+q(owner)+" IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "+q(app),
		"ALTER DEFAULT PRIVILEGES FOR ROLE "+q(owner)+" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
		"ALTER DEFAULT PRIVILEGES FOR ROLE "+q(owner)+" IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO "+q(app),
	)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		exec(ctx, t, server,
			"DROP DATABASE IF EXISTS "+q(name)+" WITH (FORCE)",
			"DROP ROLE IF EXISTS "+q(app),
			"DROP ROLE IF EXISTS "+q(owner),
		)
	})

	ownerPool := pool(ctx, t, cfg, owner, ownerPass)
	appPool := pool(ctx, t, cfg, app, appPass)

	db := stdlib.OpenDBFromPool(ownerPool)
	defer func() { _ = db.Close() }()
	if err := postgres.MigrateDB(ctx, db, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	return &DB{App: appPool, Owner: ownerPool}
}

func pool(ctx context.Context, t testing.TB, base *pgxpool.Config, user, password string) *pgxpool.Pool {
	t.Helper()
	cfg := base.Copy()
	cfg.ConnConfig.User = user
	cfg.ConnConfig.Password = password
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open %s pool: %v", user, err)
	}
	// Registered after the drop cleanup, so it runs first (LIFO).
	t.Cleanup(p.Close)
	return p
}

func exec(ctx context.Context, t testing.TB, cfg *pgx.ConnConfig, stmts ...string) {
	t.Helper()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to test server: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	for _, s := range stmts {
		// nosemgrep: go.lang.security.audit.sqli.pgx-sqli.pgx-sqli
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("test database setup: %v", err)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
