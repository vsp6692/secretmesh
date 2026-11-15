// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package postgres opens connection pools and applies schema migrations.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/secretmesh/secretmesh/migrations"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// Connect opens a pool and verifies connectivity.
func Connect(ctx context.Context, url sensitive.Value) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url.RevealString())
	if err != nil {
		// pgx parse errors can echo the connection string; do not wrap them.
		return nil, fmt.Errorf("invalid database URL")
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations. url must connect as the schema owner.
func Migrate(ctx context.Context, url sensitive.Value, logger *slog.Logger) error {
	pool, err := Connect(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()

	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	return MigrateDB(ctx, db, logger)
}

// MigrateDB applies all pending migrations using an existing connection.
func MigrateDB(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	for _, r := range results {
		logger.InfoContext(ctx, "migration applied", "version", r.Source.Version, "duration_ms", r.Duration.Milliseconds())
	}

	// Job queue schema (ADR-0005), versioned by River itself.
	migrator, err := rivermigrate.New(riverdatabasesql.New(db), nil)
	if err != nil {
		return fmt.Errorf("job queue migrator: %w", err)
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return fmt.Errorf("apply job queue migrations: %w", err)
	}
	for _, v := range res.Versions {
		logger.InfoContext(ctx, "job queue migration applied", "version", v.Version)
	}
	return nil
}
