// Package inventory stores environments, cloud connections and secret
// metadata. It never stores secret values.
package inventory

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

type EnvironmentKind string

const (
	Development EnvironmentKind = "development"
	Staging     EnvironmentKind = "staging"
	Production  EnvironmentKind = "production"
)

func (k EnvironmentKind) Valid() bool { return k == Development || k == Staging || k == Production }

type Classification string

const (
	Internal     Classification = "internal"
	Confidential Classification = "confidential"
	Restricted   Classification = "restricted"
)

func (c Classification) Valid() bool { return c == Internal || c == Confidential || c == Restricted }

type Environment struct {
	ID        uuid.UUID
	Name      string
	Kind      EnvironmentKind
	CreatedAt time.Time
}

type Connection struct {
	ID       uuid.UUID
	Name     string
	Provider string
	Config   map[string]string
	Status   string
	// DefaultEnvironmentID receives discovered secrets without an
	// environment tag; nil means such secrets are not imported.
	DefaultEnvironmentID *uuid.UUID
	LastSyncedAt         *time.Time
	LastSyncError        *string
	CreatedAt            time.Time
}

const connectionColumns = `id, name, provider, config, status, default_environment_id, last_synced_at, last_sync_error, created_at`

func scanConnection(r pgx.Row) (Connection, error) {
	var c Connection
	err := r.Scan(&c.ID, &c.Name, &c.Provider, &c.Config, &c.Status, &c.DefaultEnvironmentID, &c.LastSyncedAt,
		&c.LastSyncError, &c.CreatedAt)
	return c, err
}

type Secret struct {
	ID              uuid.UUID
	ConnectionID    uuid.UUID
	EnvironmentID   uuid.UUID
	EnvironmentKind EnvironmentKind
	Name            string
	ProviderRef     string
	Classification  Classification
	CurrentVersion  *string
	Status          string
	Origin          string
	Description     string
	Tags            map[string]string
	// ProviderMetadata is non-secret provider state (KMS key, rotation, last change).
	ProviderMetadata map[string]string
	LastSeenAt       *time.Time
	OwnerUserID      *uuid.UUID
	LastRotatedAt    *time.Time
	// Rotation policy summary; nil without a policy.
	RotationStrategy *string
	RotationEnabled  *bool
	NextRotationAt   *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func mapErr(err error) error {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.As(err, &pg) && pg.Code == "23505":
		return ErrConflict
	}
	return err
}

func (s *Store) CreateEnvironment(ctx context.Context, org uuid.UUID, name string, kind EnvironmentKind) (Environment, error) {
	e := Environment{Name: name, Kind: kind}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO environments (organization_id, name, kind) VALUES ($1, $2, $3)
			RETURNING id, created_at`, org, name, kind).Scan(&e.ID, &e.CreatedAt); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "environment.created", ResourceType: "environment", ResourceID: e.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"name": name, "kind": string(kind)},
		})
		return err
	})
	return e, mapErr(err)
}

func (s *Store) Environments(ctx context.Context, org uuid.UUID) ([]Environment, error) {
	var out []Environment
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, kind, created_at FROM environments
			WHERE organization_id = $1 ORDER BY name`, org)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Environment, error) {
			var e Environment
			return e, r.Scan(&e.ID, &e.Name, &e.Kind, &e.CreatedAt)
		})
		return err
	})
	return out, err
}

func (s *Store) Environment(ctx context.Context, org, id uuid.UUID) (Environment, error) {
	e := Environment{ID: id}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name, kind, created_at FROM environments
			WHERE organization_id = $1 AND id = $2`, org, id).Scan(&e.Name, &e.Kind, &e.CreatedAt)
	})
	return e, mapErr(err)
}

// ErrUnknownEnvironment is returned for a default environment outside the organization.
var ErrUnknownEnvironment = errors.New("unknown environment")

func (s *Store) CreateConnection(ctx context.Context, org uuid.UUID, name, provider string, config map[string]string, defaultEnv *uuid.UUID) (Connection, error) {
	if config == nil {
		config = map[string]string{}
	}
	c := Connection{Name: name, Provider: provider, Config: config, Status: "active", DefaultEnvironmentID: defaultEnv}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO connections (organization_id, name, provider, config, default_environment_id) VALUES ($1, $2, $3, $4, $5)
			RETURNING id, created_at`, org, name, provider, config, defaultEnv).Scan(&c.ID, &c.CreatedAt); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23503" {
				return ErrUnknownEnvironment
			}
			return err
		}
		_, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "connection.created", ResourceType: "connection", ResourceID: c.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"name": name, "provider": provider},
		})
		return err
	})
	return c, mapErr(err)
}

func (s *Store) Connections(ctx context.Context, org uuid.UUID) ([]Connection, error) {
	var out []Connection
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+connectionColumns+` FROM connections
			WHERE organization_id = $1 ORDER BY name`, org)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connection, error) { return scanConnection(r) })
		return err
	})
	return out, err
}

// ConnectionTx reads an active connection within an existing transaction.
func ConnectionTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (Connection, error) {
	c, err := scanConnection(tx.QueryRow(ctx, `SELECT `+connectionColumns+` FROM connections
		WHERE organization_id = $1 AND id = $2 AND status = 'active'`, org, id))
	return c, mapErr(err)
}

func (s *Store) Connection(ctx context.Context, org, id uuid.UUID) (Connection, error) {
	var c Connection
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		c, err = ConnectionTx(ctx, tx, org, id)
		return err
	})
	return c, err
}

// Columns selected for secrets joined with their environment.
const inventoryColumns = `s.id, s.connection_id, s.environment_id, e.kind, s.name, s.provider_ref, s.classification,
	s.current_version, s.status, s.origin, s.description, s.tags, s.provider_metadata, s.last_seen_at,
	s.owner_user_id, s.last_rotated_at, p.strategy, p.enabled, p.next_rotation_at, s.created_at, s.updated_at`

// inventoryFrom joins what inventoryColumns needs.
const inventoryFrom = ` FROM secrets s JOIN environments e ON e.id = s.environment_id
	LEFT JOIN rotation_policies p ON p.secret_id = s.id`

func scanSecret(r pgx.Row) (Secret, error) {
	var s Secret
	err := r.Scan(&s.ID, &s.ConnectionID, &s.EnvironmentID, &s.EnvironmentKind, &s.Name, &s.ProviderRef,
		&s.Classification, &s.CurrentVersion, &s.Status, &s.Origin, &s.Description, &s.Tags, &s.ProviderMetadata,
		&s.LastSeenAt, &s.OwnerUserID, &s.LastRotatedAt, &s.RotationStrategy, &s.RotationEnabled, &s.NextRotationAt,
		&s.CreatedAt, &s.UpdatedAt)
	return s, err
}

// Secrets lists active secrets.
func (s *Store) Secrets(ctx context.Context, org uuid.UUID) ([]Secret, error) {
	var out []Secret
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+inventoryColumns+inventoryFrom+`
			WHERE s.organization_id = $1 AND s.status = 'active' ORDER BY s.name`, org)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Secret, error) { return scanSecret(r) })
		return err
	})
	return out, err
}

// SecretTx reads a secret (any status) within an existing transaction.
func SecretTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (Secret, error) {
	sec, err := scanSecret(tx.QueryRow(ctx, `SELECT `+inventoryColumns+inventoryFrom+`
		WHERE s.organization_id = $1 AND s.id = $2`, org, id))
	return sec, mapErr(err)
}

func (s *Store) Secret(ctx context.Context, org, id uuid.UUID) (Secret, error) {
	var sec Secret
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		sec, err = SecretTx(ctx, tx, org, id)
		return err
	})
	return sec, err
}

// MarkRotatedTx records that the secret's value changed at `at` (an approved
// update, a completed rotation, or a new version seen by discovery) and moves
// its rotation policy's next due date. version, if set, becomes current.
func MarkRotatedTx(ctx context.Context, tx pgx.Tx, org, secretID uuid.UUID, at time.Time, version string) error {
	if _, err := tx.Exec(ctx, `UPDATE secrets SET last_rotated_at = greatest(coalesce(last_rotated_at, $3), $3),
		current_version = coalesce(nullif($4, ''), current_version), updated_at = now()
		WHERE organization_id = $1 AND id = $2`, org, secretID, at, version); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE rotation_policies p SET next_rotation_at = s.last_rotated_at + make_interval(days => p.interval_days),
		updated_at = now()
		FROM secrets s WHERE s.organization_id = $1 AND s.id = $2 AND p.organization_id = $1 AND p.secret_id = s.id`, org, secretID)
	return err
}
