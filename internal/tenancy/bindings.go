package tenancy

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// ErrConflict is returned when an identical binding exists.
var ErrConflict = errors.New("already exists")

type RoleBinding struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Email         string
	Role          auth.BindingRole
	EnvironmentID *uuid.UUID
	CreatedBy     *uuid.UUID
	CreatedAt     time.Time
}

// Bindings returns userID's role bindings in org.
func (s *Store) Bindings(ctx context.Context, orgID, userID uuid.UUID) ([]auth.Binding, error) {
	var out []auth.Binding
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = BindingsTx(ctx, tx, orgID, userID)
		return err
	})
	return out, err
}

// BindingsTx reads userID's role bindings within an existing transaction.
func BindingsTx(ctx context.Context, tx pgx.Tx, orgID, userID uuid.UUID) ([]auth.Binding, error) {
	rows, err := tx.Query(ctx, `SELECT role, environment_id FROM role_bindings
		WHERE organization_id = $1 AND user_id = $2`, orgID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (auth.Binding, error) {
		var b auth.Binding
		var env *uuid.UUID
		err := r.Scan(&b.Role, &env)
		if env != nil {
			b.EnvironmentID = *env
		}
		return b, err
	})
}

func (s *Store) RoleBindings(ctx context.Context, orgID uuid.UUID) ([]RoleBinding, error) {
	var out []RoleBinding
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT b.id, b.user_id, u.email, b.role, b.environment_id, b.created_by, b.created_at
			FROM role_bindings b JOIN users u ON u.id = b.user_id
			WHERE b.organization_id = $1 ORDER BY lower(u.email), b.role`, orgID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (RoleBinding, error) {
			var b RoleBinding
			return b, r.Scan(&b.ID, &b.UserID, &b.Email, &b.Role, &b.EnvironmentID, &b.CreatedBy, &b.CreatedAt)
		})
		return err
	})
	return out, err
}

// AddBinding grants role to a member, organization-wide when env is uuid.Nil.
func (s *Store) AddBinding(ctx context.Context, orgID, userID uuid.UUID, role auth.BindingRole, env, createdBy uuid.UUID) (RoleBinding, error) {
	b := RoleBinding{UserID: userID, Role: role, CreatedBy: &createdBy}
	var envArg *uuid.UUID
	if env != uuid.Nil {
		envArg = &env
		b.EnvironmentID = &env
	}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO role_bindings (organization_id, user_id, role, environment_id, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
			orgID, userID, role, envArg, createdBy).Scan(&b.ID, &b.CreatedAt)
		if err != nil {
			return err
		}
		details := map[string]string{"role": string(role), "user_id": userID.String(), "environment_id": "*"}
		if envArg != nil {
			details["environment_id"] = env.String()
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "role_binding.created", ResourceType: "role_binding", ResourceID: b.ID.String(),
			Decision: audit.Allow, Details: details,
		})
		return err
	})
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && pg.Code == "23505":
		return RoleBinding{}, ErrConflict
	case errors.As(err, &pg) && pg.Code == "23503":
		return RoleBinding{}, ErrNotFound // not a member, or unknown environment
	}
	return b, err
}

func (s *Store) RemoveBinding(ctx context.Context, orgID, id uuid.UUID) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var role string
		var userID uuid.UUID
		err := tx.QueryRow(ctx, `DELETE FROM role_bindings WHERE organization_id = $1 AND id = $2
			RETURNING role, user_id`, orgID, id).Scan(&role, &userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "role_binding.removed", ResourceType: "role_binding", ResourceID: id.String(), Decision: audit.Allow,
			Details: map[string]string{"role": role, "user_id": userID.String()},
		})
		return err
	})
}
