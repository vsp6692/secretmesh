package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Scope is the tenant context applied to queries through Row-Level Security.
// A zero field leaves the corresponding setting empty, which matches no rows.
type Scope struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
}

type scopeKey struct{}

// WithScope returns ctx carrying s. Only authentication middleware and
// trusted system paths (bootstrap, login) may call it, and only with
// identifiers taken from a verified identity.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFrom returns the scope in ctx, or the zero scope.
func ScopeFrom(ctx context.Context) Scope {
	s, _ := ctx.Value(scopeKey{}).(Scope)
	return s
}

// Tx runs fn in a transaction with the scope from ctx applied. The settings are
// transaction-local, so they cannot leak to other users of a pooled connection.
// fn's error, or a commit failure, is returned; the transaction is rolled back
// on error.
func Tx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := SetScope(ctx, tx, ScopeFrom(ctx)); err != nil {
			return err
		}
		return fn(tx)
	})
}

// SetScope applies s to the current transaction. It is exported for the few
// paths that learn the identity mid-transaction (session lookup).
func SetScope(ctx context.Context, tx pgx.Tx, s Scope) error {
	_, err := tx.Exec(ctx,
		`SELECT set_config('secretmesh.user_id', $1, true), set_config('secretmesh.organization_id', $2, true)`,
		uuidSetting(s.UserID), uuidSetting(s.OrganizationID))
	if err != nil {
		return fmt.Errorf("set tenant scope: %w", err)
	}
	return nil
}

func uuidSetting(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// ErrUnsafeRole is returned by CheckRuntimeRole.
var ErrUnsafeRole = errors.New("unsafe database role")

// CheckRuntimeRole refuses database roles that would silently disable
// Row-Level Security: superusers, roles with BYPASSRLS and table owners.
func CheckRuntimeRole(ctx context.Context, pool *pgxpool.Pool) error {
	var super, bypass bool
	var owned int
	err := pool.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolbypassrls,
		       (SELECT count(*) FROM pg_catalog.pg_class c
		        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		          AND pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE'))
		FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &owned)
	if err != nil {
		return fmt.Errorf("check database role: %w", err)
	}
	switch {
	case super:
		return fmt.Errorf("%w: runtime role is a superuser", ErrUnsafeRole)
	case bypass:
		return fmt.Errorf("%w: runtime role has BYPASSRLS", ErrUnsafeRole)
	case owned > 0:
		return fmt.Errorf("%w: runtime role owns (or is a member of the owner of) %d tables", ErrUnsafeRole, owned)
	}
	return nil
}
