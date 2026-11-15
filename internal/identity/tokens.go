package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// TokenPrefix marks SecretMesh API tokens so that secret scanners can find
// leaked ones (see .gitleaks.toml).
const TokenPrefix = "smt_"

// MaxTokenLifetime bounds API token expiry.
const MaxTokenLifetime = 365 * 24 * time.Hour

// APIToken is API token metadata. The token itself is shown once at creation.
type APIToken struct {
	ID            uuid.UUID
	Name          string
	DisplayPrefix string
	Scopes        []auth.Permission
	CreatedBy     uuid.UUID
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastUsedAt    *time.Time
}

// ErrTokenNotFound is returned when a token does not exist in the organization.
var ErrTokenNotFound = errors.New("api token not found")

// CreateToken issues a token for the organization in ctx's tenant scope.
// The caller must have checked that creator may grant scopes.
func (s *Store) CreateToken(ctx context.Context, orgID, creator uuid.UUID, name string, scopes []auth.Permission, lifetime time.Duration) (APIToken, sensitive.Value, error) {
	if lifetime <= 0 || lifetime > MaxTokenLifetime {
		return APIToken{}, sensitive.Value{}, fmt.Errorf("token lifetime out of range")
	}
	secret := TokenPrefix + randomToken()
	t := APIToken{
		Name:          name,
		DisplayPrefix: secret[:len(TokenPrefix)+6],
		Scopes:        scopes,
		CreatedBy:     creator,
	}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO api_tokens (organization_id, name, token_hash, display_prefix, scopes, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
			RETURNING id, created_at, expires_at`,
			orgID, name, hashToken(secret), t.DisplayPrefix, scopes, creator, lifetime.Seconds(),
		).Scan(&t.ID, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return err
		}
		scopeList := make([]string, len(scopes))
		for i, sc := range scopes {
			scopeList[i] = string(sc)
		}
		_, err := audit.Append(ctx, tx, orgID, audit.Event{
			Action: "api_token.created", ResourceType: "api_token", ResourceID: t.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"name": name, "scopes": strings.Join(scopeList, ","), "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)},
		})
		return err
	})
	if err != nil {
		return APIToken{}, sensitive.Value{}, fmt.Errorf("create api token: %w", err)
	}
	return t, sensitive.FromString(secret), nil
}

// ListTokens returns the organization's active (unrevoked, unexpired) tokens.
func (s *Store) ListTokens(ctx context.Context, orgID uuid.UUID) ([]APIToken, error) {
	var out []APIToken
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, name, display_prefix, scopes, created_by, created_at, expires_at, last_used_at
			FROM api_tokens
			WHERE organization_id = $1 AND revoked_at IS NULL AND expires_at > now()
			ORDER BY created_at DESC`, orgID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (APIToken, error) {
			var t APIToken
			err := row.Scan(&t.ID, &t.Name, &t.DisplayPrefix, &t.Scopes, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt)
			return t, err
		})
		return err
	})
	return out, err
}

// RevokeToken revokes an active token of the organization.
func (s *Store) RevokeToken(ctx context.Context, orgID, tokenID uuid.UUID) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE api_tokens SET revoked_at = now()
			WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL`, orgID, tokenID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrTokenNotFound
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "api_token.revoked", ResourceType: "api_token", ResourceID: tokenID.String(), Decision: audit.Allow,
		})
		return err
	})
}

// authenticateToken resolves a presented bearer token to a principal.
func (s *Store) authenticateToken(ctx context.Context, presented string) (auth.Principal, error) {
	if !strings.HasPrefix(presented, TokenPrefix) || len(presented) > 128 {
		return auth.Principal{}, errNotFound
	}
	p := auth.Principal{Kind: auth.KindAPIToken}
	var role string
	var scopes []string
	err := s.pool.QueryRow(ctx, `
		SELECT token_id, organization_id, created_by, creator_role, scopes
		FROM secretmesh_authenticate_api_token($1)`, hashToken(presented),
	).Scan(&p.TokenID, &p.TokenOrgID, &p.UserID, &role, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Principal{}, errNotFound
	}
	if err != nil {
		return auth.Principal{}, err
	}
	p.CreatorRole = auth.Role(role)
	for _, sc := range scopes {
		p.TokenScopes = append(p.TokenScopes, auth.Permission(sc))
	}
	return p, nil
}
