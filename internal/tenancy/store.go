// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package tenancy manages organizations, memberships and invitations.
//
// Methods run under the tenant scope carried by ctx (postgres.Tx); with no
// scope, Row-Level Security hides every row.
package tenancy

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrLastAdmin     = errors.New("organization must keep at least one admin")
	ErrAlreadyMember = errors.New("user is already a member")
	ErrInvalidEmail  = errors.New("invalid email address")
)

type Organization struct {
	ID         uuid.UUID
	Name       string
	Slug       string
	RequireMFA bool
}

type Membership struct {
	Organization Organization
	Role         auth.Role
}

type Member struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
	Role        auth.Role
	JoinedAt    time.Time
}

type Invitation struct {
	ID        uuid.UUID
	Email     string
	Role      auth.Role
	InvitedBy *uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// EnsureOrganization creates the organization if no organization has slug.
// An existing organization keeps its current name.
func (s *Store) EnsureOrganization(ctx context.Context, slug, name string) (Organization, error) {
	o := Organization{Slug: slug}
	err := s.pool.QueryRow(ctx,
		`SELECT organization_id, organization_name FROM secretmesh_ensure_organization($1, $2)`,
		slug, name).Scan(&o.ID, &o.Name)
	if err != nil {
		return Organization{}, fmt.Errorf("ensure organization %q: %w", slug, err)
	}
	return o, nil
}

// Memberships lists the active organizations userID belongs to.
func (s *Store) Memberships(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	var out []Membership
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT o.id, o.name, o.slug, o.require_mfa, m.role
			FROM memberships m
			JOIN organizations o ON o.id = m.organization_id
			WHERE m.user_id = $1 AND o.status = 'active'
			ORDER BY o.name`,
			userID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Membership, error) {
			var m Membership
			o := &m.Organization
			err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.RequireMFA, &m.Role)
			return m, err
		})
		return err
	})
	return out, err
}

// Membership returns userID's membership in an active organization, or
// ErrNotFound. ctx must carry userID's scope.
func (s *Store) Membership(ctx context.Context, orgID, userID uuid.UUID) (Membership, error) {
	var m Membership
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		o := &m.Organization
		return tx.QueryRow(ctx, `
			SELECT o.id, o.name, o.slug, o.require_mfa, m.role
			FROM memberships m
			JOIN organizations o ON o.id = m.organization_id
			WHERE m.organization_id = $1 AND m.user_id = $2 AND o.status = 'active'`,
			orgID, userID).Scan(&o.ID, &o.Name, &o.Slug, &o.RequireMFA, &m.Role)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	return m, err
}

// Organization returns the organization in ctx's scope.
func (s *Store) Organization(ctx context.Context, orgID uuid.UUID) (Organization, error) {
	o := Organization{ID: orgID}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT name, slug, require_mfa FROM organizations WHERE id = $1 AND status = 'active'`,
			orgID).Scan(&o.Name, &o.Slug, &o.RequireMFA)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

func (s *Store) SetRequireMFA(ctx context.Context, orgID uuid.UUID, require bool) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE organizations SET require_mfa = $2, updated_at = now() WHERE id = $1`, orgID, require)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "organization.settings_changed", ResourceType: "organization", ResourceID: orgID.String(),
			Decision: audit.Allow, Details: map[string]string{"require_mfa": fmt.Sprint(require)},
		})
		return err
	})
}

// AddMember grants role to userID. An existing membership is left unchanged.
func (s *Store) AddMember(ctx context.Context, orgID, userID uuid.UUID, role auth.Role) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id, user_id) DO NOTHING`,
			orgID, userID, role)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "member.added", ResourceType: "user", ResourceID: userID.String(), Decision: audit.Allow,
			Details: map[string]string{"role": string(role)},
		})
		return err
	})
}

func (s *Store) Members(ctx context.Context, orgID uuid.UUID) ([]Member, error) {
	var out []Member
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id, u.email, u.display_name, m.role, m.created_at
			FROM memberships m
			JOIN users u ON u.id = m.user_id
			WHERE m.organization_id = $1
			ORDER BY lower(u.email)`, orgID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Member, error) {
			var m Member
			err := row.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Role, &m.JoinedAt)
			return m, err
		})
		return err
	})
	return out, err
}

// SetRole changes a member's role. Demoting the last admin fails with ErrLastAdmin.
func (s *Store) SetRole(ctx context.Context, orgID, userID uuid.UUID, role auth.Role) error {
	return s.changeMember(ctx, orgID, userID, audit.Event{
		Action: "member.role_changed", ResourceType: "user", ResourceID: userID.String(), Decision: audit.Allow,
		Details: map[string]string{"role": string(role)},
	}, func(tx pgx.Tx) (pgconn.CommandTag, error) {
		return tx.Exec(ctx, `
			UPDATE memberships SET role = $3 WHERE organization_id = $1 AND user_id = $2`,
			orgID, userID, role)
	})
}

// RemoveMember removes a member. Removing the last admin fails with ErrLastAdmin.
func (s *Store) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return s.changeMember(ctx, orgID, userID, audit.Event{
		Action: "member.removed", ResourceType: "user", ResourceID: userID.String(), Decision: audit.Allow,
	}, func(tx pgx.Tx) (pgconn.CommandTag, error) {
		return tx.Exec(ctx, `DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2`, orgID, userID)
	})
}

// changeMember applies change while holding the organization row lock, then
// verifies that an admin remains. The lock serializes concurrent changes, so
// two admins cannot demote each other at the same time.
func (s *Store) changeMember(ctx context.Context, orgID, userID uuid.UUID, ev audit.Event, change func(pgx.Tx) (pgconn.CommandTag, error)) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var locked uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		tag, err := change(tx)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		var admins int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM memberships WHERE organization_id = $1 AND role = 'org_admin'`,
			orgID).Scan(&admins); err != nil {
			return err
		}
		if admins == 0 {
			return ErrLastAdmin
		}
		_, err = audit.Append(ctx, tx, orgID, ev)
		return err
	})
}

// NormalizeEmail validates a bare email address and lower-cases it.
func NormalizeEmail(email string) (string, error) {
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != strings.TrimSpace(email) || len(a.Address) > 320 {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(a.Address), nil
}

// Invite creates an invitation, replacing any open invitation for the same
// email. It fails with ErrAlreadyMember if a member already has the email.
func (s *Store) Invite(ctx context.Context, orgID, invitedBy uuid.UUID, email string, role auth.Role, ttl time.Duration) (Invitation, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Invitation{}, err
	}
	inv := Invitation{Email: email, Role: role, InvitedBy: &invitedBy}
	err = postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
			               WHERE m.organization_id = $1 AND lower(u.email) = $2)`,
			orgID, email).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadyMember
		}
		if _, err := tx.Exec(ctx, `
			UPDATE invitations SET revoked_at = now()
			WHERE organization_id = $1 AND lower(email) = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
			orgID, email); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO invitations (organization_id, email, role, invited_by, expires_at)
			VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
			RETURNING id, created_at, expires_at`,
			orgID, email, role, invitedBy, ttl.Seconds()).Scan(&inv.ID, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, orgID, audit.Event{
			Action: "invitation.created", ResourceType: "invitation", ResourceID: inv.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"email": email, "role": string(role)},
		})
		return err
	})
	if err != nil {
		return Invitation{}, err
	}
	return inv, nil
}

// Invitations lists open, unexpired invitations.
func (s *Store) Invitations(ctx context.Context, orgID uuid.UUID) ([]Invitation, error) {
	var out []Invitation
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, email, role, invited_by, created_at, expires_at
			FROM invitations
			WHERE organization_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
			ORDER BY created_at DESC`, orgID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Invitation, error) {
			var i Invitation
			err := row.Scan(&i.ID, &i.Email, &i.Role, &i.InvitedBy, &i.CreatedAt, &i.ExpiresAt)
			return i, err
		})
		return err
	})
	return out, err
}

func (s *Store) RevokeInvitation(ctx context.Context, orgID, id uuid.UUID) error {
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE invitations SET revoked_at = now()
			WHERE organization_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
			orgID, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, orgID, audit.Event{
			Action: "invitation.revoked", ResourceType: "invitation", ResourceID: id.String(), Decision: audit.Allow,
		})
		return err
	})
}

// AcceptInvitations turns open invitations for the user's verified email into
// memberships. Candidates are found across organizations (ADR-0008); each is
// then accepted under its own organization's scope, together with its audit
// event. It returns the number of memberships created.
func (s *Store) AcceptInvitations(ctx context.Context, userID uuid.UUID) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT organization_id, invitation_id FROM secretmesh_open_invitations($1)`, userID)
	if err != nil {
		return 0, err
	}
	type candidate struct{ org, inv uuid.UUID }
	cands, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (candidate, error) {
		var c candidate
		return c, r.Scan(&c.org, &c.inv)
	})
	if err != nil {
		return 0, err
	}

	ctx = auth.WithPrincipal(ctx, auth.Principal{Kind: auth.KindUser, UserID: userID})
	n := 0
	for _, c := range cands {
		ctx := postgres.WithScope(ctx, postgres.Scope{OrganizationID: c.org})
		err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
			var role string
			err := tx.QueryRow(ctx, `
				UPDATE invitations SET accepted_at = now(), accepted_by = $3
				WHERE organization_id = $1 AND id = $2
				  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
				RETURNING role`, c.org, c.inv, userID).Scan(&role)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // accepted or revoked concurrently
			}
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, $3)
				ON CONFLICT (organization_id, user_id) DO NOTHING`, c.org, userID, role)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				n++
			}
			_, err = audit.Append(ctx, tx, c.org, audit.Event{
				Action: "invitation.accepted", ResourceType: "invitation", ResourceID: c.inv.String(), Decision: audit.Allow,
				Details: map[string]string{"role": role},
			})
			return err
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
