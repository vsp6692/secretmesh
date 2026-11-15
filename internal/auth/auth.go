// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package auth defines who is calling (Principal), what they may do in an
// organization (Access) and the role/permission model. It has no
// dependencies on storage or transport.
package auth

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleOrgAdmin Role = "org_admin"
	RoleMember   Role = "member"
)

func (r Role) Valid() bool { return r == RoleOrgAdmin || r == RoleMember }

type Permission string

const (
	OrgRead      Permission = "org:read"
	OrgWrite     Permission = "org:write"
	MembersRead  Permission = "members:read"
	MembersWrite Permission = "members:write"
	TokensManage Permission = "tokens:manage"
)

var rolePermissions = map[Role][]Permission{
	RoleOrgAdmin: {OrgRead, OrgWrite, MembersRead, MembersWrite, TokensManage},
	RoleMember:   {OrgRead, MembersRead},
}

// Resource permissions come from role bindings, optionally scoped to one
// environment (ADR-0009). The organization role grants none of them, so even
// organization admins must bind themselves explicitly (separation of duties).
const (
	SecretRead       Permission = "secret.read"
	SecretCreate     Permission = "secret.create"
	SecretUpdate     Permission = "secret.update"
	SecretDelete     Permission = "secret.delete"
	ApprovalDecide   Permission = "approval.decide"
	AuditRead        Permission = "audit.read"
	PolicyManage     Permission = "policy.manage"
	ConnectionManage Permission = "connection.manage"
	// SecretReveal reads a secret's current value (separate from read, which
	// is metadata only).
	SecretReveal Permission = "secret.reveal"
	// SecretBreakGlass submits an emergency change without prior approval.
	SecretBreakGlass Permission = "secret.break_glass"
	// SecretManage sets a secret's owner and rotation policy and starts
	// rotations (ADR-0011).
	SecretManage Permission = "secret.manage"
	// NotificationsManage configures notification channels.
	NotificationsManage Permission = "notifications.manage"
)

// BindingRole is a role granted through a role binding.
type BindingRole string

const (
	RoleCloudAdmin    BindingRole = "cloud_admin"
	RoleSecurityAdmin BindingRole = "security_admin"
	RoleSecretAdmin   BindingRole = "secret_admin"
	RoleDeveloper     BindingRole = "developer"
	RoleApprover      BindingRole = "approver"
	RoleAuditor       BindingRole = "auditor"
	RoleBreakGlass    BindingRole = "break_glass"
)

var bindingPermissions = map[BindingRole][]Permission{
	RoleCloudAdmin:    {ConnectionManage, SecretRead},
	RoleSecurityAdmin: {PolicyManage, AuditRead, NotificationsManage},
	RoleSecretAdmin:   {SecretRead, SecretCreate, SecretUpdate, SecretDelete, SecretReveal, SecretManage},
	RoleDeveloper:     {SecretRead, SecretCreate, SecretUpdate},
	RoleApprover:      {SecretRead, ApprovalDecide},
	RoleAuditor:       {AuditRead, SecretRead},
	// Break-glass adds only the emergency path; the holder still needs a
	// role that permits the operation itself.
	RoleBreakGlass: {SecretBreakGlass},
}

func (r BindingRole) Valid() bool { _, ok := bindingPermissions[r]; return ok }

// RolesWith returns the binding roles that grant perm, for finding who to
// notify.
func RolesWith(perm Permission) []string {
	var out []string
	for r, perms := range bindingPermissions {
		if slices.Contains(perms, perm) {
			out = append(out, string(r))
		}
	}
	slices.Sort(out)
	return out
}

// Binding grants Role in one environment, or organization-wide when
// EnvironmentID is uuid.Nil.
type Binding struct {
	Role          BindingRole
	EnvironmentID uuid.UUID
}

// TokenScopes are the permissions an API token may be granted. Token
// management, approvals, policy and connection management are excluded:
// they require a person with a session.
var TokenScopes = []Permission{OrgRead, OrgWrite, MembersRead, MembersWrite, ScopeSecretsRead, ScopeSecretsWrite, ScopeAuditRead}

// Token scopes covering resource permissions.
const (
	ScopeSecretsRead  Permission = "secrets:read"
	ScopeSecretsWrite Permission = "secrets:write"
	ScopeAuditRead    Permission = "audit:read"
)

var resourceTokenScope = map[Permission]Permission{
	SecretRead:   ScopeSecretsRead,
	SecretCreate: ScopeSecretsWrite,
	SecretUpdate: ScopeSecretsWrite,
	SecretDelete: ScopeSecretsWrite,
	AuditRead:    ScopeAuditRead,
}

// IsResourceScope reports whether p is a token scope for resource
// permissions, which are bounded by role bindings when the token is used.
func IsResourceScope(p Permission) bool {
	return p == ScopeSecretsRead || p == ScopeSecretsWrite || p == ScopeAuditRead
}

// ValidTokenScope reports whether p may be granted to an API token.
func ValidTokenScope(p Permission) bool { return slices.Contains(TokenScopes, p) }

type Kind int

const (
	KindUser Kind = iota + 1
	KindAPIToken
)

// Principal is an authenticated caller.
type Principal struct {
	Kind Kind
	// UserID is the user, or for API tokens the user who created the token.
	UserID uuid.UUID

	// Session (KindUser) only.
	SessionMFA bool
	// AuthTime is when the user last authenticated at the identity provider;
	// zero if unknown.
	AuthTime time.Time

	// API token (KindAPIToken) only. Bindings in Access are the creator's.
	TokenID     uuid.UUID
	TokenOrgID  uuid.UUID
	TokenScopes []Permission
	// CreatorRole is the token creator's current role in TokenOrgID.
	CreatorRole Role
}

// AuthenticatedWithin reports whether the user authenticated at the identity
// provider within d. Unknown authentication times never qualify.
func (p Principal) AuthenticatedWithin(d time.Duration, now time.Time) bool {
	return p.Kind == KindUser && !p.AuthTime.IsZero() && now.Sub(p.AuthTime) <= d
}

// Access is a principal's verified standing in one organization.
type Access struct {
	Principal      Principal
	OrganizationID uuid.UUID
	Role           Role
	// Bindings are the user's (or token creator's) current role bindings.
	Bindings []Binding
}

// Can reports whether the access grants perm. For API tokens this is the
// intersection of the token's scopes and its creator's current role.
func (a Access) Can(perm Permission) bool {
	if !slices.Contains(rolePermissions[a.Role], perm) {
		return false
	}
	if a.Principal.Kind == KindAPIToken {
		return perm != TokensManage && slices.Contains(a.Principal.TokenScopes, perm)
	}
	return a.Principal.Kind == KindUser
}

// CanOn reports whether the access grants the resource permission perm in
// environment env. Pass uuid.Nil for organization-wide permissions, which
// then require an organization-wide binding. For API tokens the permission
// must also be covered by a token scope.
func (a Access) CanOn(perm Permission, env uuid.UUID) bool {
	switch a.Principal.Kind {
	case KindUser:
	case KindAPIToken:
		scope, ok := resourceTokenScope[perm]
		if !ok || !slices.Contains(a.Principal.TokenScopes, scope) {
			return false
		}
	default:
		return false
	}
	for _, b := range a.Bindings {
		if (b.EnvironmentID == uuid.Nil || b.EnvironmentID == env) && slices.Contains(bindingPermissions[b.Role], perm) {
			return true
		}
	}
	return false
}

type principalKey struct{}
type accessKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func WithAccess(ctx context.Context, a Access) context.Context {
	return context.WithValue(ctx, accessKey{}, a)
}

func AccessFrom(ctx context.Context) (Access, bool) {
	a, ok := ctx.Value(accessKey{}).(Access)
	return a, ok
}
