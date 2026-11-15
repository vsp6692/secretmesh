package httpapi

import (
	"errors"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
	"github.com/secretmesh/secretmesh/internal/tenancy"
)

// InvitationTTL is how long an invitation stays open.
const InvitationTTL = 7 * 24 * time.Hour

func (a *api) GetOrganization(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	a.writeOrganization(w, r, access, http.StatusOK)
}

func (a *api) UpdateOrganization(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgWrite)
	if !ok {
		return
	}
	var body UpdateOrganization
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	// Changing the MFA requirement either way is security-relevant.
	if !a.requireStepUp(w, r, access) {
		return
	}
	// Enabling it from a session without MFA would lock the caller out.
	if body.RequireMfa && !access.Principal.SessionMFA {
		httpx.WriteError(w, r, http.StatusForbidden, "mfa_required", "sign in with multi-factor authentication before requiring it")
		return
	}
	if err := a.d.Tenancy.SetRequireMFA(r.Context(), orgID, body.RequireMfa); err != nil {
		a.internal(w, r, "update organization", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "organization updated",
		"organization_id", orgID, "user_id", access.Principal.UserID, "require_mfa", body.RequireMfa)
	a.writeOrganization(w, r, access, http.StatusOK)
}

func (a *api) writeOrganization(w http.ResponseWriter, r *http.Request, access auth.Access, status int) {
	o, err := a.d.Tenancy.Organization(r.Context(), access.OrganizationID)
	if errors.Is(err, tenancy.ErrNotFound) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "get organization", err)
		return
	}
	httpx.WriteJSON(w, status, Organization{
		Id: o.ID, Name: o.Name, Slug: o.Slug, RequireMfa: o.RequireMFA, Role: Role(access.Role),
	})
}

func (a *api) ListMembers(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.MembersRead); !ok {
		return
	}
	members, err := a.d.Tenancy.Members(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list members", err)
		return
	}
	out := make([]Member, 0, len(members))
	for _, m := range members {
		out = append(out, Member{
			UserId: m.UserID, Email: openapi_types.Email(m.Email), DisplayName: m.DisplayName,
			Role: Role(m.Role), JoinedAt: m.JoinedAt,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": out})
}

func (a *api) UpdateMember(w http.ResponseWriter, r *http.Request, orgID OrgId, userID openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.MembersWrite)
	if !ok {
		return
	}
	var body UpdateMemberJSONRequestBody
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	role := auth.Role(body.Role)
	if !role.Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "unknown role")
		return
	}
	if !a.memberChangeResult(w, r, a.d.Tenancy.SetRole(r.Context(), orgID, userID, role)) {
		return
	}
	a.d.Logger.InfoContext(r.Context(), "member role changed",
		"organization_id", orgID, "user_id", access.Principal.UserID, "member_id", userID, "role", string(role))
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) RemoveMember(w http.ResponseWriter, r *http.Request, orgID OrgId, userID openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.MembersWrite)
	if !ok {
		return
	}
	if !a.memberChangeResult(w, r, a.d.Tenancy.RemoveMember(r.Context(), orgID, userID)) {
		return
	}
	a.d.Logger.InfoContext(r.Context(), "member removed",
		"organization_id", orgID, "user_id", access.Principal.UserID, "member_id", userID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) memberChangeResult(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, tenancy.ErrNotFound):
		notFound(w, r)
	case errors.Is(err, tenancy.ErrLastAdmin):
		httpx.WriteError(w, r, http.StatusConflict, "last_admin", "the organization must keep at least one admin")
	default:
		a.internal(w, r, "change member", err)
	}
	return false
}

func (a *api) ListInvitations(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.MembersWrite); !ok {
		return
	}
	invs, err := a.d.Tenancy.Invitations(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list invitations", err)
		return
	}
	out := make([]Invitation, 0, len(invs))
	for _, i := range invs {
		out = append(out, invitationJSON(i))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"invitations": out})
}

func (a *api) CreateInvitation(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.MembersWrite)
	if !ok {
		return
	}
	var body CreateInvitation
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	role := auth.Role(body.Role)
	if !role.Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "unknown role")
		return
	}
	inv, err := a.d.Tenancy.Invite(r.Context(), orgID, access.Principal.UserID, string(body.Email), role, InvitationTTL)
	switch {
	case errors.Is(err, tenancy.ErrInvalidEmail):
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_email", "invalid email address")
		return
	case errors.Is(err, tenancy.ErrAlreadyMember):
		httpx.WriteError(w, r, http.StatusConflict, "already_member", "a member already has this email")
		return
	case err != nil:
		a.internal(w, r, "create invitation", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "invitation created",
		"organization_id", orgID, "user_id", access.Principal.UserID, "invitation_id", inv.ID, "role", string(role))
	httpx.WriteJSON(w, http.StatusCreated, invitationJSON(inv))
}

func (a *api) RevokeInvitation(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.MembersWrite)
	if !ok {
		return
	}
	err := a.d.Tenancy.RevokeInvitation(r.Context(), orgID, id)
	if errors.Is(err, tenancy.ErrNotFound) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "revoke invitation", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "invitation revoked",
		"organization_id", orgID, "user_id", access.Principal.UserID, "invitation_id", id)
	w.WriteHeader(http.StatusNoContent)
}

func invitationJSON(i tenancy.Invitation) Invitation {
	return Invitation{
		Id: i.ID, Email: openapi_types.Email(i.Email), Role: Role(i.Role),
		InvitedBy: i.InvitedBy, CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt,
	}
}
