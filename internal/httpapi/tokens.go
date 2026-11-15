package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/identity"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
)

func (a *api) ListApiTokens(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.TokensManage); !ok {
		return
	}
	tokens, err := a.d.Identities.ListTokens(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list api tokens", err)
		return
	}
	out := make([]ApiToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, apiTokenJSON(t))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *api) CreateApiToken(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.TokensManage)
	if !ok {
		return
	}
	var body CreateApiToken
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > 100 {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "name must be 1-100 characters")
		return
	}
	if body.ExpiresInDays < 1 || body.ExpiresInDays > 365 {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "expires_in_days must be between 1 and 365")
		return
	}
	if len(body.Scopes) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "at least one scope is required")
		return
	}
	scopes := make([]auth.Permission, 0, len(body.Scopes))
	for _, s := range body.Scopes {
		p := auth.Permission(s)
		if !auth.ValidTokenScope(p) {
			httpx.WriteError(w, r, http.StatusBadRequest, "invalid_scope", "unknown scope "+string(s))
			return
		}
		// A token never carries more than its creator could do. Resource
		// scopes are bounded by the creator's role bindings at use time.
		if !auth.IsResourceScope(p) && !access.Can(p) {
			httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "cannot grant scope "+string(s))
			return
		}
		for _, existing := range scopes {
			if existing == p {
				httpx.WriteError(w, r, http.StatusBadRequest, "invalid_scope", "duplicate scope "+string(s))
				return
			}
		}
		scopes = append(scopes, p)
	}
	if !a.requireStepUp(w, r, access) {
		return
	}

	lifetime := time.Duration(body.ExpiresInDays) * 24 * time.Hour
	t, secret, err := a.d.Identities.CreateToken(r.Context(), orgID, access.Principal.UserID, name, scopes, lifetime)
	if err != nil {
		a.internal(w, r, "create api token", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "api token created",
		"organization_id", orgID, "user_id", access.Principal.UserID, "token_id", t.ID)
	httpx.WriteJSON(w, http.StatusCreated, CreatedApiToken{Token: apiTokenJSON(t), Secret: secret.RevealString()})
}

func (a *api) RevokeApiToken(w http.ResponseWriter, r *http.Request, orgID OrgId, tokenID openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.TokensManage)
	if !ok {
		return
	}
	err := a.d.Identities.RevokeToken(r.Context(), orgID, tokenID)
	if errors.Is(err, identity.ErrTokenNotFound) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "revoke api token", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "api token revoked",
		"organization_id", orgID, "user_id", access.Principal.UserID, "token_id", tokenID)
	w.WriteHeader(http.StatusNoContent)
}

func apiTokenJSON(t identity.APIToken) ApiToken {
	scopes := make([]Scope, 0, len(t.Scopes))
	for _, s := range t.Scopes {
		scopes = append(scopes, Scope(s))
	}
	return ApiToken{
		Id: t.ID, Name: t.Name, DisplayPrefix: t.DisplayPrefix, Scopes: scopes,
		CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt,
	}
}
