package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/identity"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/rotation"
	"github.com/secretmesh/secretmesh/internal/tenancy"
)

// StepUpMaxAge is how recently a user must have authenticated at the
// identity provider to perform sensitive operations.
const StepUpMaxAge = 5 * time.Minute

// Deps are the services the router depends on.
type Deps struct {
	Pool       *pgxpool.Pool
	Identity   *identity.Service
	Identities *identity.Store
	Tenancy    *tenancy.Store
	Inventory  *inventory.Store
	Discovery  *inventory.Discovery
	Rotation   *rotation.Service
	Deliverer  *notify.Deliverer
	Approvals  *approvals.Service
	Connectors *connectors.Registry
	Keyring    keys.Keyring
	Logger     *slog.Logger
	// Now defaults to time.Now; tests may override it.
	Now func() time.Time
}

// NewRouter builds the complete HTTP handler.
func NewRouter(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.Pool.Ping(ctx); err != nil {
			httpx.WriteError(w, r, http.StatusServiceUnavailable, "not_ready", "database unavailable")
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /auth/login", d.Identity.HandleLogin)
	mux.HandleFunc("GET /auth/callback", d.Identity.HandleCallback)
	mux.HandleFunc("POST /auth/logout", d.Identity.HandleLogout)

	// Every /api/ request is authenticated before routing (fail closed);
	// organization routes then verify the caller's access to the organization.
	a := &api{d: d}
	apiMux := http.NewServeMux()
	HandlerWithOptions(a, StdHTTPServerOptions{
		BaseURL:     "/api/v1",
		BaseRouter:  apiMux,
		Middlewares: []MiddlewareFunc{a.orgAccess},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, _ error) {
			httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "invalid request parameters")
		},
	})
	apiMux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	})
	mux.Handle("/api/", d.Identity.Authenticate(apiMux))

	// Rejects cross-origin state-changing browser requests (Sec-Fetch-Site /
	// Origin), in addition to SameSite=Lax cookies.
	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusForbidden, "cross_origin_request", "cross-origin request rejected")
	}))

	return httpx.Chain(csrf.Handler(mux),
		httpx.WithRequestID,
		httpx.AccessLog(d.Logger),
		httpx.Recover(d.Logger),
		httpx.SecurityHeaders,
		httpx.LimitBody,
	)
}

// api implements ServerInterface.
type api struct {
	d Deps
}

var _ ServerInterface = (*api)(nil)

// orgAccess runs on every generated route. For routes with an {orgId} it
// verifies the principal's access to that organization and, only then, sets
// the organization as tenant scope. Non-members get 404 so that other
// organizations' existence is not revealed.
func (a *api) orgAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.PathValue("orgId")
		if raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		orgID, err := uuid.Parse(raw)
		if err != nil {
			notFound(w, r)
			return
		}
		p, ok := auth.PrincipalFrom(ctx)
		if !ok {
			httpx.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}

		access := auth.Access{Principal: p, OrganizationID: orgID}
		switch p.Kind {
		case auth.KindUser:
			m, err := a.d.Tenancy.Membership(ctx, orgID, p.UserID)
			if errors.Is(err, tenancy.ErrNotFound) {
				notFound(w, r)
				return
			}
			if err != nil {
				a.internal(w, r, "resolve membership", err)
				return
			}
			if m.Organization.RequireMFA && !p.SessionMFA {
				httpx.WriteError(w, r, http.StatusForbidden, "mfa_required", "this organization requires multi-factor authentication; sign in again with MFA")
				return
			}
			access.Role = m.Role
		case auth.KindAPIToken:
			if p.TokenOrgID != orgID {
				notFound(w, r)
				return
			}
			access.Role = p.CreatorRole
		default:
			httpx.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}

		ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: orgID})
		bindings, err := a.d.Tenancy.Bindings(ctx, orgID, p.UserID)
		if err != nil {
			a.internal(w, r, "load role bindings", err)
			return
		}
		access.Bindings = bindings
		ctx = auth.WithAccess(ctx, access)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize returns the caller's access to orgID if it grants perm,
// otherwise writes an error and returns false.
func (a *api) authorize(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, perm auth.Permission) (auth.Access, bool) {
	access, ok := auth.AccessFrom(r.Context())
	if !ok || access.OrganizationID != orgID {
		// orgAccess did not run for this route: a wiring bug. Fail closed.
		a.d.Logger.ErrorContext(r.Context(), "organization access missing", "permission", string(perm))
		notFound(w, r)
		return auth.Access{}, false
	}
	if !access.Can(perm) {
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "missing permission "+string(perm))
		return auth.Access{}, false
	}
	return access, true
}

// authorizeOn is authorize for resource permissions in environment env
// (uuid.Nil: organization-wide).
func (a *api) authorizeOn(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, perm auth.Permission, env uuid.UUID) (auth.Access, bool) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return access, false
	}
	if !access.CanOn(perm, env) {
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "missing permission "+string(perm))
		return auth.Access{}, false
	}
	return access, true
}

// requireStepUp fails with 401 step_up_required unless the session user
// authenticated at the identity provider within StepUpMaxAge.
func (a *api) requireStepUp(w http.ResponseWriter, r *http.Request, access auth.Access) bool {
	if access.Principal.Kind != auth.KindUser {
		httpx.WriteError(w, r, http.StatusForbidden, "session_required", "this operation requires a user session")
		return false
	}
	if !access.Principal.AuthenticatedWithin(StepUpMaxAge, a.d.Now()) {
		httpx.WriteError(w, r, http.StatusUnauthorized, "step_up_required", "re-authenticate to perform this operation")
		return false
	}
	return true
}

func (a *api) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.d.Logger.ErrorContext(r.Context(), what, "error", err, "request_id", httpx.RequestID(r.Context()))
	httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
}

func notFound(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
}

func (a *api) GetMe(w http.ResponseWriter, r *http.Request) {
	u, ok := identity.CurrentUser(r.Context())
	p, _ := auth.PrincipalFrom(r.Context())
	if !ok || p.Kind != auth.KindUser {
		httpx.WriteError(w, r, http.StatusForbidden, "session_required", "this endpoint requires a user session")
		return
	}
	memberships, err := a.d.Tenancy.Memberships(r.Context(), u.ID)
	if err != nil {
		a.internal(w, r, "list memberships", err)
		return
	}

	orgs := make([]OrganizationMembership, 0, len(memberships))
	for _, m := range memberships {
		orgs = append(orgs, OrganizationMembership{
			Id:         m.Organization.ID,
			Name:       m.Organization.Name,
			Slug:       m.Organization.Slug,
			Role:       Role(m.Role),
			RequireMfa: m.Organization.RequireMFA,
		})
	}
	session := Session{Mfa: p.SessionMFA}
	if !p.AuthTime.IsZero() {
		session.AuthenticatedAt = &p.AuthTime
	}
	httpx.WriteJSON(w, http.StatusOK, Me{
		User: User{
			Id:          u.ID,
			Email:       openapi_types.Email(u.Email),
			DisplayName: u.DisplayName,
		},
		Session:       session,
		Organizations: orgs,
	})
}
