// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package identity authenticates users via OIDC and manages browser sessions.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

const (
	loginStateTTL   = 10 * time.Minute
	providerTimeout = 15 * time.Second
	// authTimeSkew tolerates clock differences with the identity provider
	// (auth_time has one-second resolution).
	authTimeSkew = time.Minute
)

// Config configures the OIDC login flow.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret sensitive.Value
	// PublicURL is the browser-facing origin; the callback is PublicURL + "/auth/callback".
	PublicURL    *url.URL
	CookieSecure bool
	SessionTTL   time.Duration
	// MFAMethods and MFAContexts are the "amr" and "acr" values that count
	// as multi-factor authentication.
	MFAMethods  []string
	MFAContexts []string
	// AssumeEmailVerified treats emails without an email_verified claim as
	// verified. Only for single-tenant IdPs that control the attribute.
	AssumeEmailVerified bool
}

// LoginHook runs after a user authenticates and before the session is created.
// Returning an error aborts the login.
type LoginHook func(ctx context.Context, u User) error

// LoginHooks runs hooks in order, stopping at the first error.
func LoginHooks(hooks ...LoginHook) LoginHook {
	return func(ctx context.Context, u User) error {
		for _, h := range hooks {
			if h == nil {
				continue
			}
			if err := h(ctx, u); err != nil {
				return err
			}
		}
		return nil
	}
}

// Service implements the OIDC authorization code flow (with PKCE and nonce)
// and server-side sessions.
type Service struct {
	cfg     Config
	store   *Store
	onLogin LoginHook
	logger  *slog.Logger

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewService(cfg Config, store *Store, onLogin LoginHook, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, store: store, onLogin: onLogin, logger: logger}
}

// provider performs OIDC discovery on first use, so the API can start (and
// report readiness) while the identity provider is still coming up.
func (s *Service) provider(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oauth != nil {
		return s.oauth, s.verifier, nil
	}

	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	p, err := oidc.NewProvider(ctx, s.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	s.oauth = &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret.RevealString(),
		Endpoint:     p.Endpoint(),
		RedirectURL:  s.cfg.PublicURL.String() + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	s.verifier = p.Verifier(&oidc.Config{ClientID: s.cfg.ClientID})
	return s.oauth, s.verifier, nil
}

func (s *Service) sessionCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-sm_session"
	}
	return "sm_session"
}

func (s *Service) stateCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-sm_login_state"
	}
	return "sm_login_state"
}

func (s *Service) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	// Secure is false only for http:// public URLs (enforced in config).
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124, see above
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		// Lax: the cookie must accompany the top-level redirect back from the IdP.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	// Secure is false only for http:// public URLs (enforced in config).
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124, see above
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// HandleLogin starts the authorization code flow.
//
// Query parameters: return_to, a same-origin path to land on afterwards;
// step_up=1, which forces re-authentication at the identity provider so that
// the new session satisfies step-up checks.
func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	oauthCfg, _, err := s.provider(r.Context())
	if err != nil {
		s.logger.ErrorContext(r.Context(), "identity provider unavailable", "error", err)
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "idp_unavailable", "identity provider unavailable")
		return
	}

	state := randomToken()
	st := loginState{
		Nonce:        randomToken(),
		CodeVerifier: oauth2.GenerateVerifier(),
		StepUp:       r.URL.Query().Get("step_up") == "1",
		ReturnTo:     SafeReturnTo(r.URL.Query().Get("return_to")),
	}
	if err := s.store.createLoginState(r.Context(), hashToken(state), st, time.Now().Add(loginStateTTL)); err != nil {
		s.logger.ErrorContext(r.Context(), "store login state", "error", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	opts := []oauth2.AuthCodeOption{oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.CodeVerifier)}
	if st.StepUp {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	s.setCookie(w, s.stateCookieName(), state, loginStateTTL)
	// Target is the IdP's discovered authorization endpoint, not user input.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, opts...), http.StatusFound)
}

// SafeReturnTo returns p if it is a local absolute path, otherwise "/".
// It rejects scheme-relative ("//host") and backslash forms that browsers
// may treat as another origin.
func SafeReturnTo(p string) string {
	if p == "" || len(p) > 512 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}

// HandleCallback completes the flow, creates a session and redirects home.
func (s *Service) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	cookie, err := r.Cookie(s.stateCookieName())
	s.clearCookie(w, s.stateCookieName())
	if err != nil || q.Get("state") == "" ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(q.Get("state"))) != 1 {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_login_state", "login state is missing or does not match")
		return
	}

	// Consume the state before anything else so it cannot be replayed.
	st, err := s.store.consumeLoginState(ctx, hashToken(q.Get("state")))
	if err != nil {
		if !errors.Is(err, errNotFound) {
			s.logger.ErrorContext(ctx, "consume login state", "error", err)
		}
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_login_state", "login state is invalid or expired")
		return
	}

	if e := q.Get("error"); e != "" {
		s.logger.WarnContext(ctx, "identity provider returned error", "oidc_error", e)
		httpx.WriteError(w, r, http.StatusUnauthorized, "login_failed", "identity provider rejected the login")
		return
	}

	oauthCfg, verifier, err := s.provider(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "identity provider unavailable", "error", err)
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "idp_unavailable", "identity provider unavailable")
		return
	}

	exCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	tok, err := oauthCfg.Exchange(exCtx, q.Get("code"), oauth2.VerifierOption(st.CodeVerifier))
	if err != nil {
		s.logger.WarnContext(ctx, "authorization code exchange failed", "error", err)
		httpx.WriteError(w, r, http.StatusUnauthorized, "login_failed", "login failed")
		return
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, "login_failed", "identity provider did not return an ID token")
		return
	}
	idToken, err := verifier.Verify(exCtx, rawIDToken)
	if err != nil {
		s.logger.WarnContext(ctx, "id token verification failed", "error", err)
		httpx.WriteError(w, r, http.StatusUnauthorized, "login_failed", "login failed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
		httpx.WriteError(w, r, http.StatusUnauthorized, "login_failed", "login failed")
		return
	}

	var claims struct {
		Email         string   `json:"email"`
		EmailVerified *bool    `json:"email_verified"`
		Name          string   `json:"name"`
		AuthTime      int64    `json:"auth_time"`
		AMR           []string `json:"amr"`
		ACR           string   `json:"acr"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Email == "" {
		httpx.WriteError(w, r, http.StatusForbidden, "email_required", "identity provider must supply an email claim")
		return
	}
	emailVerified := s.cfg.AssumeEmailVerified
	if claims.EmailVerified != nil {
		emailVerified = *claims.EmailVerified
	}
	var authTime time.Time
	if claims.AuthTime > 0 {
		authTime = time.Unix(claims.AuthTime, 0)
	}
	if st.StepUp && (authTime.IsZero() || authTime.Before(st.CreatedAt.Add(-authTimeSkew))) {
		// The IdP did not re-authenticate the user (or did not say so).
		s.logger.WarnContext(ctx, "step-up login without fresh authentication", "subject", idToken.Subject)
		httpx.WriteError(w, r, http.StatusUnauthorized, "step_up_failed", "identity provider did not re-authenticate the user")
		return
	}

	user, err := s.store.loginUser(ctx, User{
		Issuer:        idToken.Issuer,
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: emailVerified,
		DisplayName:   claims.Name,
	})
	if errors.Is(err, errUserDisabled) {
		httpx.WriteError(w, r, http.StatusForbidden, "user_disabled", "user is disabled")
		return
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "upsert user", "error", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if s.onLogin != nil {
		if err := s.onLogin(ctx, user); err != nil {
			s.logger.ErrorContext(ctx, "login hook failed", "user_id", user.ID, "error", err)
			httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	// Rotate: every login gets a new session; the previous one is revoked.
	if old, err := r.Cookie(s.sessionCookieName()); err == nil && old.Value != "" {
		if err := s.store.deleteSession(ctx, hashToken(old.Value)); err != nil {
			s.logger.WarnContext(ctx, "revoke previous session", "error", err)
		}
	}
	mfa := s.satisfiesMFA(claims.AMR, claims.ACR)
	session := randomToken()
	if err := s.store.createSession(ctx, hashToken(session), user.ID, time.Now().Add(s.cfg.SessionTTL), authTime, mfa); err != nil {
		s.logger.ErrorContext(ctx, "create session", "error", err)
		httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.setCookie(w, s.sessionCookieName(), session, s.cfg.SessionTTL)
	s.logger.InfoContext(ctx, "user logged in", "user_id", user.ID, "mfa", mfa, "step_up", st.StepUp)

	// Fixed origin plus a validated local path (SafeReturnTo).
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, s.cfg.PublicURL.String()+SafeReturnTo(st.ReturnTo), http.StatusFound)
}

func (s *Service) satisfiesMFA(amr []string, acr string) bool {
	for _, m := range amr {
		if slices.Contains(s.cfg.MFAMethods, m) {
			return true
		}
	}
	return acr != "" && slices.Contains(s.cfg.MFAContexts, acr)
}

// HandleLogout deletes the session. It only accepts POST; SameSite=Lax
// prevents cross-site requests from carrying the session cookie.
func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		if err := s.store.deleteSession(r.Context(), hashToken(c.Value)); err != nil {
			s.logger.ErrorContext(r.Context(), "delete session", "error", err)
		}
	}
	s.clearCookie(w, s.sessionCookieName())
	http.Redirect(w, r, s.cfg.PublicURL.String()+"/", http.StatusSeeOther)
}

// Authenticate identifies the caller from a bearer API token or, failing
// that, the session cookie, and rejects the request with 401 if neither is
// valid. A presented but invalid bearer token never falls back to the cookie.
// For sessions it also sets the user's tenant scope.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if h := r.Header.Get("Authorization"); h != "" {
			token, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "unsupported authorization scheme")
				return
			}
			p, err := s.store.authenticateToken(ctx, token)
			if err != nil {
				if !errors.Is(err, errNotFound) {
					s.logger.ErrorContext(ctx, "authenticate api token", "error", err)
					httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
					return
				}
				httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "invalid, expired or revoked token")
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(ctx, p)))
			return
		}

		c, err := r.Cookie(s.sessionCookieName())
		if err != nil || c.Value == "" {
			httpx.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		sess, err := s.store.lookupSession(ctx, hashToken(c.Value))
		if err != nil {
			if !errors.Is(err, errNotFound) {
				s.logger.ErrorContext(ctx, "lookup session", "error", err)
				httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal server error")
				return
			}
			httpx.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		ctx = auth.WithPrincipal(ctx, auth.Principal{
			Kind:       auth.KindUser,
			UserID:     sess.User.ID,
			SessionMFA: sess.MFA,
			AuthTime:   sess.AuthTime,
		})
		ctx = context.WithValue(ctx, userKey{}, sess.User)
		ctx = postgres.WithScope(ctx, postgres.Scope{UserID: sess.User.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type userKey struct{}

// CurrentUser returns the session user placed in ctx by Authenticate. It is
// absent for API token requests.
func CurrentUser(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey{}).(User)
	return u, ok
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}
