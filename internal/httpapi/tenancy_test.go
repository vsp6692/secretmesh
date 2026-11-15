package httpapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity/oidctest"
)

var (
	acmeAdmin   = oidctest.Claims{Subject: "u-admin", Email: adminEmail, EmailVerified: true, Name: "Admin"}
	globexAdmin = oidctest.Claims{Subject: "u-globex", Email: "boss@globex.example", EmailVerified: true}
	dev         = oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true}
)

// twoTenants returns the environment, signed-in clients for the admins of
// acme and globex, and globex's ID.
func twoTenants(t *testing.T) (e *env, acme, globex *http.Client, globexID uuid.UUID) {
	t.Helper()
	e = setup(t)
	if err := e.db.Owner.QueryRow(context.Background(),
		`INSERT INTO organizations (slug, name) VALUES ('globex', 'Globex') RETURNING id`).Scan(&globexID); err != nil {
		t.Fatal(err)
	}
	acme, globex = e.browser(t), e.browser(t)
	e.login(t, acme, acmeAdmin)
	e.login(t, globex, globexAdmin)
	e.grant(t, globexID, globexAdmin.Email, "org_admin")
	return e, acme, globex, globexID
}

// createToken creates an API token in org as the signed-in client and returns its secret and ID.
func createToken(t *testing.T, e *env, c *http.Client, org uuid.UUID, scopes ...string) (string, string) {
	t.Helper()
	r := e.call(t, c, "POST", "/orgs/"+org.String()+"/api-tokens",
		map[string]any{"name": "ci", "scopes": scopes, "expires_in_days": 30})
	if r.Status != http.StatusCreated {
		t.Fatalf("create token: %d %s", r.Status, r.Body)
	}
	var created httpapi.CreatedApiToken
	r.decode(t, &created)
	return created.Secret, created.Token.Id.String()
}

func bearer(token string) []string { return []string{"Authorization", "Bearer " + token} }

func TestCrossTenantAccessFailsClosed(t *testing.T) {
	e, acme, globex, globexID := twoTenants(t)
	acmeID := e.acme.ID.String()
	g := "/orgs/" + globexID.String()

	globexToken, globexTokenID := createToken(t, e, globex, globexID, "org:read", "members:read")
	if r := e.call(t, globex, "POST", g+"/invitations", map[string]string{"email": "new@globex.example", "role": "member"}); r.Status != http.StatusCreated {
		t.Fatalf("globex invite: %d %s", r.Status, r.Body)
	}

	// Every organization route, called by acme's admin against globex, must
	// return 404 and change nothing.
	globexAdminID := memberID(t, e, globex, globexID, globexAdmin.Email)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", g, nil},
		{"PATCH", g, map[string]bool{"require_mfa": false}},
		{"GET", g + "/members", nil},
		{"PATCH", g + "/members/" + globexAdminID, map[string]string{"role": "member"}},
		{"DELETE", g + "/members/" + globexAdminID, nil},
		{"GET", g + "/invitations", nil},
		{"POST", g + "/invitations", map[string]string{"email": "spy@acme.example", "role": "org_admin"}},
		{"GET", g + "/api-tokens", nil},
		{"POST", g + "/api-tokens", map[string]any{"name": "x", "scopes": []string{"org:read"}, "expires_in_days": 1}},
		{"DELETE", g + "/api-tokens/" + globexTokenID, nil},
		{"GET", "/orgs/" + uuid.NewString(), nil},
		{"GET", "/orgs/not-a-uuid", nil},
	} {
		if r := e.call(t, acme, tc.method, tc.path, tc.body); r.Status != http.StatusNotFound && r.Status != http.StatusBadRequest {
			t.Errorf("%s %s: status %d, want 404", tc.method, tc.path, r.Status)
		}
	}

	// Acme's admin cannot reach globex objects through acme's own routes either.
	if r := e.call(t, acme, "DELETE", "/orgs/"+acmeID+"/api-tokens/"+globexTokenID, nil); r.Status != http.StatusNotFound {
		t.Errorf("revoke foreign token via own org: %d", r.Status)
	}
	if r := e.call(t, acme, "DELETE", "/orgs/"+acmeID+"/members/"+globexAdminID, nil); r.Status != http.StatusNotFound {
		t.Errorf("remove foreign member via own org: %d", r.Status)
	}

	// A globex token cannot be used against acme.
	if r := e.call(t, nil, "GET", "/orgs/"+acmeID+"/members", nil, bearer(globexToken)...); r.Status != http.StatusNotFound {
		t.Errorf("foreign token: %d", r.Status)
	}

	// Globex is intact.
	if r := e.call(t, nil, "GET", g+"/members", nil, bearer(globexToken)...); r.Status != http.StatusOK {
		t.Fatalf("globex token stopped working: %d %s", r.Status, r.Body)
	}
	var orgs struct{ Members []httpapi.Member }
	e.call(t, globex, "GET", g+"/members", nil).decode(t, &orgs)
	if len(orgs.Members) != 1 || orgs.Members[0].Role != httpapi.RoleOrgAdmin {
		t.Fatalf("globex members changed: %+v", orgs.Members)
	}
	var invs struct{ Invitations []httpapi.Invitation }
	e.call(t, globex, "GET", g+"/invitations", nil).decode(t, &invs)
	if len(invs.Invitations) != 1 {
		t.Fatalf("globex invitations changed: %+v", invs.Invitations)
	}

	// /me lists only the caller's own organizations.
	_, me := getMe(t, acme, e.api.URL)
	if len(me.Organizations) != 1 || me.Organizations[0].Id != e.acme.ID {
		t.Fatalf("acme admin sees %+v", me.Organizations)
	}
}

func memberID(t *testing.T, e *env, c *http.Client, org uuid.UUID, email string) string {
	t.Helper()
	var out struct{ Members []httpapi.Member }
	e.call(t, c, "GET", "/orgs/"+org.String()+"/members", nil).decode(t, &out)
	for _, m := range out.Members {
		if string(m.Email) == email {
			return m.UserId.String()
		}
	}
	t.Fatalf("%s is not a member", email)
	return ""
}

func TestMembersAndInvitations(t *testing.T) {
	e := setup(t)
	admin := e.browser(t)
	e.login(t, admin, acmeAdmin)
	o := "/orgs/" + e.acme.ID.String()

	t.Run("invalid input is rejected", func(t *testing.T) {
		for _, body := range []any{
			map[string]string{"email": "not-an-email", "role": "member"},
			map[string]string{"email": "dev@example.com", "role": "owner"},
			map[string]any{"email": "dev@example.com", "role": "member", "extra": 1},
		} {
			if r := e.call(t, admin, "POST", o+"/invitations", body); r.Status != http.StatusBadRequest {
				t.Errorf("%v: status %d", body, r.Status)
			}
		}
	})

	t.Run("invitation is accepted on login with verified email only", func(t *testing.T) {
		if r := e.call(t, admin, "POST", o+"/invitations", map[string]string{"email": "DEV@example.com", "role": "member"}); r.Status != http.StatusCreated {
			t.Fatalf("invite: %d %s", r.Status, r.Body)
		}

		spoof := e.browser(t)
		e.login(t, spoof, oidctest.Claims{Subject: "u-spoof", Email: dev.Email, EmailVerified: false})
		if _, me := getMe(t, spoof, e.api.URL); len(me.Organizations) != 0 {
			t.Fatal("unverified email accepted an invitation")
		}

		c := e.browser(t)
		e.login(t, c, dev)
		_, me := getMe(t, c, e.api.URL)
		if len(me.Organizations) != 1 || me.Organizations[0].Role != httpapi.RoleMember {
			t.Fatalf("dev memberships: %+v", me.Organizations)
		}
		var invs struct{ Invitations []httpapi.Invitation }
		e.call(t, admin, "GET", o+"/invitations", nil).decode(t, &invs)
		if len(invs.Invitations) != 0 {
			t.Fatalf("accepted invitation still open: %+v", invs.Invitations)
		}
		if r := e.call(t, admin, "POST", o+"/invitations", map[string]string{"email": dev.Email, "role": "member"}); r.Status != http.StatusConflict || r.code() != "already_member" {
			t.Fatalf("re-invite member: %d %s", r.Status, r.Body)
		}
	})

	t.Run("revoked invitation is not accepted", func(t *testing.T) {
		r := e.call(t, admin, "POST", o+"/invitations", map[string]string{"email": "late@example.com", "role": "org_admin"})
		var inv httpapi.Invitation
		r.decode(t, &inv)
		if r := e.call(t, admin, "DELETE", o+"/invitations/"+inv.Id.String(), nil); r.Status != http.StatusNoContent {
			t.Fatalf("revoke: %d", r.Status)
		}
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-late", Email: "late@example.com", EmailVerified: true})
		if _, me := getMe(t, c, e.api.URL); len(me.Organizations) != 0 {
			t.Fatal("revoked invitation was accepted")
		}
	})

	t.Run("members cannot manage members or tokens", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, dev)
		if r := e.call(t, c, "GET", o+"/members", nil); r.Status != http.StatusOK {
			t.Fatalf("member list: %d", r.Status)
		}
		for _, tc := range []struct {
			method, path string
			body         any
		}{
			{"POST", o + "/invitations", map[string]string{"email": "x@example.com", "role": "org_admin"}},
			{"GET", o + "/invitations", nil},
			{"PATCH", o + "/members/" + memberID(t, e, c, e.acme.ID, dev.Email), map[string]string{"role": "org_admin"}},
			{"PATCH", o, map[string]bool{"require_mfa": false}},
			{"GET", o + "/api-tokens", nil},
			{"POST", o + "/api-tokens", map[string]any{"name": "x", "scopes": []string{"org:read"}, "expires_in_days": 1}},
		} {
			if r := e.call(t, c, tc.method, tc.path, tc.body); r.Status != http.StatusForbidden {
				t.Errorf("%s %s: status %d, want 403", tc.method, tc.path, r.Status)
			}
		}
	})

	t.Run("last admin is protected", func(t *testing.T) {
		adminID := memberID(t, e, admin, e.acme.ID, adminEmail)
		if r := e.call(t, admin, "PATCH", o+"/members/"+adminID, map[string]string{"role": "member"}); r.Status != http.StatusConflict || r.code() != "last_admin" {
			t.Fatalf("demote last admin: %d %s", r.Status, r.Body)
		}
		if r := e.call(t, admin, "DELETE", o+"/members/"+adminID, nil); r.Status != http.StatusConflict {
			t.Fatalf("remove last admin: %d", r.Status)
		}

		devID := memberID(t, e, admin, e.acme.ID, dev.Email)
		if r := e.call(t, admin, "PATCH", o+"/members/"+devID, map[string]string{"role": "org_admin"}); r.Status != http.StatusNoContent {
			t.Fatalf("promote: %d %s", r.Status, r.Body)
		}
		if r := e.call(t, admin, "PATCH", o+"/members/"+adminID, map[string]string{"role": "member"}); r.Status != http.StatusNoContent {
			t.Fatalf("demote with another admin present: %d %s", r.Status, r.Body)
		}
		// The demotion takes effect on the next request.
		if r := e.call(t, admin, "GET", o+"/invitations", nil); r.Status != http.StatusForbidden {
			t.Fatalf("demoted admin still has admin access: %d", r.Status)
		}
	})
}

func TestAPITokens(t *testing.T) {
	e := setup(t)
	o := "/orgs/" + e.acme.ID.String()

	admin := e.browser(t)
	e.login(t, admin, acmeAdmin)

	t.Run("creation requires step-up", func(t *testing.T) {
		stale := e.browser(t)
		old := acmeAdmin
		old.AuthTime = time.Now().Add(-time.Hour)
		e.login(t, stale, old)
		body := map[string]any{"name": "ci", "scopes": []string{"org:read"}, "expires_in_days": 30}
		if r := e.call(t, stale, "POST", o+"/api-tokens", body); r.Status != http.StatusUnauthorized || r.code() != "step_up_required" {
			t.Fatalf("stale session: %d %s", r.Status, r.Body)
		}

		// An IdP that ignores max_age=0 cannot complete step-up.
		lazy := old
		lazy.IgnoreMaxAge = true
		if r := e.loginWith(t, stale, lazy, "step_up=1"); r.Status != http.StatusUnauthorized || r.code() != "step_up_failed" {
			t.Fatalf("step-up without re-authentication: %d %s", r.Status, r.Body)
		}
		// Neither can one that omits auth_time.
		noTime := acmeAdmin
		noTime.OmitAuthTime = true
		if r := e.loginWith(t, stale, noTime, "step_up=1"); r.Status != http.StatusUnauthorized {
			t.Fatalf("step-up without auth_time: %d", r.Status)
		}

		if r := e.loginWith(t, stale, old, "step_up=1&return_to=%2Fsettings"); r.Status != http.StatusFound || r.Location != e.api.URL+"/settings" {
			t.Fatalf("step-up login: %d %q %s", r.Status, r.Location, r.Body)
		}
		if q := e.idp.LastAuthorize(); q.Get("max_age") != "0" || q.Get("prompt") != "login" {
			t.Fatalf("step-up did not force re-authentication: %v", q)
		}
		if r := e.call(t, stale, "POST", o+"/api-tokens", body); r.Status != http.StatusCreated {
			t.Fatalf("after step-up: %d %s", r.Status, r.Body)
		}
	})

	t.Run("validation", func(t *testing.T) {
		for _, body := range []map[string]any{
			{"name": "", "scopes": []string{"org:read"}, "expires_in_days": 30},
			{"name": "x", "scopes": []string{}, "expires_in_days": 30},
			{"name": "x", "scopes": []string{"tokens:manage"}, "expires_in_days": 30},
			{"name": "x", "scopes": []string{"org:read", "org:read"}, "expires_in_days": 30},
			{"name": "x", "scopes": []string{"org:read"}, "expires_in_days": 366},
			{"name": "x", "scopes": []string{"org:read"}, "expires_in_days": 0},
		} {
			if r := e.call(t, admin, "POST", o+"/api-tokens", body); r.Status != http.StatusBadRequest {
				t.Errorf("%v: status %d", body, r.Status)
			}
		}
	})

	t.Run("token is shown once and stored hashed", func(t *testing.T) {
		secret, id := createToken(t, e, admin, e.acme.ID, "org:read")
		if !strings.HasPrefix(secret, "smt_") || len(secret) < 40 {
			t.Fatalf("unexpected token format %q", secret)
		}
		var stored int
		if err := e.db.Owner.QueryRow(context.Background(), `
			SELECT count(*) FROM api_tokens WHERE id = $1 AND token_hash = sha256(convert_to($2, 'UTF8'))
			  AND position(convert_to($2, 'UTF8') IN token_hash) = 0`, id, secret).Scan(&stored); err != nil || stored != 1 {
			t.Fatalf("token not stored as SHA-256 hash: %v %d", err, stored)
		}
		r := e.call(t, admin, "GET", o+"/api-tokens", nil)
		if strings.Contains(string(r.Body), secret) || strings.Contains(string(r.Body), secret[10:]) {
			t.Fatal("token listing exposes the secret")
		}
	})

	t.Run("scopes are enforced", func(t *testing.T) {
		secret, _ := createToken(t, e, admin, e.acme.ID, "org:read", "members:read")
		tok := bearer(secret)
		if r := e.call(t, nil, "GET", o, nil, tok...); r.Status != http.StatusOK {
			t.Fatalf("org:read: %d", r.Status)
		}
		if r := e.call(t, nil, "GET", o+"/members", nil, tok...); r.Status != http.StatusOK {
			t.Fatalf("members:read: %d", r.Status)
		}
		for _, tc := range []struct {
			method, path string
			body         any
		}{
			{"POST", o + "/invitations", map[string]string{"email": "x@example.com", "role": "member"}},
			{"GET", o + "/api-tokens", nil},
			{"POST", o + "/api-tokens", map[string]any{"name": "x", "scopes": []string{"org:read"}, "expires_in_days": 1}},
		} {
			if r := e.call(t, nil, tc.method, tc.path, tc.body, tok...); r.Status != http.StatusForbidden {
				t.Errorf("%s %s: %d, want 403", tc.method, tc.path, r.Status)
			}
		}
		if r := e.call(t, nil, "GET", "/me", nil, tok...); r.Status != http.StatusForbidden {
			t.Errorf("/me with token: %d", r.Status)
		}
	})

	t.Run("token with org:write cannot pass step-up", func(t *testing.T) {
		secret, _ := createToken(t, e, admin, e.acme.ID, "org:write")
		if r := e.call(t, nil, "PATCH", o, map[string]bool{"require_mfa": false}, bearer(secret)...); r.Status != http.StatusForbidden || r.code() != "session_required" {
			t.Fatalf("token changed MFA requirement: %d %s", r.Status, r.Body)
		}
	})

	t.Run("invalid bearer never falls back to the session cookie", func(t *testing.T) {
		for _, h := range []string{"Bearer smt_invalid", "Bearer ", "Basic YTpi", "smt_x"} {
			if r := e.call(t, admin, "GET", o, nil, "Authorization", h); r.Status != http.StatusUnauthorized {
				t.Errorf("%q: status %d", h, r.Status)
			}
		}
	})

	t.Run("revoked token stops working", func(t *testing.T) {
		secret, id := createToken(t, e, admin, e.acme.ID, "org:read")
		if r := e.call(t, admin, "DELETE", o+"/api-tokens/"+id, nil); r.Status != http.StatusNoContent {
			t.Fatalf("revoke: %d", r.Status)
		}
		if r := e.call(t, nil, "GET", o, nil, bearer(secret)...); r.Status != http.StatusUnauthorized {
			t.Fatalf("revoked token: %d", r.Status)
		}
		if r := e.call(t, admin, "DELETE", o+"/api-tokens/"+id, nil); r.Status != http.StatusNotFound {
			t.Fatalf("double revoke: %d", r.Status)
		}
	})

	t.Run("expired token stops working", func(t *testing.T) {
		secret, id := createToken(t, e, admin, e.acme.ID, "org:read")
		if _, err := e.db.Owner.Exec(context.Background(), `UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if r := e.call(t, nil, "GET", o, nil, bearer(secret)...); r.Status != http.StatusUnauthorized {
			t.Fatalf("expired token: %d", r.Status)
		}
	})

	t.Run("token follows its creator's current role", func(t *testing.T) {
		// A second admin creates a members:write token, is demoted, then removed.
		e.grant(t, e.acme.ID, mustLogin(t, e, oidctest.Claims{Subject: "u-ops", Email: "ops@example.com", EmailVerified: true}), "org_admin")
		ops := e.browser(t)
		e.login(t, ops, oidctest.Claims{Subject: "u-ops", Email: "ops@example.com", EmailVerified: true})
		secret, _ := createToken(t, e, ops, e.acme.ID, "members:write", "org:read")
		tok := bearer(secret)
		invite := map[string]string{"email": "via-token@example.com", "role": "member"}
		if r := e.call(t, nil, "POST", o+"/invitations", invite, tok...); r.Status != http.StatusCreated {
			t.Fatalf("token invite as admin: %d %s", r.Status, r.Body)
		}

		opsID := memberID(t, e, admin, e.acme.ID, "ops@example.com")
		if r := e.call(t, admin, "PATCH", o+"/members/"+opsID, map[string]string{"role": "member"}); r.Status != http.StatusNoContent {
			t.Fatalf("demote: %d", r.Status)
		}
		if r := e.call(t, nil, "POST", o+"/invitations", invite, tok...); r.Status != http.StatusForbidden {
			t.Fatalf("token kept admin rights after creator demotion: %d", r.Status)
		}

		if r := e.call(t, admin, "DELETE", o+"/members/"+opsID, nil); r.Status != http.StatusNoContent {
			t.Fatalf("remove: %d", r.Status)
		}
		if r := e.call(t, nil, "GET", o, nil, tok...); r.Status != http.StatusUnauthorized {
			t.Fatalf("token survived creator removal: %d", r.Status)
		}
	})
}

// mustLogin signs the user in once (creating the user record) and returns the email.
func mustLogin(t *testing.T, e *env, c oidctest.Claims) string {
	t.Helper()
	e.login(t, e.browser(t), c)
	return c.Email
}

func TestRequireMFA(t *testing.T) {
	e := setup(t)
	o := "/orgs/" + e.acme.ID.String()
	e.grant(t, e.acme.ID, mustLogin(t, e, dev), "member")

	admin := e.browser(t)
	e.login(t, admin, acmeAdmin)
	_, me := getMe(t, admin, e.api.URL)
	if me.Session.Mfa {
		t.Fatal("password login reported as MFA")
	}

	if r := e.call(t, admin, "PATCH", o, map[string]bool{"require_mfa": true}); r.Status != http.StatusForbidden || r.code() != "mfa_required" {
		t.Fatalf("enable without MFA: %d %s", r.Status, r.Body)
	}

	withMFA := acmeAdmin
	withMFA.AMR = []string{"pwd", "otp"}
	e.login(t, admin, withMFA)
	if _, me := getMe(t, admin, e.api.URL); !me.Session.Mfa || me.Session.AuthenticatedAt == nil {
		t.Fatalf("MFA session not recorded: %+v", me.Session)
	}
	r := e.call(t, admin, "PATCH", o, map[string]bool{"require_mfa": true})
	var org httpapi.Organization
	r.decode(t, &org)
	if r.Status != http.StatusOK || !org.RequireMfa {
		t.Fatalf("enable with MFA: %d %s", r.Status, r.Body)
	}

	member := e.browser(t)
	e.login(t, member, dev)
	if r := e.call(t, member, "GET", o+"/members", nil); r.Status != http.StatusForbidden || r.code() != "mfa_required" {
		t.Fatalf("member without MFA: %d %s", r.Status, r.Body)
	}
	if status, me := getMe(t, member, e.api.URL); status != http.StatusOK || !me.Organizations[0].RequireMfa {
		t.Fatalf("/me must still work and show the requirement: %d %+v", status, me.Organizations)
	}

	withACR := dev
	withACR.ACR = "unknown-level"
	e.login(t, member, withACR)
	if r := e.call(t, member, "GET", o+"/members", nil); r.Status != http.StatusForbidden {
		t.Fatalf("unconfigured acr counted as MFA: %d", r.Status)
	}
	devMFA := dev
	devMFA.AMR = []string{"mfa"}
	e.login(t, member, devMFA)
	if r := e.call(t, member, "GET", o+"/members", nil); r.Status != http.StatusOK {
		t.Fatalf("member with MFA: %d %s", r.Status, r.Body)
	}
}
