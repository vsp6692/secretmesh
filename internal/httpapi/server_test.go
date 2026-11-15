package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/connectors"
	awsconn "github.com/secretmesh/secretmesh/internal/connectors/aws"
	"github.com/secretmesh/secretmesh/internal/connectors/fake"
	"github.com/secretmesh/secretmesh/internal/execution"
	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity"
	"github.com/secretmesh/secretmesh/internal/identity/oidctest"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/postgres/pgtest"
	"github.com/secretmesh/secretmesh/internal/policy"
	"github.com/secretmesh/secretmesh/internal/rotation"
	"github.com/secretmesh/secretmesh/internal/tenancy"
	"github.com/secretmesh/secretmesh/internal/workflows"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
	"github.com/secretmesh/secretmesh/policies"
)

const adminEmail = "admin@example.com"

type env struct {
	api  *httptest.Server
	idp  *oidctest.Provider
	db   *pgtest.DB
	acme tenancy.Organization

	vault     *fake.Vault
	registry  *connectors.Registry
	keyring   keys.Keyring
	approvals *approvals.Service
	exec      *execution.Executor
	jobs      *workflows.Client
	rotation  *rotation.Service
	deliverer *notify.Deliverer
	mail      *mailSink
	slack     *slackSink
	logger    *slog.Logger
}

func setup(t *testing.T) *env {
	t.Helper()
	db := pgtest.New(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	tenants := tenancy.NewStore(db.App)
	org, err := tenants.EnsureOrganization(ctx, "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	idp := oidctest.New(t, "secretmesh", "test-client-secret")
	api := httptest.NewServer(nil)
	t.Cleanup(api.Close)
	publicURL, _ := url.Parse(api.URL)

	identities := identity.NewStore(db.App)
	idSvc := identity.NewService(identity.Config{
		Issuer:       idp.URL,
		ClientID:     idp.ClientID,
		ClientSecret: sensitive.FromString(idp.ClientSecret),
		PublicURL:    publicURL,
		CookieSecure: false, // httptest serves plain HTTP
		SessionTTL:   time.Hour,
		MFAMethods:   []string{"mfa", "otp", "hwk"},
	}, identities, identity.LoginHooks(
		tenancy.AcceptInvitationsHook(tenants),
		tenancy.BootstrapAdminHook(tenants, org, adminEmail),
	), logger)

	keyring, err := keys.NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	vault := fake.New()
	registry := connectors.NewRegistry()
	registry.Register(fake.Provider, vault.Factory)
	if endpoint := os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT"); endpoint != "" {
		t.Setenv("AWS_ACCESS_KEY_ID", "test")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
		t.Setenv("AWS_REGION", "us-east-1")
		p, err := awsconn.New(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		registry.Register(awsconn.ProviderName, p.Factory)
	}
	engine, err := policy.New(ctx, policies.Execution)
	if err != nil {
		t.Fatal(err)
	}
	svc := approvals.NewService(db.App, registry, keyring, nil, logger)
	exec := execution.NewExecutor(db.App, registry, keyring, engine, logger)
	rotationEngine, err := policy.NewRotation(ctx, policies.Rotation)
	if err != nil {
		t.Fatal(err)
	}
	rot := rotation.NewService(db.App, registry, rotation.DefaultPlugins(), rotationEngine, logger)
	mail, slack := newMailSink(t), newSlackSink(t)
	deliverer := notify.NewDeliverer(db.App, registry,
		&notify.SMTP{Addr: mail.addr, From: "SecretMesh <secretmesh@example.com>", TLS: "none"},
		&notify.Slack{Prefixes: []string{slack.URL + "/"}}, "http://secretmesh.test", logger)
	// Insert-only: tests run jobs explicitly through exec, except the River
	// end-to-end test, which starts its own working client.
	jobs, err := workflows.New(db.App, workflows.Config{
		Executor: exec, Approvals: svc, Registry: registry, Keyring: keyring, Logger: logger,
		Rotation: rot, Deliverer: deliverer,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetJobs(jobs)
	rot.SetJobs(jobs)

	api.Config.Handler = httpapi.NewRouter(httpapi.Deps{
		Pool: db.App, Identity: idSvc, Identities: identities, Tenancy: tenants, Logger: logger,
		Inventory: inventory.NewStore(db.App), Approvals: svc, Connectors: registry, Keyring: keyring,
		Discovery: inventory.NewDiscovery(db.App, registry, logger), Rotation: rot, Deliverer: deliverer,
	})
	return &env{api: api, idp: idp, db: db, acme: org, vault: vault, registry: registry, keyring: keyring,
		approvals: svc, exec: exec, jobs: jobs, rotation: rot, deliverer: deliverer, mail: mail, slack: slack, logger: logger}
}

// browser follows redirects through the IdP but stops on arrival back at the
// app (any non-/auth/ path).
func (e *env) browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), e.api.URL) && !strings.HasPrefix(req.URL.Path, "/auth/") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (e *env) login(t *testing.T, c *http.Client, claims oidctest.Claims) {
	t.Helper()
	if res := e.loginWith(t, c, claims, ""); res.Status != http.StatusFound || res.Location != e.api.URL+"/" {
		t.Fatalf("login: status %d location %q body %s", res.Status, res.Location, res.Body)
	}
}

// loginWith runs the login flow with extra /auth/login query parameters and
// returns the final response from the app.
func (e *env) loginWith(t *testing.T, c *http.Client, claims oidctest.Claims, query string) response {
	t.Helper()
	e.idp.SetUser(claims)
	res, err := c.Get(e.api.URL + "/auth/login?" + query)
	if err != nil {
		t.Fatal(err)
	}
	return read(t, res)
}

type response struct {
	Status   int
	Location string
	Body     []byte
}

func read(t *testing.T, res *http.Response) response {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{Status: res.StatusCode, Location: res.Header.Get("Location"), Body: b}
}

// code returns the API error code of the response, if any.
func (r response) code() string {
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Error.Code
}

func (r response) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
}

// call sends a JSON API request. headers are key, value pairs.
func (e *env) call(t *testing.T, c *http.Client, method, path string, body any, headers ...string) response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.api.URL+"/api/v1"+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if c == nil {
		c = http.DefaultClient
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return read(t, res)
}

// grant makes the user with email a member of org directly in the database.
func (e *env) grant(t *testing.T, org uuid.UUID, email, role string) {
	t.Helper()
	tag, err := e.db.Owner.Exec(context.Background(), `
		INSERT INTO memberships (organization_id, user_id, role)
		SELECT $1, id, $3 FROM users WHERE email = $2`, org, email, role)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("grant %s: %v (rows %d)", email, err, tag.RowsAffected())
	}
}

func getMe(t *testing.T, c *http.Client, base string) (int, httpapi.Me) {
	t.Helper()
	res, err := c.Get(base + "/api/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var me httpapi.Me
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&me); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, me
}

func TestLoginFlow(t *testing.T) {
	e := setup(t)

	t.Run("unauthenticated request is rejected", func(t *testing.T) {
		if status, _ := getMe(t, http.DefaultClient, e.api.URL); status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", status)
		}
	})

	t.Run("bootstrap admin gets org_admin", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-admin", Email: adminEmail, EmailVerified: true, Name: "Admin"})

		status, me := getMe(t, c, e.api.URL)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		if string(me.User.Email) != adminEmail || len(me.Organizations) != 1 ||
			me.Organizations[0].Slug != "acme" || me.Organizations[0].Role != httpapi.RoleOrgAdmin {
			t.Fatalf("unexpected /me: %+v", me)
		}

		// Logging in again must not duplicate the user or membership.
		e.login(t, c, oidctest.Claims{Subject: "u-admin", Email: adminEmail, EmailVerified: true, Name: "Admin"})
		if _, me2 := getMe(t, c, e.api.URL); me2.User.Id != me.User.Id || len(me2.Organizations) != 1 {
			t.Fatalf("re-login changed identity: %+v", me2)
		}
	})

	t.Run("unverified email does not get bootstrap admin", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-spoof", Email: adminEmail, EmailVerified: false})
		if _, me := getMe(t, c, e.api.URL); len(me.Organizations) != 0 {
			t.Fatalf("unverified user joined orgs: %+v", me.Organizations)
		}
	})

	t.Run("other users have no organizations", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})
		status, me := getMe(t, c, e.api.URL)
		if status != http.StatusOK || len(me.Organizations) != 0 {
			t.Fatalf("status %d orgs %+v", status, me.Organizations)
		}
	})

	t.Run("logout revokes the session server-side", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})

		u, _ := url.Parse(e.api.URL)
		stolen := c.Jar.Cookies(u)

		res, err := c.Post(e.api.URL+"/auth/logout", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		// Replaying the old cookie must fail even though the client still has it.
		replay := e.browser(t)
		replay.Jar.SetCookies(u, stolen)
		if status, _ := getMe(t, replay, e.api.URL); status != http.StatusUnauthorized {
			t.Fatalf("replayed session status = %d, want 401", status)
		}
	})

	t.Run("callback rejects mismatched state", func(t *testing.T) {
		c := e.browser(t)
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		res, err := c.Get(e.api.URL + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		res, err = c.Get(e.api.URL + "/auth/callback?code=x&state=forged")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", res.StatusCode)
		}
	})

	t.Run("login state is single use", func(t *testing.T) {
		c := e.browser(t)
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		e.idp.SetUser(oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})

		res, err := c.Get(e.api.URL + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		res, err = c.Get(res.Header.Get("Location")) // IdP redirects back with code+state
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		callback := res.Header.Get("Location")

		u, _ := url.Parse(e.api.URL)
		stateCookies := c.Jar.Cookies(u)

		res, err = c.Get(callback)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("first callback status = %d", res.StatusCode)
		}

		replay := e.browser(t)
		replay.Jar.SetCookies(u, stateCookies)
		res, err = replay.Get(callback)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("replayed callback status = %d, want 400", res.StatusCode)
		}
	})

	t.Run("unknown api path is authenticated first, then JSON 404", func(t *testing.T) {
		if r := e.call(t, nil, "GET", "/nope", nil); r.Status != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status %d", r.Status)
		}
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})
		if r := e.call(t, c, "GET", "/nope", nil); r.Status != http.StatusNotFound || r.code() != "not_found" {
			t.Fatalf("status %d body %s", r.Status, r.Body)
		}
	})

	t.Run("login rotates the session", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})
		u, _ := url.Parse(e.api.URL)
		first := c.Jar.Cookies(u)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})

		old := e.browser(t)
		old.Jar.SetCookies(u, first)
		if status, _ := getMe(t, old, e.api.URL); status != http.StatusUnauthorized {
			t.Fatalf("previous session still valid: %d", status)
		}
	})

	t.Run("return_to is restricted to local paths", func(t *testing.T) {
		claims := oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true}
		for query, want := range map[string]string{
			"return_to=%2Forgs%2Fx%3Ftab%3Dtokens": "/orgs/x?tab=tokens",
			"return_to=%2F%2Fevil.example":         "/",
			"return_to=https%3A%2F%2Fevil.example": "/",
			"return_to=%2F%5Cevil.example":         "/",
		} {
			if r := e.loginWith(t, e.browser(t), claims, query); r.Location != e.api.URL+want {
				t.Errorf("%s: redirected to %q, want %q", query, r.Location, e.api.URL+want)
			}
		}
	})

	t.Run("cross-origin state-changing requests are rejected", func(t *testing.T) {
		c := e.browser(t)
		e.login(t, c, oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true})
		r := e.call(t, c, "POST", "/orgs/"+e.acme.ID.String()+"/invitations",
			map[string]string{"email": "x@example.com", "role": "member"}, "Sec-Fetch-Site", "cross-site")
		if r.Status != http.StatusForbidden || r.code() != "cross_origin_request" {
			t.Fatalf("status %d body %s", r.Status, r.Body)
		}
		req, _ := http.NewRequest("POST", e.api.URL+"/auth/logout", nil)
		req.Header.Set("Origin", "https://evil.example")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if read(t, res).Status != http.StatusForbidden {
			t.Fatal("cross-origin logout accepted")
		}
	})
}
