package httpapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/fake"
	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity/oidctest"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/workflows"
)

// gov is an organization with staging and production environments, a fake
// connection, and people in the blueprint roles.
type gov struct {
	*env
	o                         string // "/orgs/<id>"
	staging, prod, conn       uuid.UUID
	admin, dev, ap1, ap2, aud *http.Client
	devID, ap1ID              uuid.UUID
}

var (
	devClaims = oidctest.Claims{Subject: "u-dev", Email: "dev@example.com", EmailVerified: true}
	ap1Claims = oidctest.Claims{Subject: "u-ap1", Email: "ap1@example.com", EmailVerified: true, AMR: []string{"mfa"}}
	ap2Claims = oidctest.Claims{Subject: "u-ap2", Email: "ap2@example.com", EmailVerified: true, AMR: []string{"mfa"}}
	audClaims = oidctest.Claims{Subject: "u-aud", Email: "aud@example.com", EmailVerified: true}
)

func newGov(t *testing.T) *gov {
	t.Helper()
	g := &gov{env: setup(t)}
	g.o = "/orgs/" + g.acme.ID.String()
	g.admin = g.browser(t)
	g.login(t, g.admin, acmeAdmin)
	_, me := getMe(t, g.admin, g.api.URL)

	g.staging = g.createEnv(t, "staging", "staging")
	g.prod = g.createEnv(t, "prod", "production")

	// Organization admins have no resource permissions until bound.
	if r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]string{"name": "vault", "provider": "fake"}); r.Status != http.StatusForbidden {
		t.Fatalf("unbound admin created a connection: %d", r.Status)
	}
	g.bind(t, me.User.Id, "cloud_admin", uuid.Nil)
	r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]any{"name": "vault", "provider": "fake", "config": map[string]string{"region": "test"}})
	if r.Status != http.StatusCreated {
		t.Fatalf("create connection: %d %s", r.Status, r.Body)
	}
	var conn httpapi.Connection
	r.decode(t, &conn)
	g.conn = conn.Id

	g.dev, g.devID = g.person(t, devClaims, "member")
	g.bind(t, g.devID, "developer", uuid.Nil)
	g.bind(t, g.devID, "secret_admin", g.prod)
	g.ap1, g.ap1ID = g.person(t, ap1Claims, "member")
	g.bind(t, g.ap1ID, "approver", uuid.Nil)
	var ap2ID uuid.UUID
	g.ap2, ap2ID = g.person(t, ap2Claims, "member")
	g.bind(t, ap2ID, "approver", g.prod)
	var audID uuid.UUID
	g.aud, audID = g.person(t, audClaims, "member")
	g.bind(t, audID, "auditor", uuid.Nil)
	return g
}

func (g *gov) createEnv(t *testing.T, name, kind string) uuid.UUID {
	t.Helper()
	r := g.call(t, g.admin, "POST", g.o+"/environments", map[string]string{"name": name, "kind": kind})
	if r.Status != http.StatusCreated {
		t.Fatalf("create environment: %d %s", r.Status, r.Body)
	}
	var e httpapi.Environment
	r.decode(t, &e)
	return e.Id
}

// person signs a user in, makes them a member and returns their client and ID.
func (g *gov) person(t *testing.T, c oidctest.Claims, role string) (*http.Client, uuid.UUID) {
	t.Helper()
	client := g.browser(t)
	g.login(t, client, c)
	g.grant(t, g.acme.ID, c.Email, role)
	_, me := getMe(t, client, g.api.URL)
	return client, me.User.Id
}

func (g *gov) bind(t *testing.T, user uuid.UUID, role string, env uuid.UUID) {
	t.Helper()
	body := map[string]any{"user_id": user, "role": role}
	if env != uuid.Nil {
		body["environment_id"] = env
	}
	if r := g.call(t, g.admin, "POST", g.o+"/role-bindings", body); r.Status != http.StatusCreated {
		t.Fatalf("bind %s: %d %s", role, r.Status, r.Body)
	}
}

func (g *gov) submit(t *testing.T, c *http.Client, body map[string]any, headers ...string) (response, httpapi.ChangeRequest) {
	t.Helper()
	r := g.call(t, c, "POST", g.o+"/change-requests", body, headers...)
	var cr httpapi.ChangeRequest
	if r.Status == http.StatusCreated {
		r.decode(t, &cr)
	}
	return r, cr
}

func (g *gov) mustSubmit(t *testing.T, c *http.Client, body map[string]any) httpapi.ChangeRequest {
	t.Helper()
	r, cr := g.submit(t, c, body)
	if r.Status != http.StatusCreated {
		t.Fatalf("submit: %d %s", r.Status, r.Body)
	}
	return cr
}

func (g *gov) create(env uuid.UUID, name, value string) map[string]any {
	return map[string]any{"operation": "create", "connection_id": g.conn, "environment_id": env,
		"name": name, "classification": "confidential", "value": value, "reason": "test"}
}

func (g *gov) decide(t *testing.T, c *http.Client, id uuid.UUID, decision, hash string) response {
	t.Helper()
	return g.call(t, c, "POST", g.o+"/change-requests/"+id.String()+"/decisions",
		map[string]string{"decision": decision, "binding_hash": hash})
}

func (g *gov) run(t *testing.T, id uuid.UUID) error {
	t.Helper()
	return g.exec.Execute(context.Background(), g.acme.ID, id)
}

func (g *gov) get(t *testing.T, id uuid.UUID) httpapi.ChangeRequest {
	t.Helper()
	var cr httpapi.ChangeRequest
	r := g.call(t, g.dev, "GET", g.o+"/change-requests/"+id.String(), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("get change request: %d %s", r.Status, r.Body)
	}
	r.decode(t, &cr)
	return cr
}

func (g *gov) expectStatus(t *testing.T, id uuid.UUID, status httpapi.ChangeRequestStatus, failure string) httpapi.ChangeRequest {
	t.Helper()
	cr := g.get(t, id)
	got := ""
	if cr.FailureCode != nil {
		got = *cr.FailureCode
	}
	if cr.Status != status || got != failure {
		t.Fatalf("status %s/%q, want %s/%q", cr.Status, got, status, failure)
	}
	return cr
}

// failureReasons returns the policy reasons recorded in the audit log.
func (g *gov) auditActions(t *testing.T, cr uuid.UUID) []string {
	t.Helper()
	var out []string
	ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: g.acme.ID})
	_ = postgres.Tx(ctx, g.db.App, func(tx pgx.Tx) error {
		recs, err := audit.List(ctx, tx, g.acme.ID, 0, 500)
		for _, r := range recs {
			if r.ChangeRequestID == cr {
				out = append([]string{r.Action + detailSuffix(r.Details)}, out...)
			}
		}
		return err
	})
	return out
}

func detailSuffix(d map[string]string) string {
	if d["policy_reasons"] != "" {
		return ":" + d["policy_reasons"]
	}
	return ""
}

func TestChangeLifecycle(t *testing.T) {
	g := newGov(t)
	values := []string{"staging-pw-1f7c", "prod-pw-9a2e", "prod-pw-rotated-44b1"}

	// Staging needs no approval: approved on submission, executed by the worker.
	cr := g.mustSubmit(t, g.dev, g.create(g.staging, "db/password", values[0]))
	if cr.Status != httpapi.ChangeRequestStatusApproved || cr.RequiredApprovals != 0 {
		t.Fatalf("staging create: %+v", cr)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	done := g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	ref := fake.Ref(g.conn, "db/password")
	if v, ver, ok := g.vault.Current(ref); !ok || v != values[0] || ver != "v1" || done.CloudRequestId == nil {
		t.Fatalf("vault %q %q %v, cloud request %v", v, ver, ok, done.CloudRequestId)
	}

	// Production create needs one approval from someone else, recently
	// authenticated, who approves exactly the reviewed binding.
	cr = g.mustSubmit(t, g.dev, g.create(g.prod, "api/key", values[1]))
	if cr.Status != httpapi.ChangeRequestStatusPending || cr.RequiredApprovals != 1 {
		t.Fatalf("production create: %+v", cr)
	}
	if !g.vault.Staged(fmt.Sprintf("fake-staging://%s/%s", g.conn, cr.Id)) {
		t.Fatal("value not staged in the provider")
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusPending, "") // worker ignores pending requests
	if _, _, ok := g.vault.Current(fake.Ref(g.conn, "api/key")); ok {
		t.Fatal("pending change reached the provider")
	}

	stale := g.browser(t)
	old := ap1Claims
	old.AuthTime = time.Now().Add(-time.Hour)
	g.login(t, stale, old)
	if r := g.decide(t, stale, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusUnauthorized || r.code() != "step_up_required" {
		t.Fatalf("stale approver: %d %s", r.Status, r.Body)
	}
	if r := g.decide(t, g.ap1, cr.Id, "approve", strings.Repeat("0", 64)); r.Status != http.StatusConflict || r.code() != "binding_mismatch" {
		t.Fatalf("wrong binding: %d %s", r.Status, r.Body)
	}
	r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash)
	if r.Status != http.StatusOK {
		t.Fatalf("approve: %d %s", r.Status, r.Body)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	created := g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	prodSecret := *created.SecretId
	if v, _, _ := g.vault.Current(fake.Ref(g.conn, "api/key")); v != values[1] {
		t.Fatalf("vault has %q", v)
	}
	if g.vault.Staged(fmt.Sprintf("fake-staging://%s/%s", g.conn, cr.Id)) {
		t.Fatal("staged value not discarded after promotion")
	}

	// Update: one approval.
	cr = g.mustSubmit(t, g.dev, map[string]any{"operation": "update", "secret_id": prodSecret, "value": values[2]})
	if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("approve update: %d %s", r.Status, r.Body)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	if v, ver, _ := g.vault.Current(fake.Ref(g.conn, "api/key")); v != values[2] || ver != "v2" {
		t.Fatalf("after update: %q %q", v, ver)
	}

	// Delete in production: two approvals by different people.
	cr = g.mustSubmit(t, g.dev, map[string]any{"operation": "delete", "secret_id": prodSecret})
	if cr.RequiredApprovals != 2 {
		t.Fatalf("production delete requires %d approvals", cr.RequiredApprovals)
	}
	if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("first approval: %d", r.Status)
	}
	if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusConflict || r.code() != "already_decided" {
		t.Fatalf("same approver twice: %d %s", r.Status, r.Body)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusPending, "")
	if r := g.decide(t, g.ap2, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("second approval: %d %s", r.Status, r.Body)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	if _, _, ok := g.vault.Current(fake.Ref(g.conn, "api/key")); ok {
		t.Fatal("secret not deleted")
	}

	// Rejection ends a request; it never executes.
	cr = g.mustSubmit(t, g.dev, g.create(g.prod, "rejected/one", "never-promoted-77"))
	if r := g.decide(t, g.ap1, cr.Id, "reject", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("reject: %d", r.Status)
	}
	_ = g.run(t, cr.Id)
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusRejected, "")
	values = append(values, "never-promoted-77")

	t.Run("secret values are never stored by SecretMesh", func(t *testing.T) {
		rows, err := g.db.Owner.Query(context.Background(),
			`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
		if err != nil {
			t.Fatal(err)
		}
		tables, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, table := range tables {
			var dump string
			// Table names come from pg_tables and are quoted.
			// nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query, go.lang.security.audit.sqli.pgx-sqli.pgx-sqli
			q := `SELECT coalesce(string_agg(row_to_json(t)::text, ''), '') FROM ` + pgx.Identifier{table}.Sanitize() + ` t`
			if err := g.db.Owner.QueryRow(context.Background(), q).Scan(&dump); err != nil {
				t.Fatal(err)
			}
			for _, v := range values {
				if strings.Contains(dump, v) {
					t.Errorf("table %s contains a secret value", table)
				}
			}
		}
	})

	t.Run("audit trail is complete and verifiable", func(t *testing.T) {
		r := g.call(t, g.dev, "GET", g.o+"/audit/events", nil)
		if r.Status != http.StatusForbidden {
			t.Fatalf("developer read audit: %d", r.Status)
		}
		var evs struct{ Events []httpapi.AuditEvent }
		g.call(t, g.aud, "GET", g.o+"/audit/events?limit=500", nil).decode(t, &evs)
		var actions []string
		for _, e := range evs.Events {
			actions = append(actions, e.Action)
			for _, v := range values {
				for _, d := range e.Details {
					if strings.Contains(d, v) {
						t.Errorf("audit event %s contains a secret value", e.Action)
					}
				}
			}
		}
		for _, want := range []string{"role_binding.created", "connection.created", "change_request.submitted",
			"change_request.decision", "change_request.approved", "change_request.execution_started",
			"change_request.executed", "change_request.rejected"} {
			if !slices.Contains(actions, want) {
				t.Errorf("no %s event", want)
			}
		}
		if n, err := audit.CheckpointDue(context.Background(), g.db.App, g.keyring); err != nil || n != 1 {
			t.Fatalf("checkpoint: %d %v", n, err)
		}
		var v httpapi.AuditVerification
		g.call(t, g.aud, "GET", g.o+"/audit/verification", nil).decode(t, &v)
		if !v.Valid || v.CheckpointsVerified != 1 || v.EventsChecked != int64(len(evs.Events)) {
			t.Fatalf("verification: %+v", v)
		}
	})
}

func TestGateBypassesFailClosed(t *testing.T) {
	g := newGov(t)

	// A developer bound to staging only cannot touch production.
	stagingDev, stagingDevID := g.person(t, oidctest.Claims{Subject: "u-sd", Email: "sd@example.com", EmailVerified: true}, "member")
	g.bind(t, stagingDevID, "developer", g.staging)
	if r, _ := g.submit(t, stagingDev, g.create(g.prod, "x", "v")); r.Status != http.StatusForbidden {
		t.Fatalf("staging developer created in production: %d %s", r.Status, r.Body)
	}
	if r, _ := g.submit(t, stagingDev, g.create(g.staging, "x", "v")); r.Status != http.StatusCreated {
		t.Fatalf("staging developer in staging: %d %s", r.Status, r.Body)
	}

	// Members without bindings can do nothing with secrets.
	plain, _ := g.person(t, oidctest.Claims{Subject: "u-plain", Email: "plain@example.com", EmailVerified: true}, "member")
	if r, _ := g.submit(t, plain, g.create(g.staging, "y", "v")); r.Status != http.StatusForbidden {
		t.Fatalf("unbound member submitted: %d", r.Status)
	}
	var list struct{ Secrets, ChangeRequests []any }
	g.call(t, plain, "GET", g.o+"/change-requests", nil).decode(t, &list)
	if len(list.ChangeRequests) != 0 {
		t.Fatal("unbound member sees change requests")
	}

	cr := g.mustSubmit(t, g.dev, g.create(g.prod, "prod/secret", "v-prod"))

	// The requester cannot approve, even with an approver binding.
	g.bind(t, g.devID, "approver", uuid.Nil)
	if r := g.decide(t, g.dev, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusForbidden || r.code() != "self_approval" {
		t.Fatalf("self approval: %d %s", r.Status, r.Body)
	}
	// An approver bound to staging cannot approve production.
	stagingApprover, sid := g.person(t, oidctest.Claims{Subject: "u-sa", Email: "sa@example.com", EmailVerified: true, AMR: []string{"mfa"}}, "member")
	g.bind(t, sid, "approver", g.staging)
	if r := g.decide(t, stagingApprover, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusForbidden {
		t.Fatalf("staging approver approved production: %d", r.Status)
	}
	// Non-members of another tenant see nothing.
	globex := g.browser(t)
	g.login(t, globex, globexAdmin)
	if r := g.call(t, globex, "GET", g.o+"/change-requests/"+cr.Id.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("other tenant: %d", r.Status)
	}

	// Tokens: secrets:read cannot submit; secrets:write can (within the
	// creator's bindings); no token can approve.
	admin := g.admin
	readTok, _ := createToken(t, g.env, admin, g.acme.ID, "secrets:read")
	if r, _ := g.submit(t, nil, g.create(g.staging, "t1", "v"), bearer(readTok)...); r.Status != http.StatusForbidden {
		t.Fatalf("read token submitted: %d", r.Status)
	}
	// The admin is only a cloud_admin, so even a write token cannot create secrets.
	writeTok, _ := createToken(t, g.env, admin, g.acme.ID, "secrets:write")
	if r, _ := g.submit(t, nil, g.create(g.staging, "t2", "v"), bearer(writeTok)...); r.Status != http.StatusForbidden {
		t.Fatalf("token exceeded its creator's bindings: %d", r.Status)
	}
	r := g.call(t, nil, "POST", g.o+"/change-requests/"+cr.Id.String()+"/decisions",
		map[string]string{"decision": "approve", "binding_hash": cr.BindingHash}, bearer(writeTok)...)
	if r.Status != http.StatusForbidden {
		t.Fatalf("token approved: %d", r.Status)
	}

	// A second open request for the same secret is refused.
	if r, _ := g.submit(t, g.dev, g.create(g.prod, "prod/secret", "other")); r.Status != http.StatusConflict {
		t.Fatalf("concurrent request: %d %s", r.Status, r.Body)
	}
	// Approvals cannot be replayed onto another request.
	other := g.mustSubmit(t, g.dev, g.create(g.prod, "prod/other", "v2"))
	if r := g.decide(t, g.ap1, other.Id, "approve", cr.BindingHash); r.Status != http.StatusConflict || r.code() != "binding_mismatch" {
		t.Fatalf("reused binding: %d %s", r.Status, r.Body)
	}
	// Credentials are refused in connection config.
	if r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]any{"name": "bad", "provider": "fake",
		"config": map[string]string{"secret_access_key": "AKIA..."}}); r.Status != http.StatusBadRequest {
		t.Fatalf("credential in config: %d", r.Status)
	}
	if r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]any{"name": "gcp", "provider": "gcp"}); r.Status != http.StatusBadRequest || r.code() != "provider_unavailable" {
		t.Fatalf("unavailable provider: %d %s", r.Status, r.Body)
	}
}

func TestWorkerRechecksGates(t *testing.T) {
	g := newGov(t)

	approved := func(t *testing.T, name string, approver *http.Client) httpapi.ChangeRequest {
		t.Helper()
		cr := g.mustSubmit(t, g.dev, g.create(g.prod, name, "value-"+name))
		if approver != nil {
			if r := g.decide(t, approver, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
				t.Fatalf("approve: %d %s", r.Status, r.Body)
			}
		}
		return cr
	}

	t.Run("replayed execution applies once", func(t *testing.T) {
		cr := approved(t, "replay", g.ap1)
		before := g.vault.Applied()
		for range 3 {
			if err := g.run(t, cr.Id); err != nil {
				t.Fatal(err)
			}
		}
		if g.vault.Applied() != before+1 {
			t.Fatalf("applied %d times", g.vault.Applied()-before)
		}
	})

	t.Run("tampered staged value is not promoted", func(t *testing.T) {
		cr := approved(t, "tamper", g.ap1)
		g.vault.Tamper(fmt.Sprintf("fake-staging://%s/%s", g.conn, cr.Id), "attacker-value")
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "staged_value_tampered")
		if _, _, ok := g.vault.Current(fake.Ref(g.conn, "tamper")); ok {
			t.Fatal("tampered value promoted")
		}
	})

	t.Run("changed request fields invalidate the approval", func(t *testing.T) {
		cr := approved(t, "fields", g.ap1)
		if _, err := g.db.Owner.Exec(context.Background(),
			`UPDATE change_requests SET secret_name = 'other-target' WHERE id = $1`, cr.Id); err != nil {
			t.Fatal(err)
		}
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
		if acts := g.auditActions(t, cr.Id); !slices.Contains(acts, "change_request.execution_denied:payload_changed") {
			t.Fatalf("audit: %v", acts)
		}
	})

	t.Run("forged approval status is caught at the worker", func(t *testing.T) {
		cr := approved(t, "forged", nil)
		if _, err := g.db.Owner.Exec(context.Background(),
			`UPDATE change_requests SET status = 'approved' WHERE id = $1`, cr.Id); err != nil {
			t.Fatal(err)
		}
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
		acts := g.auditActions(t, cr.Id)
		if !slices.ContainsFunc(acts, func(a string) bool { return strings.Contains(a, "insufficient_approvals") }) {
			t.Fatalf("audit: %v", acts)
		}
	})

	t.Run("approver who lost the role no longer counts", func(t *testing.T) {
		tmp, tmpID := g.person(t, oidctest.Claims{Subject: "u-tmp", Email: "tmp@example.com", EmailVerified: true, AMR: []string{"mfa"}}, "member")
		g.bind(t, tmpID, "approver", g.prod)
		cr := approved(t, "lost-role", tmp)
		if _, err := g.db.Owner.Exec(context.Background(), `DELETE FROM role_bindings WHERE user_id = $1`, tmpID); err != nil {
			t.Fatal(err)
		}
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
	})

	t.Run("requester who left cannot have the change executed", func(t *testing.T) {
		leaver, leaverID := g.person(t, oidctest.Claims{Subject: "u-leave", Email: "leave@example.com", EmailVerified: true}, "member")
		g.bind(t, leaverID, "developer", uuid.Nil)
		cr := g.mustSubmit(t, leaver, g.create(g.staging, "leaver", "leaver-value"))
		if r := g.call(t, g.admin, "DELETE", g.o+"/members/"+leaverID.String(), nil); r.Status != http.StatusNoContent {
			t.Fatalf("remove: %d", r.Status)
		}
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
	})

	t.Run("production approval without MFA is refused", func(t *testing.T) {
		noMFA, id := g.person(t, oidctest.Claims{Subject: "u-nomfa", Email: "nomfa@example.com", EmailVerified: true}, "member")
		g.bind(t, id, "approver", g.prod)
		cr := approved(t, "no-mfa", noMFA)
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
		acts := g.auditActions(t, cr.Id)
		if !slices.ContainsFunc(acts, func(a string) bool { return strings.Contains(a, "production_requires_mfa") }) {
			t.Fatalf("audit: %v", acts)
		}
	})

	t.Run("approval that expired while queued is refused", func(t *testing.T) {
		cr := approved(t, "late", g.ap1)
		g.exec.Now = func() time.Time { return time.Now().Add(100 * time.Hour) }
		defer func() { g.exec.Now = time.Now }()
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
	})

	t.Run("expired pending requests are closed and staging destroyed", func(t *testing.T) {
		cr := approved(t, "expiring", nil)
		staging := fmt.Sprintf("fake-staging://%s/%s", g.conn, cr.Id)
		if _, err := g.db.Owner.Exec(context.Background(),
			`UPDATE change_requests SET expires_at = now() - interval '1 second' WHERE id = $1`, cr.Id); err != nil {
			t.Fatal(err)
		}
		if n, err := g.approvals.ExpireDue(context.Background()); err != nil || n != 1 {
			t.Fatalf("expire: %d %v", n, err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusExpired, "")
		if err := g.approvals.DiscardStaging(context.Background(), g.acme.ID, cr.Id); err != nil {
			t.Fatal(err)
		}
		if g.vault.Staged(staging) {
			t.Fatal("staged value survived expiry")
		}
	})

	t.Run("cancel is limited to the requester", func(t *testing.T) {
		cr := approved(t, "cancel-me", nil)
		if r := g.call(t, g.ap1, "POST", g.o+"/change-requests/"+cr.Id.String()+"/cancel", nil); r.Status != http.StatusForbidden {
			t.Fatalf("other user cancelled: %d", r.Status)
		}
		if r := g.call(t, g.dev, "POST", g.o+"/change-requests/"+cr.Id.String()+"/cancel", nil); r.Status != http.StatusNoContent {
			t.Fatalf("cancel: %d", r.Status)
		}
		if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusConflict {
			t.Fatalf("approved a cancelled request: %d", r.Status)
		}
	})
}

func TestExecutionRecovery(t *testing.T) {
	g := newGov(t)

	t.Run("lost provider response is reconciled without re-applying", func(t *testing.T) {
		cr := g.mustSubmit(t, g.dev, g.create(g.staging, "lost", "lost-value"))
		g.vault.LoseNextResponse()
		before := g.vault.Applied()
		if err := g.run(t, cr.Id); !errors.Is(err, connectors.ErrTransient) {
			t.Fatalf("want transient error, got %v", err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusExecuting, "")

		// The reconciler finds the stale intent and completes it from provider state.
		if n, err := g.exec.ReconcileStale(context.Background(), 0); err != nil || n != 1 {
			t.Fatalf("reconcile: %d %v", n, err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
		if g.vault.Applied() != before+1 {
			t.Fatalf("applied %d times", g.vault.Applied()-before)
		}
		if acts := g.auditActions(t, cr.Id); acts[len(acts)-1] != "change_request.executed" {
			t.Fatalf("audit: %v", acts)
		}
	})

	t.Run("failure before applying is retried once applied", func(t *testing.T) {
		cr := g.mustSubmit(t, g.dev, g.create(g.staging, "retry", "retry-value"))
		g.vault.FailNext(fmt.Errorf("%w: throttled", connectors.ErrTransient))
		before := g.vault.Applied()
		if err := g.run(t, cr.Id); err == nil {
			t.Fatal("expected error")
		}
		if err := g.run(t, cr.Id); err != nil {
			t.Fatal(err)
		}
		g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
		if g.vault.Applied() != before+1 {
			t.Fatalf("applied %d times", g.vault.Applied()-before)
		}
	})
}

func TestRiverWorkerEndToEnd(t *testing.T) {
	g := newGov(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker, err := workflows.New(g.db.App, workflows.Config{
		Work: true, Executor: g.exec, Approvals: g.approvals, Registry: g.registry, Keyring: g.keyring, Logger: g.logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Stop(context.Background()) }()

	cr := g.mustSubmit(t, g.dev, g.create(g.staging, "via-river", "river-value"))
	rejected := g.mustSubmit(t, g.dev, g.create(g.prod, "via-river-rejected", "rejected-value"))
	if r := g.decide(t, g.ap1, rejected.Id, "reject", rejected.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("reject: %d", r.Status)
	}
	staging := fmt.Sprintf("fake-staging://%s/%s", g.conn, rejected.Id)

	deadline := time.Now().Add(20 * time.Second)
	for {
		done := g.get(t, cr.Id).Status == httpapi.ChangeRequestStatusSucceeded && !g.vault.Staged(staging)
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not finish: %s, rejected staging present %v", g.get(t, cr.Id).Status, g.vault.Staged(staging))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if v, _, _ := g.vault.Current(fake.Ref(g.conn, "via-river")); v != "river-value" {
		t.Fatalf("vault has %q", v)
	}

	// Job arguments carry identifiers only.
	var args string
	if err := g.db.Owner.QueryRow(context.Background(), `SELECT string_agg(args::text, ' ') FROM river_job`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(args, "river-value") || strings.Contains(args, "rejected-value") {
		t.Fatal("job arguments contain a secret value")
	}
}
