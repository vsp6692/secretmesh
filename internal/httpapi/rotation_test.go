// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package httpapi_test

import (
	"context"
	"errors"
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
	"github.com/secretmesh/secretmesh/internal/rotation"
	"github.com/secretmesh/secretmesh/internal/workflows"
)

// secret creates a secret through an auto-approved staging change (or an
// approved production one) and returns its ID and provider reference.
func (g *gov) secret(t *testing.T, env uuid.UUID, name, value string) (uuid.UUID, string) {
	t.Helper()
	cr := g.mustSubmit(t, g.dev, g.create(env, name, value))
	if cr.Status == httpapi.ChangeRequestStatusPending {
		if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
			t.Fatalf("approve: %d %s", r.Status, r.Body)
		}
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	done := g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	return *done.SecretId, fake.Ref(g.conn, name)
}

func (g *gov) setPolicy(t *testing.T, c *http.Client, secret uuid.UUID, body map[string]any) response {
	t.Helper()
	return g.call(t, c, "PUT", g.o+"/secrets/"+secret.String()+"/rotation-policy", body)
}

// at makes the rotation service believe it is now+d.
func (g *gov) at(d time.Duration) {
	g.rotation.Now = func() time.Time { return time.Now().Add(d) }
}

func (g *gov) rotations(t *testing.T, secret uuid.UUID) []httpapi.RotationExecution {
	t.Helper()
	var out struct{ Rotations []httpapi.RotationExecution }
	r := g.call(t, g.dev, "GET", g.o+"/secrets/"+secret.String()+"/rotations", nil)
	if r.Status != http.StatusOK {
		t.Fatalf("rotations: %d %s", r.Status, r.Body)
	}
	r.decode(t, &out)
	return out.Rotations
}

func (g *gov) rotationRun(t *testing.T, id uuid.UUID) error {
	t.Helper()
	return g.rotation.Run(context.Background(), g.acme.ID, id)
}

// notifications returns event:recipient-count for the organization.
func (g *gov) notifications(t *testing.T, event string) [][]uuid.UUID {
	t.Helper()
	rows, err := g.db.Owner.Query(context.Background(),
		`SELECT recipients FROM notifications WHERE organization_id = $1 AND event = $2 ORDER BY created_at`, g.acme.ID, event)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[[]uuid.UUID])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (g *gov) secretJSON(t *testing.T, id uuid.UUID) httpapi.Secret {
	t.Helper()
	var s httpapi.Secret
	g.call(t, g.dev, "GET", g.o+"/secrets/"+id.String(), nil).decode(t, &s)
	return s
}

func TestNativeRotation(t *testing.T) {
	g := newGov(t)
	ctx := context.Background()
	g.bind(t, g.devID, "secret_admin", g.staging)
	id, ref := g.secret(t, g.staging, "db/rotating", "original-value-1")

	policy := map[string]any{"strategy": "native", "interval_days": 1}
	if r := g.setPolicy(t, g.aud, id, policy); r.Status != http.StatusForbidden {
		t.Fatalf("auditor set a policy: %d", r.Status)
	}
	if r := g.setPolicy(t, g.dev, id, policy); r.Status != http.StatusBadRequest || r.code() != "rotation_not_configured" {
		t.Fatalf("native policy without a rotation function: %d %s", r.Status, r.Body)
	}
	g.vault.EnableRotation(ref)
	r := g.setPolicy(t, g.dev, id, policy)
	if r.Status != http.StatusOK {
		t.Fatalf("set policy: %d %s", r.Status, r.Body)
	}
	var p httpapi.RotationPolicy
	r.decode(t, &p)
	if !p.Enabled || p.NextRotationAt.Before(time.Now()) || !slices.Equal(p.EscalationDays, []int{1, 3, 7}) {
		t.Fatalf("policy: %+v", p)
	}

	// Not due yet: nothing happens.
	if _, err := g.rotation.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(g.rotations(t, id)) != 0 {
		t.Fatal("rotation scheduled before it was due")
	}

	t.Run("worker killed mid-rotation recovers without rotating twice", func(t *testing.T) {
		g.at(25 * time.Hour)
		defer g.at(0)
		if _, err := g.rotation.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := g.rotation.Tick(ctx); err != nil { // idempotent
			t.Fatal(err)
		}
		g.at(0)
		exs := g.rotations(t, id)
		if len(exs) != 1 || exs[0].Status != httpapi.RotationExecutionStatusScheduled || exs[0].Trigger != httpapi.RotationExecutionTriggerSchedule {
			t.Fatalf("executions: %+v", exs)
		}
		ex := exs[0].Id

		// The provider starts rotating but the response is lost, as if the
		// worker died right after the call.
		g.vault.LoseNextResponse()
		if err := g.rotationRun(t, ex); !errors.Is(err, connectors.ErrTransient) {
			t.Fatalf("want transient error, got %v", err)
		}
		if g.rotations(t, id)[0].Status != httpapi.RotationExecutionStatusRotating {
			t.Fatal("state not persisted")
		}
		// A new worker resumes: it finds the attempt instead of starting another.
		var pending *rotation.PendingError
		if err := g.rotationRun(t, ex); !errors.As(err, &pending) {
			t.Fatalf("want pending, got %v", err)
		}
		if n := g.vault.Rotations(ref); n != 1 {
			t.Fatalf("provider rotated %d times", n)
		}
		// The reconciler (another worker) also only checks.
		if _, err := g.rotation.ReconcileStale(ctx, 0); err != nil {
			t.Fatal(err)
		}
		if n := g.vault.Rotations(ref); n != 1 {
			t.Fatalf("provider rotated %d times after reconcile", n)
		}

		g.vault.FinishRotations(false)
		if err := g.rotationRun(t, ex); err != nil {
			t.Fatal(err)
		}
		done := g.rotations(t, id)[0]
		if done.Status != httpapi.RotationExecutionStatusSucceeded || done.FinishedAt == nil {
			t.Fatalf("execution: %+v", done)
		}
		if v, ver, _ := g.vault.Current(ref); v == "original-value-1" || !strings.HasPrefix(v, "rotated-") || done.ProviderVersionId == nil || *done.ProviderVersionId != ver {
			t.Fatalf("vault %q %q, execution %+v", v, ver, done)
		}
		s := g.secretJSON(t, id)
		if s.LastRotatedAt == nil || s.NextRotationAt == nil || !s.NextRotationAt.After(time.Now().Add(23*time.Hour)) {
			t.Fatalf("secret after rotation: last %v next %v", s.LastRotatedAt, s.NextRotationAt)
		}
		// Completed: running again changes nothing.
		if err := g.rotationRun(t, ex); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rotation and changes exclude each other", func(t *testing.T) {
		mfaDev := g.browser(t)
		c := devClaims
		c.AMR = []string{"mfa"}
		g.login(t, mfaDev, c)
		r := g.call(t, mfaDev, "POST", g.o+"/secrets/"+id.String()+"/rotate", nil)
		if r.Status != http.StatusAccepted {
			t.Fatalf("rotate now: %d %s", r.Status, r.Body)
		}
		var ex httpapi.RotationExecution
		r.decode(t, &ex)
		if r := g.call(t, mfaDev, "POST", g.o+"/secrets/"+id.String()+"/rotate", nil); r.Status != http.StatusConflict {
			t.Fatalf("second rotate now: %d", r.Status)
		}
		if r, _ := g.submit(t, g.dev, map[string]any{"operation": "update", "secret_id": id, "value": "racing-value"}); r.Status != http.StatusConflict || r.code() != "rotation_in_progress" {
			t.Fatalf("change during rotation: %d %s", r.Status, r.Body)
		}
		for i := 0; i < 3; i++ {
			_ = g.rotationRun(t, ex.Id)
		}
		g.vault.FinishRotations(false)
		if err := g.rotationRun(t, ex.Id); err != nil {
			t.Fatal(err)
		}

		// A rotation that comes due while a change is open is denied by the
		// worker (gate 4), leaving the reviewed change intact.
		g.mustSubmit(t, g.dev, map[string]any{"operation": "update", "secret_id": id, "value": "reviewed-value"})
		g.at(72 * time.Hour)
		if _, err := g.rotation.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		g.at(0)
		sched := g.rotations(t, id)[0]
		if err := g.rotationRun(t, sched.Id); err != nil {
			t.Fatal(err)
		}
		if got := g.rotations(t, id)[0]; got.Status != httpapi.RotationExecutionStatusFailed || *got.ErrorCode != "policy_denied" {
			t.Fatalf("rotation during change: %+v", got)
		}
		if acts := auditDetails(t, g, "rotation.failed"); !strings.Contains(acts, "change_in_progress") {
			t.Fatalf("audit: %s", acts)
		}
	})

	t.Run("production rotate-now requires MFA", func(t *testing.T) {
		prodID, prodRef := g.secret(t, g.prod, "prod/rotating", "prod-original-2")
		g.vault.EnableRotation(prodRef)
		if r := g.setPolicy(t, g.dev, prodID, policy); r.Status != http.StatusOK {
			t.Fatalf("set policy: %d %s", r.Status, r.Body)
		}
		if r := g.call(t, g.dev, "POST", g.o+"/secrets/"+prodID.String()+"/rotate", nil); r.Status != http.StatusForbidden || r.code() != "mfa_required" {
			t.Fatalf("rotate without MFA: %d %s", r.Status, r.Body)
		}
	})
}

func TestRotationFailures(t *testing.T) {
	g := newGov(t)
	ctx := context.Background()
	g.bind(t, g.devID, "secret_admin", g.staging)
	id, ref := g.secret(t, g.staging, "svc/failing", "failing-value-1")
	g.vault.EnableRotation(ref)
	if r := g.setPolicy(t, g.dev, id, map[string]any{"strategy": "native", "interval_days": 1}); r.Status != http.StatusOK {
		t.Fatalf("set policy: %d %s", r.Status, r.Body)
	}
	owner := g.call(t, g.dev, "PATCH", g.o+"/secrets/"+id.String(), map[string]any{"owner_user_id": g.devID})
	if owner.Status != http.StatusOK {
		t.Fatalf("set owner: %d %s", owner.Status, owner.Body)
	}

	schedule := func(after time.Duration) uuid.UUID {
		t.Helper()
		g.at(after)
		if _, err := g.rotation.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		g.at(0)
		return g.rotations(t, id)[0].Id
	}

	t.Run("provider failure is recovered and reported", func(t *testing.T) {
		ex := schedule(25 * time.Hour)
		_ = g.rotationRun(t, ex)
		_ = g.rotationRun(t, ex)
		g.vault.FinishRotations(true)
		if err := g.rotationRun(t, ex); err != nil {
			t.Fatal(err)
		}
		got := g.rotations(t, id)[0]
		if got.Status != httpapi.RotationExecutionStatusFailed || *got.ErrorCode != "rotation_failed" {
			t.Fatalf("execution: %+v", got)
		}
		if v, _, _ := g.vault.Current(ref); v != "failing-value-1" {
			t.Fatal("current value changed by a failed rotation")
		}
		n := g.notifications(t, "rotation.failed")
		if len(n) != 1 || !slices.Contains(n[0], g.devID) {
			t.Fatalf("failure notification: %v", n)
		}
	})

	t.Run("a stuck rotation times out and is abandoned", func(t *testing.T) {
		r := g.call(t, g.dev, "POST", g.o+"/secrets/"+id.String()+"/rotate", nil)
		if r.Status != http.StatusAccepted {
			t.Fatalf("rotate now: %d %s", r.Status, r.Body)
		}
		var ex httpapi.RotationExecution
		r.decode(t, &ex)
		g.at(0)
		_ = g.rotationRun(t, ex.Id)
		var pending *rotation.PendingError
		if err := g.rotationRun(t, ex.Id); !errors.As(err, &pending) {
			t.Fatalf("want pending, got %v", err)
		}
		g.at(31 * time.Minute)
		defer g.at(0)
		if err := g.rotationRun(t, ex.Id); err != nil {
			t.Fatal(err)
		}
		if got := g.rotations(t, id)[0]; *got.ErrorCode != "verification_timeout" {
			t.Fatalf("execution: %+v", got)
		}
		// Abandoned in the provider, so it can never complete later.
		if g.vault.FinishRotations(false) != 0 {
			t.Fatal("abandoned rotation still in progress")
		}
	})

	t.Run("removing the rotation function fails closed", func(t *testing.T) {
		other, otherRef := g.secret(t, g.staging, "svc/no-function", "no-function-1")
		g.vault.EnableRotation(otherRef)
		if r := g.setPolicy(t, g.dev, other, map[string]any{"strategy": "native", "interval_days": 1}); r.Status != http.StatusOK {
			t.Fatal(r.Status)
		}
		var exID uuid.UUID
		ctxScope := postgres.WithScope(ctx, postgres.Scope{OrganizationID: g.acme.ID})
		// Disable rotation in the provider after scheduling.
		g.at(25 * time.Hour)
		if _, err := g.rotation.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		g.at(0)
		_ = postgres.Tx(ctxScope, g.db.App, func(tx pgx.Tx) error {
			return tx.QueryRow(ctxScope, `SELECT id FROM rotation_executions WHERE secret_id = $1 AND status = 'scheduled'`, other).Scan(&exID)
		})
		g.vault.DisableRotation(otherRef)
		if err := g.rotationRun(t, exID); err != nil {
			t.Fatal(err)
		}
		ex, _ := g.rotation.Execution(ctx, g.acme.ID, exID)
		if ex.Status != "failed" || ex.ErrorCode != "not_configured" {
			t.Fatalf("execution: %+v", ex)
		}
	})
}

func auditDetails(t *testing.T, g *gov, action string) string {
	t.Helper()
	var out []string
	ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: g.acme.ID})
	_ = postgres.Tx(ctx, g.db.App, func(tx pgx.Tx) error {
		recs, err := audit.List(ctx, tx, g.acme.ID, 0, 500)
		for _, r := range recs {
			if r.Action == action {
				for k, v := range r.Details {
					out = append(out, k+"="+v)
				}
			}
		}
		return err
	})
	return strings.Join(out, " ")
}

func TestManualRotationReminders(t *testing.T) {
	g := newGov(t)
	ctx := context.Background()
	g.bind(t, g.devID, "secret_admin", g.staging)
	_, secID := g.person(t, oidctest.Claims{Subject: "u-sec", Email: "sec@example.com", EmailVerified: true}, "member")
	g.bind(t, secID, "security_admin", uuid.Nil)
	_, adminMe := getMe(t, g.admin, g.api.URL)

	id, _ := g.secret(t, g.staging, "vendor/api-key", "vendor-value-1")
	if r := g.setPolicy(t, g.dev, id, map[string]any{"strategy": "native", "interval_days": 0}); r.Status != http.StatusBadRequest {
		t.Fatalf("interval 0 accepted: %d", r.Status)
	}
	if r := g.call(t, g.dev, "PATCH", g.o+"/secrets/"+id.String(), map[string]any{"owner_user_id": uuid.New()}); r.Status != http.StatusBadRequest {
		t.Fatalf("non-member owner accepted: %d %s", r.Status, r.Body)
	}
	if r := g.call(t, g.dev, "PATCH", g.o+"/secrets/"+id.String(), map[string]any{"owner_user_id": g.devID}); r.Status != http.StatusOK {
		t.Fatalf("set owner: %d %s", r.Status, r.Body)
	}
	if r := g.setPolicy(t, g.dev, id, map[string]any{"strategy": "manual", "interval_days": 2, "reminder_days": []int{1, 2}}); r.Status != http.StatusOK {
		t.Fatalf("set policy: %d %s", r.Status, r.Body)
	}
	if r := g.call(t, g.dev, "POST", g.o+"/secrets/"+id.String()+"/rotate", nil); r.Status != http.StatusBadRequest {
		t.Fatalf("rotate-now on a manual policy: %d", r.Status)
	}

	tick := func(after time.Duration) {
		t.Helper()
		g.at(after)
		for range 2 { // every effect is idempotent
			if _, err := g.rotation.Tick(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	const day = 24 * time.Hour

	tick(0)
	if n := g.notifications(t, "rotation.reminder"); len(n) != 1 || !slices.Equal(n[0], []uuid.UUID{g.devID}) {
		t.Fatalf("2-day reminder: %v", n)
	}
	tick(day + time.Hour)
	if n := g.notifications(t, "rotation.reminder"); len(n) != 2 {
		t.Fatalf("1-day reminder: %v", n)
	}
	tick(2*day + time.Hour)
	if n := g.notifications(t, "rotation.due"); len(n) != 1 {
		t.Fatalf("due: %v", n)
	}
	if len(g.rotations(t, id)) != 0 {
		t.Fatal("manual policy started an automated rotation")
	}
	// Escalation widens: owner, + security, + organization admins.
	tick(3*day + 2*time.Hour)
	tick(5*day + 2*time.Hour)
	tick(9*day + 2*time.Hour)
	over := g.notifications(t, "rotation.overdue")
	if len(over) != 3 {
		t.Fatalf("escalations: %v", over)
	}
	if !slices.Equal(over[0], []uuid.UUID{g.devID}) || !slices.Contains(over[1], secID) || slices.Contains(over[1], adminMe.User.Id) ||
		!slices.Contains(over[2], adminMe.User.Id) {
		t.Fatalf("escalation recipients: %v", over)
	}

	// An approved change with a new value is the manual rotation.
	g.at(0)
	cr := g.mustSubmit(t, g.dev, map[string]any{"operation": "update", "secret_id": id, "value": "vendor-value-2"})
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	s := g.secretJSON(t, id)
	if s.LastRotatedAt == nil || s.NextRotationAt == nil || s.NextRotationAt.Before(time.Now().Add(47*time.Hour)) {
		t.Fatalf("after manual rotation: %v %v", s.LastRotatedAt, s.NextRotationAt)
	}
	before := len(g.notifications(t, "rotation.overdue"))
	tick(0)
	if len(g.notifications(t, "rotation.overdue")) != before {
		t.Fatal("still escalating after rotation")
	}
}

// TestRotationWorkerEndToEnd runs rotations through River, killing the worker
// while the provider is rotating.
func TestRotationWorkerEndToEnd(t *testing.T) {
	g := newGov(t)
	g.bind(t, g.devID, "secret_admin", g.staging)
	id, ref := g.secret(t, g.staging, "river/rotating", "river-original")
	g.vault.EnableRotation(ref)
	if r := g.setPolicy(t, g.dev, id, map[string]any{"strategy": "native", "interval_days": 30}); r.Status != http.StatusOK {
		t.Fatalf("set policy: %d %s", r.Status, r.Body)
	}
	g.rotation.PollInterval = 200 * time.Millisecond

	start := func() (*workflows.Client, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		w, err := workflows.New(g.db.App, workflows.Config{
			Work: true, Executor: g.exec, Approvals: g.approvals, Registry: g.registry, Keyring: g.keyring, Logger: g.logger,
			Rotation: g.rotation, Deliverer: g.deliverer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return w, cancel
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	w1, cancel1 := start()
	r := g.call(t, g.dev, "POST", g.o+"/secrets/"+id.String()+"/rotate", nil)
	if r.Status != http.StatusAccepted {
		t.Fatalf("rotate: %d %s", r.Status, r.Body)
	}
	waitFor("rotation to start", func() bool { return g.vault.Rotations(ref) == 1 })
	waitFor("verifying", func() bool { return g.rotations(t, id)[0].Status == httpapi.RotationExecutionStatusVerifying })

	// Kill the worker mid-rotation.
	cancel1()
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	_ = w1.Stop(stopCtx)
	stop()

	g.vault.FinishRotations(false)
	w2, cancel2 := start()
	defer func() { cancel2(); _ = w2.Stop(context.Background()) }()
	waitFor("rotation to finish", func() bool { return g.rotations(t, id)[0].Status == httpapi.RotationExecutionStatusSucceeded })
	if n := g.vault.Rotations(ref); n != 1 {
		t.Fatalf("provider rotated %d times", n)
	}
	if v, _, _ := g.vault.Current(ref); !strings.HasPrefix(v, "rotated-") {
		t.Fatalf("vault has %q", v)
	}
}
