// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package httpapi_test

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity/oidctest"
	"github.com/secretmesh/secretmesh/internal/inventory"
)

// TestAWSFlow drives the AWS connector through the API against the emulator
// at SECRETMESH_TEST_AWS_ENDPOINT (Moto in development and CI).
func TestAWSFlow(t *testing.T) {
	endpoint := os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECRETMESH_TEST_AWS_ENDPOINT not set")
	}
	g := newGov(t)
	ctx := context.Background()
	raw := sm.New(sm.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider("123456789012", "test", "")})
	current := func(name string) string {
		t.Helper()
		out, err := raw.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: aws.String(name), VersionStage: aws.String("AWSCURRENT")})
		if err != nil {
			t.Fatal(err)
		}
		return aws.ToString(out.SecretString)
	}
	prefix := "sm-" + uuid.NewString()[:8] + "/"

	cfg := map[string]string{"role_arn": "arn:aws:iam::123456789012:role/secretmesh-connector", "region": "us-east-1"}
	withID := map[string]string{"external_id": "secretmesh-chosen"}
	for k, v := range cfg {
		withID[k] = v
	}
	if r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]any{"name": "aws-chosen", "provider": "aws", "config": withID}); r.Status != http.StatusBadRequest || r.code() != "invalid_config" {
		t.Fatalf("caller-chosen external_id: %d %s", r.Status, r.Body)
	}
	r := g.call(t, g.admin, "POST", g.o+"/connections", map[string]any{"name": "aws", "provider": "aws", "config": cfg, "default_environment_id": g.staging})
	if r.Status != http.StatusCreated {
		t.Fatalf("create aws connection: %d %s", r.Status, r.Body)
	}
	var conn httpapi.Connection
	r.decode(t, &conn)
	if !strings.HasPrefix(conn.Config["external_id"], "secretmesh-") || conn.Capabilities == nil || !conn.Capabilities.Discovery {
		t.Fatalf("connection: %+v", conn)
	}

	// Create in production: staged in a shadow secret, promoted after approval.
	name := prefix + "api-key"
	cr := g.mustSubmit(t, g.dev, map[string]any{"operation": "create", "connection_id": conn.Id, "environment_id": g.prod,
		"name": name, "classification": "confidential", "value": "aws-first-3f9a", "reason": "test"})
	if _, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)}); err == nil {
		t.Fatal("secret exists before approval")
	}
	if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("approve: %d %s", r.Status, r.Body)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	done := g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	secretID := *done.SecretId
	if current(name) != "aws-first-3f9a" {
		t.Fatal("value not promoted")
	}
	if _, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String("secretmesh-staging/" + cr.Id.String())}); err == nil {
		if d, _ := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String("secretmesh-staging/" + cr.Id.String())}); d.DeletedDate == nil {
			t.Fatal("shadow secret left behind")
		}
	}

	// Update: staged under SECRETMESH_PENDING, invisible until approved.
	cr = g.mustSubmit(t, g.dev, map[string]any{"operation": "update", "secret_id": secretID, "value": "aws-second-71c0"})
	if current(name) != "aws-first-3f9a" {
		t.Fatal("staging changed the current value")
	}
	g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash)
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	if current(name) != "aws-second-71c0" {
		t.Fatal("update not promoted")
	}

	// Rejection discards the staged version and leaves the current value.
	cr = g.mustSubmit(t, g.dev, map[string]any{"operation": "update", "secret_id": secretID, "value": "aws-rejected-0d2b"})
	if r := g.decide(t, g.ap1, cr.Id, "reject", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("reject: %d %s", r.Status, r.Body)
	}
	if current(name) != "aws-second-71c0" {
		t.Fatal("rejected value promoted")
	}
	// The discard job (run by the worker in production).
	if err := g.approvals.DiscardStaging(ctx, g.acme.ID, cr.Id); err != nil {
		t.Fatal(err)
	}
	desc, _ := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)})
	for v, stages := range desc.VersionIdsToStages {
		if slices.Contains(stages, "SECRETMESH_PENDING") {
			t.Fatalf("rejected version %s still pending", v)
		}
	}

	t.Run("orphaned staging is swept", func(t *testing.T) {
		// A pending create keeps its shadow secret; once the request is
		// rejected and the discard job never ran, the sweeper removes it.
		cr := g.mustSubmit(t, g.dev, map[string]any{"operation": "create", "connection_id": conn.Id, "environment_id": g.prod,
			"name": prefix + "swept", "classification": "internal", "value": "aws-orphan-5e71", "reason": "test"})
		shadow := "secretmesh-staging/" + cr.Id.String()
		exists := func() bool {
			d, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(shadow)})
			return err == nil && d.DeletedDate == nil
		}
		if !exists() {
			t.Fatal("no shadow secret for a pending create")
		}
		// The emulator is shared with other tests, so use a short grace
		// period (not zero) that never catches a secret mid-promotion.
		const grace = 2 * time.Second
		time.Sleep(grace + 500*time.Millisecond)
		disc := inventory.NewDiscovery(g.db.App, g.registry, g.logger)
		if _, err := disc.SweepStaging(ctx, g.acme.ID, conn.Id, grace); err != nil {
			t.Fatal(err)
		}
		if !exists() {
			t.Fatal("sweeper removed the staging secret of a pending request")
		}
		if r := g.decide(t, g.ap1, cr.Id, "reject", cr.BindingHash); r.Status != http.StatusOK {
			t.Fatalf("reject: %d %s", r.Status, r.Body)
		}
		if !exists() {
			t.Fatal("staging secret vanished without the discard job")
		}
		if _, err := disc.SweepStaging(ctx, g.acme.ID, conn.Id, grace); err != nil {
			t.Fatal(err)
		}
		if exists() {
			t.Fatal("sweeper left the staging secret of a rejected request")
		}
	})

	t.Run("versions and reveal", func(t *testing.T) {
		var vs struct{ Versions []httpapi.SecretVersion }
		r := g.call(t, g.dev, "GET", g.o+"/secrets/"+secretID.String()+"/versions", nil)
		if r.Status != http.StatusOK {
			t.Fatalf("versions: %d %s", r.Status, r.Body)
		}
		r.decode(t, &vs)
		if len(vs.Versions) < 2 {
			t.Fatalf("versions: %+v", vs)
		}

		reveal := "/secrets/" + secretID.String() + "/reveal"
		if r := g.call(t, g.ap1, "POST", g.o+reveal, nil); r.Status != http.StatusForbidden || r.code() != "forbidden" {
			t.Fatalf("approver revealed: %d %s", r.Status, r.Body)
		}
		if r := g.call(t, g.dev, "POST", g.o+reveal, nil); r.Status != http.StatusForbidden || r.code() != "mfa_required" {
			t.Fatalf("production reveal without MFA: %d %s", r.Status, r.Body)
		}
		mfaDev := g.browser(t)
		c := devClaims
		c.AMR = []string{"mfa"}
		g.login(t, mfaDev, c)
		r = g.call(t, mfaDev, "POST", g.o+reveal, nil)
		if r.Status != http.StatusOK {
			t.Fatalf("reveal: %d %s", r.Status, r.Body)
		}
		var got httpapi.RevealedSecret
		r.decode(t, &got)
		if got.Value != "aws-second-71c0" || got.VersionId == "" {
			t.Fatalf("revealed %+v", got)
		}
		if !slices.Contains(g.auditActions(t, uuid.Nil), "secret.revealed") {
			t.Fatal("reveal not audited")
		}
	})

	t.Run("discovery imports tagged secrets", func(t *testing.T) {
		tagged, untagged := prefix+"discovered/prod", prefix+"discovered/default"
		if _, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(tagged), SecretString: aws.String("x"),
			Tags: []smtypes.Tag{{Key: aws.String("secretmesh:environment"), Value: aws.String("prod")},
				{Key: aws.String("secretmesh:classification"), Value: aws.String("restricted")}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(untagged), SecretString: aws.String("y")}); err != nil {
			t.Fatal(err)
		}
		if r := g.call(t, g.dev, "POST", g.o+"/connections/"+conn.Id.String()+"/sync", nil); r.Status != http.StatusForbidden {
			t.Fatalf("developer synced: %d", r.Status)
		}
		r := g.call(t, g.admin, "POST", g.o+"/connections/"+conn.Id.String()+"/sync", nil)
		if r.Status != http.StatusOK {
			t.Fatalf("sync: %d %s", r.Status, r.Body)
		}
		var res httpapi.SyncResult
		r.decode(t, &res)
		if res.Imported < 2 || res.Updated < 1 {
			t.Fatalf("sync result: %+v", res)
		}
		var list struct{ Secrets []httpapi.Secret }
		g.call(t, g.dev, "GET", g.o+"/secrets", nil).decode(t, &list)
		found := map[string]httpapi.Secret{}
		for _, s := range list.Secrets {
			found[s.Name] = s
		}
		if s := found[tagged]; s.EnvironmentId != g.prod || s.Classification != "restricted" || s.Origin == nil || *s.Origin != "discovered" {
			t.Fatalf("tagged secret: %+v", s)
		}
		if s := found[untagged]; s.EnvironmentId != g.staging {
			t.Fatalf("untagged secret not in the default environment: %+v", s)
		}
		for n := range found {
			if strings.HasPrefix(n, "secretmesh-staging/") {
				t.Fatalf("staging secret imported: %s", n)
			}
		}
		// A second run changes nothing.
		g.call(t, g.admin, "POST", g.o+"/connections/"+conn.Id.String()+"/sync", nil).decode(t, &res)
		if res.Imported != 0 {
			t.Fatalf("second sync imported %d", res.Imported)
		}
	})
}

// TestBreakGlass covers emergency changes without prior approval. It uses the
// fake connector, so it needs no AWS emulator.
func TestBreakGlass(t *testing.T) {
	g := newGov(t)
	reason := "INC-4711: production database credentials leaked"
	body := func(name string) map[string]any {
		b := g.create(g.prod, name, "emergency-value-"+name)
		b["break_glass"], b["reason"] = true, reason
		return b
	}
	mfa := func(c oidctest.Claims) *http.Client {
		cl := g.browser(t)
		c.AMR = []string{"mfa"}
		g.login(t, cl, c)
		return cl
	}

	// Without the break_glass role.
	if r, _ := g.submit(t, mfa(devClaims), body("bg/a")); r.Status != http.StatusForbidden || r.code() != "break_glass_denied" {
		t.Fatalf("without role: %d %s", r.Status, r.Body)
	}
	bindingID := g.bindID(t, g.devID, "break_glass", g.prod)
	// Without MFA.
	if r, _ := g.submit(t, g.dev, body("bg/a")); r.Status != http.StatusForbidden || r.code() != "break_glass_denied" {
		t.Fatalf("without MFA: %d %s", r.Status, r.Body)
	}
	// Without a real justification.
	short := body("bg/a")
	short["reason"] = "urgent"
	if r, _ := g.submit(t, mfa(devClaims), short); r.Status != http.StatusBadRequest {
		t.Fatalf("short reason: %d %s", r.Status, r.Body)
	}

	dev := mfa(devClaims)
	cr := g.mustSubmit(t, dev, body("bg/a"))
	if cr.Status != httpapi.ChangeRequestStatusApproved || cr.RequiredApprovals != 0 || cr.BreakGlass == nil || !*cr.BreakGlass {
		t.Fatalf("break-glass request: %+v", cr)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusSucceeded, "")
	if !slices.Contains(g.auditActions(t, cr.Id), "change_request.break_glass") {
		t.Fatalf("break-glass not audited: %v", g.auditActions(t, cr.Id))
	}
	var list struct {
		ChangeRequests []httpapi.ChangeRequest `json:"change_requests"`
	}
	g.call(t, g.aud, "GET", g.o+"/change-requests?break_glass=true", nil).decode(t, &list)
	if len(list.ChangeRequests) != 1 || list.ChangeRequests[0].Id != cr.Id {
		t.Fatalf("break-glass filter: %+v", list.ChangeRequests)
	}

	// Losing the role before execution fails closed.
	cr = g.mustSubmit(t, dev, body("bg/b"))
	if r := g.call(t, g.admin, "DELETE", g.o+"/role-bindings/"+bindingID.String(), nil); r.Status != http.StatusNoContent {
		t.Fatalf("delete binding: %d %s", r.Status, r.Body)
	}
	_ = g.run(t, cr.Id)
	g.expectStatus(t, cr.Id, httpapi.ChangeRequestStatusFailed, "policy_denied")
}

// bindID creates a role binding and returns its ID.
func (g *gov) bindID(t *testing.T, user uuid.UUID, role string, env uuid.UUID) uuid.UUID {
	t.Helper()
	r := g.call(t, g.admin, "POST", g.o+"/role-bindings", map[string]any{"user_id": user, "role": role, "environment_id": env})
	if r.Status != http.StatusCreated {
		t.Fatalf("bind %s: %d %s", role, r.Status, r.Body)
	}
	var b httpapi.RoleBinding
	r.decode(t, &b)
	return b.Id
}
