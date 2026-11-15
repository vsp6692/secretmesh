package aws_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	smaws "github.com/secretmesh/secretmesh/internal/connectors/aws"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// env returns a store connected through AssumeRole to the emulator at
// SECRETMESH_TEST_AWS_ENDPOINT, and a raw client for assertions. The access
// key equals the account ID of the role: LocalStack derives the account from the
// key, so the raw client then sees the same secrets as the assumed role.
func env(t *testing.T) (connectors.SecretStore, *sm.Client) {
	t.Helper()
	endpoint := os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECRETMESH_TEST_AWS_ENDPOINT not set")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "123456789012")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	p, err := smaws.New(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	store, err := p.Factory(connectors.Connection{ID: uuid.New(), Provider: smaws.ProviderName, Config: map[string]string{
		"role_arn": "arn:aws:iam::123456789012:role/secretmesh-connector", "region": "us-east-1",
		"external_id": smaws.NewExternalID(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw := sm.New(sm.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider("123456789012", "test", ""),
	})
	return store, raw
}

// current reads what consumers see: the AWSCURRENT version. (AWS defaults to
// AWSCURRENT; Moto 5.2.5 returns a stale value for unqualified reads after
// UpdateSecretVersionStage, so the stage is explicit.)
func current(t *testing.T, raw *sm.Client, id string) string {
	t.Helper()
	out, err := raw.GetSecretValue(context.Background(), &sm.GetSecretValueInput{
		SecretId: aws.String(id), VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.SecretString)
}

func TestCreateThroughShadowSecret(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	name := "app/" + uuid.NewString()
	target := connectors.Target{Name: name}
	req, key := uuid.New(), uuid.New()

	staged, err := store.Stage(ctx, target, req, sensitive.FromString("first-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)}); err == nil {
		t.Fatal("target exists before promotion")
	}
	if v, err := store.ReadStaged(ctx, staged); err != nil || v.RevealString() != "first-value" {
		t.Fatalf("read staged: %v", err)
	}
	if _, found, _ := store.LookupOperation(ctx, connectors.Operation{Kind: "create", Target: target, Key: key}); found {
		t.Fatal("lookup found an operation that has not happened")
	}

	res, err := store.Promote(ctx, target, staged, key)
	if err != nil {
		t.Fatal(err)
	}
	if current(t, raw, name) != "first-value" || res.VersionID != key.String() || res.ProviderRef == "" {
		t.Fatalf("after promote: %+v", res)
	}
	// Retrying with the same key is a no-op that reports the same result.
	again, err := store.Promote(ctx, target, staged, key)
	if err != nil || again.VersionID != res.VersionID {
		t.Fatalf("idempotent retry: %+v %v", again, err)
	}
	if r, found, err := store.LookupOperation(ctx, connectors.Operation{Kind: "create", Target: target, Key: key}); err != nil || !found || r.ProviderRef != res.ProviderRef {
		t.Fatalf("lookup: %+v %v %v", r, found, err)
	}
	// A different key for an existing name is a conflict, not a success.
	if _, err := store.Promote(ctx, target, staged, uuid.New()); !errors.Is(err, connectors.ErrConflict) {
		t.Fatalf("conflicting create: %v", err)
	}

	if err := store.DiscardStaged(ctx, staged); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardStaged(ctx, staged); err != nil {
		t.Fatalf("discard is not idempotent: %v", err)
	}

	var names []string
	if err := store.List(ctx, func(s connectors.SecretInfo) error { names = append(names, s.Name); return nil }); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, name) {
		t.Fatal("created secret not listed")
	}
	for _, n := range names {
		if len(n) >= len(smaws.StagingPrefix) && n[:len(smaws.StagingPrefix)] == smaws.StagingPrefix {
			t.Fatalf("staging secret listed: %s", n)
		}
	}
}

func TestUpdateThroughPendingLabel(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	name := "db/" + uuid.NewString()
	created, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(name), SecretString: aws.String("old")})
	if err != nil {
		t.Fatal(err)
	}
	target := connectors.Target{ProviderRef: aws.ToString(created.ARN), Name: name}

	t.Run("staged value is invisible to consumers until promoted", func(t *testing.T) {
		staged, err := store.Stage(ctx, target, uuid.New(), sensitive.FromString("new"))
		if err != nil {
			t.Fatal(err)
		}
		if current(t, raw, name) != "old" {
			t.Fatal("staging changed the current value")
		}
		op := connectors.Operation{Kind: "update", Target: target, Staged: staged}
		if _, found, _ := store.LookupOperation(ctx, op); found {
			t.Fatal("lookup found an unapplied update")
		}
		res, err := store.Promote(ctx, target, staged, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		if current(t, raw, name) != "new" || res.VersionID != staged.Version {
			t.Fatalf("after promote: %+v", res)
		}
		desc, _ := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)})
		for v, stages := range desc.VersionIdsToStages {
			if slices.Contains(stages, smaws.PendingLabel) {
				t.Fatalf("version %s still labelled pending: %v", v, stages)
			}
		}
		if _, found, _ := store.LookupOperation(ctx, op); !found {
			t.Fatal("lookup missed an applied update")
		}
		if _, err := store.Promote(ctx, target, staged, uuid.New()); err != nil {
			t.Fatalf("idempotent retry: %v", err)
		}
	})

	t.Run("discarded staging leaves the current value", func(t *testing.T) {
		staged, err := store.Stage(ctx, target, uuid.New(), sensitive.FromString("rejected"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.DiscardStaged(ctx, staged); err != nil {
			t.Fatal(err)
		}
		if current(t, raw, name) != "new" {
			t.Fatal("discard changed the current value")
		}
		desc, _ := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)})
		if slices.Contains(desc.VersionIdsToStages[staged.Version], smaws.PendingLabel) {
			t.Fatal("pending label not removed")
		}
	})

	t.Run("versions and reveal", func(t *testing.T) {
		versions, err := store.Versions(ctx, target)
		if err != nil || len(versions) < 2 {
			t.Fatalf("versions: %+v %v", versions, err)
		}
		v, ver, err := store.Reveal(ctx, target)
		if err != nil || v.RevealString() != "new" || ver == "" {
			t.Fatalf("reveal: %q %q %v", v.RevealString(), ver, err)
		}
	})

	t.Run("delete is soft and idempotent", func(t *testing.T) {
		key := uuid.New()
		if _, err := store.Delete(ctx, target, key); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.LookupOperation(ctx, connectors.Operation{Kind: "delete", Target: target, Key: key}); err != nil || !found {
			t.Fatalf("lookup delete: %v %v", found, err)
		}
		if _, err := store.Delete(ctx, target, key); err != nil {
			t.Fatalf("second delete: %v", err)
		}
	})

	t.Run("missing secrets map to ErrNotFound", func(t *testing.T) {
		_, _, err := store.Reveal(ctx, connectors.Target{ProviderRef: "arn:aws:secretsmanager:us-east-1:123456789012:secret:nope-AbCdEf"})
		if !errors.Is(err, connectors.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestValidateConfig(t *testing.T) {
	ok := map[string]string{"role_arn": "arn:aws:iam::123456789012:role/sm", "region": "eu-west-1", "external_id": smaws.NewExternalID()}
	if err := smaws.ValidateConfig(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"bad arn":         func(c map[string]string) { c["role_arn"] = "arn:aws:iam::123:user/x" },
		"bad region":      func(c map[string]string) { c["region"] = "mars" },
		"chosen ext id":   func(c map[string]string) { c["external_id"] = "mine" },
		"unknown setting": func(c map[string]string) { c["endpoint"] = "http://169.254.169.254" },
	} {
		c := map[string]string{}
		for k, v := range ok {
			c[k] = v
		}
		mutate(c)
		if smaws.ValidateConfig(c) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestNativeRotation covers the RotateSecret calls. Moto cannot run rotation
// functions, so it never completes a rotation; completion is covered with
// the fake provider and must be confirmed against real AWS.
func TestNativeRotation(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	rot := store.(connectors.NativeRotator)
	name := "rot/" + uuid.NewString()
	created, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(name), SecretString: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	target := connectors.Target{ProviderRef: aws.ToString(created.ARN), Name: name}

	if ok, err := rot.RotationConfigured(ctx, target); err != nil || ok {
		t.Fatalf("secret without a rotation function reported configured: %v %v", ok, err)
	}
	key := uuid.New()
	if st, _, err := rot.RotationState(ctx, target, key); err != nil || st != connectors.RotationNotStarted {
		t.Fatalf("state before start: %v %v", st, err)
	}
	versions := func() int {
		d, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		return len(d.VersionIdsToStages)
	}
	before := versions()
	res, err := rot.StartRotation(ctx, target, key)
	if err != nil && strings.Contains(err.Error(), "Lambda rotation function") {
		// AWS and LocalStack refuse to rotate a secret that has no rotation
		// function (running one needs the Lambda service); Moto does not.
		// The connector must fail without side effects.
		if res.VersionID != "" || versions() != before {
			t.Fatalf("refused rotation left traces: %+v, versions %d -> %d", res, before, versions())
		}
		if st, _, _ := rot.RotationState(ctx, target, key); st != connectors.RotationNotStarted {
			t.Fatalf("state after refused start: %v", st)
		}
		t.Logf("emulator enforces the rotation function requirement: %v", err)
	} else {
		if err != nil || res.VersionID != key.String() {
			t.Fatalf("start: %+v %v", res, err)
		}
		// Real AWS reports in progress until the rotation function finishes;
		// Moto completes immediately.
		st, ver, err := rot.RotationState(ctx, target, key)
		if err != nil || (st != connectors.RotationInProgress && st != connectors.RotationDone) || ver != key.String() {
			t.Fatalf("state after start: %v %q %v", st, ver, err)
		}
		n := versions()
		// Starting again with the same key does not start a second rotation.
		if again, err := rot.StartRotation(ctx, target, key); err != nil || again.VersionID != key.String() || versions() != n {
			t.Fatalf("idempotent start: %+v %v", again, err)
		}
	}

	// Abandoning removes AWSPENDING from a stuck attempt.
	stuck := uuid.New()
	if _, err := raw.PutSecretValue(ctx, &sm.PutSecretValueInput{SecretId: aws.String(name), SecretString: aws.String("half-rotated"),
		ClientRequestToken: aws.String(stuck.String()), VersionStages: []string{"AWSPENDING"}}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := rot.RotationState(ctx, target, stuck); st != connectors.RotationInProgress {
		t.Fatalf("stuck attempt state: %v", st)
	}
	if err := rot.AbandonRotation(ctx, target, stuck); err != nil {
		t.Fatal(err)
	}
	// Moto keeps the unlabelled version (failed); AWS and LocalStack drop it
	// (not started). Either way the attempt is over and nothing is pending.
	if st, _, _ := rot.RotationState(ctx, target, stuck); st != connectors.RotationFailed && st != connectors.RotationNotStarted {
		t.Fatalf("state after abandoning: %v", st)
	}
	if d, err := raw.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(name)}); err != nil {
		t.Fatal(err)
	} else {
		for id, stages := range d.VersionIdsToStages {
			if slices.Contains(stages, "AWSPENDING") {
				t.Fatalf("version %s is still AWSPENDING after abandoning", id)
			}
		}
	}
	if err := rot.AbandonRotation(ctx, target, stuck); err != nil {
		t.Fatalf("abandon is not idempotent: %v", err)
	}
}
