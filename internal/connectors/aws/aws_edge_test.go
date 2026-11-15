package aws_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	smaws "github.com/secretmesh/secretmesh/internal/connectors/aws"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// isMoto reports whether the emulator under test is Moto, which exposes an
// admin API that LocalStack and AWS do not.
func isMoto() bool {
	resp, err := http.Get(strings.TrimRight(os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT"), "/") + "/moto-api/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// A staging reference the connector did not issue must be rejected by every
// method that takes one, never guessed at.
func TestUnrecognizedStagingReference(t *testing.T) {
	store, _ := env(t)
	ctx := context.Background()
	bad := connectors.Staged{Ref: "not-a-staging-ref", Version: uuid.NewString()}
	target := connectors.Target{Name: "app/" + uuid.NewString()}

	if _, err := store.ReadStaged(ctx, bad); err == nil {
		t.Error("ReadStaged accepted an unknown reference")
	}
	if err := store.DiscardStaged(ctx, bad); err == nil {
		t.Error("DiscardStaged accepted an unknown reference")
	}
	if _, err := store.Promote(ctx, target, bad, uuid.New()); err == nil {
		t.Error("Promote accepted an unknown reference")
	}
}

// Missing secrets are reported as ErrNotFound so callers can tell "gone" from
// "provider is down".
func TestMissingSecretsAreNotFound(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	rot := store.(connectors.NativeRotator)

	name := "gone/" + uuid.NewString()
	created, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(name), SecretString: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	ref := aws.ToString(created.ARN)
	if _, err := raw.DeleteSecret(ctx, &sm.DeleteSecretInput{SecretId: aws.String(ref), ForceDeleteWithoutRecovery: aws.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	target := connectors.Target{ProviderRef: ref, Name: name}

	if _, _, err := store.Reveal(ctx, target); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Reveal of a deleted secret: %v", err)
	}
	if _, err := store.Versions(ctx, target); err == nil || (!errors.Is(err, connectors.ErrNotFound) && !isMoto()) {
		// Moto answers ListSecretVersionIds for a deleted secret with an HTML
		// 500; AWS and LocalStack return ResourceNotFoundException.
		t.Errorf("Versions of a deleted secret: %v", err)
	}
	if _, err := rot.RotationConfigured(ctx, target); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("RotationConfigured of a deleted secret: %v", err)
	}
	if _, _, err := rot.RotationState(ctx, target, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("RotationState of a deleted secret: %v", err)
	}
	if _, err := rot.StartRotation(ctx, target, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("StartRotation of a deleted secret: %v", err)
	}

	// A staged value that has been discarded is gone, and discarding twice is fine.
	staged, err := store.Stage(ctx, connectors.Target{Name: "app/" + uuid.NewString()}, uuid.New(), sensitive.FromString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardStaged(ctx, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadStaged(ctx, staged); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("ReadStaged after discard: %v", err)
	}
	// Discarding a label-staged value whose secret was deleted is a no-op.
	other, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String("tmp/" + uuid.NewString()), SecretString: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.Stage(ctx, connectors.Target{ProviderRef: aws.ToString(other.ARN)}, uuid.New(), sensitive.FromString("v2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.DeleteSecret(ctx, &sm.DeleteSecretInput{SecretId: other.ARN, ForceDeleteWithoutRecovery: aws.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardStaged(ctx, pending); err != nil {
		t.Errorf("discarding a staged value of a deleted secret: %v", err)
	}
}

// Binary secrets are revealed byte for byte.
func TestRevealBinarySecret(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	want := []byte{0x00, 0x01, 0xfe, 0xff, 'k', 'e', 'y'}
	created, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String("bin/" + uuid.NewString()), SecretBinary: want})
	if err != nil {
		t.Fatal(err)
	}
	v, version, err := store.Reveal(ctx, connectors.Target{ProviderRef: aws.ToString(created.ARN)})
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Reveal()) != string(want) {
		t.Errorf("binary value changed: %x", v.Reveal())
	}
	if version == "" {
		t.Error("no version reported")
	}
}

// Staging the same request twice returns the same version (retries after a
// lost response must not create a second one).
func TestStageIsIdempotentPerRequest(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	created, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String("idem/" + uuid.NewString()), SecretString: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	target := connectors.Target{ProviderRef: aws.ToString(created.ARN)}
	req := uuid.New()
	first, err := store.Stage(ctx, target, req, sensitive.FromString("v2"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Stage(ctx, target, req, sensitive.FromString("v2"))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.Version != second.Version {
		t.Fatalf("retry created a new version: %s vs %s", first.Version, second.Version)
	}
	// The current value is untouched until promotion.
	if got := current(t, raw, target.ProviderRef); got != "v1" {
		t.Fatalf("staging changed the current value to %q", got)
	}
}

// Listing follows pagination, maps tags and never returns SecretMesh's own
// staging secrets, however they are recognised.
func TestListPaginatesAndHidesStaging(t *testing.T) {
	store, raw := env(t)
	ctx := context.Background()
	prefix := "list/" + uuid.NewString()[:8] + "/"

	const n = 105 // more than one page (Secrets Manager returns up to 100)
	for i := range n {
		in := &sm.CreateSecretInput{Name: aws.String(fmt.Sprintf("%s%03d", prefix, i)), SecretString: aws.String("v")}
		if i == 0 {
			in.Description = aws.String("first")
			in.Tags = []smtypes.Tag{{Key: aws.String("secretmesh:environment"), Value: aws.String("prod")}}
		}
		if _, err := raw.CreateSecret(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	// Hidden by the tag even though the name does not match the staging prefix.
	if _, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{
		Name: aws.String(prefix + "tagged-staging"), SecretString: aws.String("v"),
		Tags: []smtypes.Tag{{Key: aws.String("secretmesh:staging"), Value: aws.String("true")}},
	}); err != nil {
		t.Fatal(err)
	}
	// Hidden by the name.
	if _, err := store.Stage(ctx, connectors.Target{Name: prefix + "x"}, uuid.New(), sensitive.FromString("s")); err != nil {
		t.Fatal(err)
	}
	// A secret scheduled for deletion is not inventory.
	doomed, err := raw.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(prefix + "doomed"), SecretString: aws.String("v")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.DeleteSecret(ctx, &sm.DeleteSecretInput{SecretId: doomed.ARN, RecoveryWindowInDays: aws.Int64(7)}); err != nil {
		t.Fatal(err)
	}

	got := map[string]connectors.SecretInfo{}
	if err := store.List(ctx, func(s connectors.SecretInfo) error {
		if len(s.Name) >= len(prefix) && s.Name[:len(prefix)] == prefix {
			got[s.Name] = s
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Errorf("listed %d of %d secrets under the prefix", len(got), n)
	}
	for _, hidden := range []string{"tagged-staging", "doomed"} {
		if _, ok := got[prefix+hidden]; ok {
			t.Errorf("%s was listed", hidden)
		}
	}
	first := got[prefix+"000"]
	if first.Description != "first" || first.Tags["secretmesh:environment"] != "prod" || first.CurrentVersion == "" || first.ProviderRef == "" {
		t.Errorf("metadata not mapped: %+v", first)
	}

	// A callback error stops the walk and is returned unchanged.
	stop := errors.New("stop")
	if err := store.List(ctx, func(connectors.SecretInfo) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("callback error: %v", err)
	}
}

func TestProviderIdentity(t *testing.T) {
	if smaws.ProviderName != "aws" {
		t.Fatalf("provider name changed: %q", smaws.ProviderName)
	}
	a, b := smaws.NewExternalID(), smaws.NewExternalID()
	if a == b || len(a) < 24 {
		t.Fatalf("external IDs must be unique and unguessable: %q %q", a, b)
	}
}
