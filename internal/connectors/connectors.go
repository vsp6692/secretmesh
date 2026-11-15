// Package connectors defines how SecretMesh talks to secret providers.
//
// Every mutating call takes an idempotency key (the execution journal ID,
// ADR-0007) so that retries and reconciliation never apply an operation twice.
// Values cross this interface only as sensitive.Value and are never stored by
// SecretMesh: pending values are staged inside the provider (ADR-0003).
package connectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// Target identifies a secret in a provider.
type Target struct {
	ConnectionID uuid.UUID
	// Name is the secret's name; used when creating.
	Name string
	// ProviderRef identifies an existing secret; empty for create.
	ProviderRef string
}

// Staged identifies a value staged in the provider.
type Staged struct {
	Ref     string
	Version string
}

// Result describes a completed provider operation.
type Result struct {
	ProviderRef string
	VersionID   string
	RequestID   string
}

// Operation identifies an applied (or attempted) mutation for lookup.
type Operation struct {
	Kind   string // create, update, delete
	Target Target
	Staged Staged
	Key    uuid.UUID
}

// Capabilities describe what a provider supports natively (blueprint §6.3),
// so the product does not pretend providers behave identically.
type Capabilities struct {
	SecretCreate   bool   `json:"secret_create"`
	SecretUpdate   bool   `json:"secret_update"`
	SecretDelete   bool   `json:"secret_delete"`
	SecretReveal   bool   `json:"secret_reveal"`
	Discovery      bool   `json:"discovery"`
	Versioning     bool   `json:"versioning"`
	VersionLabels  bool   `json:"version_labels"`
	SoftDelete     bool   `json:"soft_delete"`
	NativeRotation bool   `json:"native_rotation"`
	Tags           bool   `json:"tags"`
	UpdateStaging  string `json:"update_staging"` // version_label | shadow_secret
	CreateStaging  string `json:"create_staging"`
}

// SecretInfo is discovered, non-secret metadata.
type SecretInfo struct {
	ProviderRef     string
	Name            string
	Description     string
	CurrentVersion  string
	Tags            map[string]string
	KMSKeyID        string
	RotationEnabled bool
	LastChanged     *time.Time
}

// Version is one version of a secret.
type Version struct {
	ID        string
	Stages    []string
	CreatedAt *time.Time
}

// SecretStore is implemented by each provider connector.
type SecretStore interface {
	Capabilities() Capabilities
	// Stage writes value where live consumers do not read it.
	Stage(ctx context.Context, t Target, requestID uuid.UUID, value sensitive.Value) (Staged, error)
	ReadStaged(ctx context.Context, s Staged) (sensitive.Value, error)
	DiscardStaged(ctx context.Context, s Staged) error
	// Promote makes the staged value current, creating the secret if
	// t.ProviderRef is empty.
	Promote(ctx context.Context, t Target, s Staged, key uuid.UUID) (Result, error)
	Delete(ctx context.Context, t Target, key uuid.UUID) (Result, error)
	// LookupOperation reports whether op took effect, for reconciliation.
	LookupOperation(ctx context.Context, op Operation) (Result, bool, error)
	// List calls fn for every secret, excluding SecretMesh staging secrets.
	List(ctx context.Context, fn func(SecretInfo) error) error
	Versions(ctx context.Context, t Target) ([]Version, error)
	// Reveal reads the current value. Callers enforce authorization.
	Reveal(ctx context.Context, t Target) (sensitive.Value, string, error)
}

// StagingSweeper is implemented by stores that can find staging resources
// left behind by crashes or lost responses (ADR-0003: staged values must not
// outlive their request).
type StagingSweeper interface {
	// SweepStaging destroys staging resources created before olderThan whose
	// request live reports as no longer live. It returns how many it removed.
	SweepStaging(ctx context.Context, olderThan time.Time, live func(requestID uuid.UUID) (bool, error)) (int, error)
}

// RotationState is the provider's view of one native rotation attempt.
type RotationState int

const (
	// RotationNotStarted: the provider has no rotation for this key.
	RotationNotStarted RotationState = iota
	// RotationInProgress: the provider is still rotating (e.g. the rotation
	// function has not finished).
	RotationInProgress
	// RotationDone: the rotated version is current.
	RotationDone
	// RotationFailed: the attempt was abandoned without becoming current.
	RotationFailed
)

func (s RotationState) String() string {
	return [...]string{"not_started", "in_progress", "done", "failed"}[s]
}

// NativeRotator is implemented by stores whose provider can rotate a secret
// itself (AWS Secrets Manager rotation functions). The provider generates the
// new value; it never passes through SecretMesh.
type NativeRotator interface {
	// RotationConfigured reports whether the secret has a rotation function.
	RotationConfigured(ctx context.Context, t Target) (bool, error)
	// StartRotation starts rotating; key makes it idempotent.
	StartRotation(ctx context.Context, t Target, key uuid.UUID) (Result, error)
	// RotationState reports the state of the attempt identified by key and,
	// once known, the version it created.
	RotationState(ctx context.Context, t Target, key uuid.UUID) (RotationState, string, error)
	// AbandonRotation clears what a failed attempt left behind (e.g. the
	// AWSPENDING label) so a later attempt can start. It does not restore old
	// credentials.
	AbandonRotation(ctx context.Context, t Target, key uuid.UUID) error
}

// ErrAccessDenied means the provider refused SecretMesh's identity.
var ErrAccessDenied = errors.New("access denied by provider")

// ErrTransient marks errors after which the operation may or may not have
// been applied; callers retry or reconcile.
var ErrTransient = errors.New("transient provider error")

// ErrConflict means the provider already has a different resource by that name.
var ErrConflict = errors.New("conflicts with an existing provider resource")

// ErrNotFound is returned for missing secrets or staged values.
var ErrNotFound = errors.New("not found in provider")

// Connection is what a factory needs to build a store.
type Connection struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Provider       string
	Config         map[string]string
}

// Factory builds a SecretStore for a connection.
type Factory func(Connection) (SecretStore, error)

// Registry maps provider names to factories. Providers without a factory are
// unavailable in this deployment.
type Registry struct {
	factories map[string]Factory
}

func NewRegistry() *Registry { return &Registry{factories: map[string]Factory{}} }

func (r *Registry) Register(provider string, f Factory) { r.factories[provider] = f }

// Enabled reports whether provider can be used.
func (r *Registry) Enabled(provider string) bool { _, ok := r.factories[provider]; return ok }

// ErrProviderUnavailable is returned for providers that are not enabled.
var ErrProviderUnavailable = errors.New("provider not available in this deployment")

func (r *Registry) Store(c Connection) (SecretStore, error) {
	f, ok := r.factories[c.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderUnavailable, c.Provider)
	}
	return f(c)
}
