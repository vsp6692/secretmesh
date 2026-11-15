// Package rotation schedules and runs secret rotation (ADR-0011).
//
// SecretMesh owns the schedule and the governance: who may set a policy,
// when a rotation runs, the policy check immediately before the provider
// call, reminders and escalation. Generating and applying the new value is
// left to the provider (native strategy) or to people (manual strategy), so
// rotated values never pass through SecretMesh.
package rotation

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
)

// Strategies.
const (
	Native = "native"
	Manual = "manual"
)

// ErrNotConfigured: the provider cannot rotate this secret as configured.
var ErrNotConfigured = errors.New("the secret has no rotation function in the provider")

// Plugin is the rotation contract (blueprint §7.2). Every method that acts
// on the provider takes the execution ID as idempotency key, so a resumed
// execution never rotates twice.
type Plugin interface {
	Strategy() string
	// Automated plugins rotate on schedule; others only remind and escalate,
	// and a rotation is recorded when someone changes the value.
	Automated() bool
	// Validate checks that the secret can be rotated this way.
	Validate(ctx context.Context, store connectors.SecretStore, t connectors.Target) error
	// Rotate starts a rotation (preparing the new version is the provider's
	// job). It must be idempotent for key.
	Rotate(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) (connectors.Result, error)
	// Verify reports the attempt's state and, once known, its version.
	Verify(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) (connectors.RotationState, string, error)
	// Recover cleans up a failed attempt so that a later one can run. It is
	// provider-specific and never restores an old credential.
	Recover(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) error
}

// Plugins maps strategies to plugins.
type Plugins map[string]Plugin

// DefaultPlugins are the built-in strategies.
func DefaultPlugins() Plugins {
	return Plugins{Native: nativePlugin{}, Manual: manualPlugin{}}
}

// nativePlugin uses the provider's rotation (AWS: RotateSecret with the
// secret's rotation function).
type nativePlugin struct{}

func (nativePlugin) Strategy() string { return Native }
func (nativePlugin) Automated() bool  { return true }

func rotator(store connectors.SecretStore) (connectors.NativeRotator, error) {
	r, ok := store.(connectors.NativeRotator)
	if !ok || !store.Capabilities().NativeRotation {
		return nil, ErrNotConfigured
	}
	return r, nil
}

func (nativePlugin) Validate(ctx context.Context, store connectors.SecretStore, t connectors.Target) error {
	r, err := rotator(store)
	if err != nil {
		return err
	}
	ok, err := r.RotationConfigured(ctx, t)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotConfigured
	}
	return nil
}

func (nativePlugin) Rotate(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) (connectors.Result, error) {
	r, err := rotator(store)
	if err != nil {
		return connectors.Result{}, err
	}
	return r.StartRotation(ctx, t, key)
}

func (nativePlugin) Verify(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) (connectors.RotationState, string, error) {
	r, err := rotator(store)
	if err != nil {
		return 0, "", err
	}
	return r.RotationState(ctx, t, key)
}

func (nativePlugin) Recover(ctx context.Context, store connectors.SecretStore, t connectors.Target, key uuid.UUID) error {
	r, err := rotator(store)
	if err != nil {
		return err
	}
	return r.AbandonRotation(ctx, t, key)
}

// manualPlugin is for credentials only people can rotate: SecretMesh tracks
// the schedule, reminds and escalates, and records a rotation when the value
// changes (an approved update or a new version found by discovery).
type manualPlugin struct{}

var errManual = errors.New("manual rotation is performed by people")

func (manualPlugin) Strategy() string { return Manual }
func (manualPlugin) Automated() bool  { return false }
func (manualPlugin) Validate(context.Context, connectors.SecretStore, connectors.Target) error {
	return nil
}
func (manualPlugin) Rotate(context.Context, connectors.SecretStore, connectors.Target, uuid.UUID) (connectors.Result, error) {
	return connectors.Result{}, errManual
}
func (manualPlugin) Verify(context.Context, connectors.SecretStore, connectors.Target, uuid.UUID) (connectors.RotationState, string, error) {
	return 0, "", errManual
}
func (manualPlugin) Recover(context.Context, connectors.SecretStore, connectors.Target, uuid.UUID) error {
	return nil
}
