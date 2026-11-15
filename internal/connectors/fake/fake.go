// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package fake is an in-memory secret provider for tests and local
// development. Its state lives in process memory only, so the worker must run
// in the same process as the API (the default). It must never be enabled in
// production (SECRETMESH_ENABLE_FAKE_CONNECTOR).
package fake

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

const Provider = "fake"

type secret struct {
	versions [][]byte
	deleted  bool
	// Native rotation: whether a rotation function is "configured", and
	// attempts by key (index into versions while pending).
	rotatable bool
	rotations map[uuid.UUID]*rotation
}

type rotation struct {
	value []byte
	state connectors.RotationState
	// version is set once the rotated value is current.
	version int
}

// Vault holds every fake connection's secrets.
type Vault struct {
	mu      sync.Mutex
	secrets map[string]*secret // provider ref -> secret
	staged  map[string][]byte  // staging ref -> value
	ops     map[uuid.UUID]connectors.Result
	applied int

	// Failure injection for tests.
	failNext     error
	loseResponse bool
}

func New() *Vault {
	return &Vault{secrets: map[string]*secret{}, staged: map[string][]byte{}, ops: map[uuid.UUID]connectors.Result{}}
}

// Factory registers the vault with a connectors.Registry.
func (v *Vault) Factory(c connectors.Connection) (connectors.SecretStore, error) {
	return &store{v: v, conn: c.ID}, nil
}

// Ref returns the provider reference of a secret created through connection.
func Ref(connection uuid.UUID, name string) string {
	return "fake://" + connection.String() + "/" + name
}

// Current returns the current value of a secret, for test assertions.
func (v *Vault) Current(ref string) (string, string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.secrets[ref]
	if !ok || s.deleted || len(s.versions) == 0 {
		return "", "", false
	}
	return string(s.versions[len(s.versions)-1]), versionID(len(s.versions)), true
}

// Staged reports whether a staged value exists.
func (v *Vault) Staged(ref string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.staged[ref]
	return ok
}

// Tamper overwrites a staged value, simulating modification inside the provider.
func (v *Vault) Tamper(ref, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.staged[ref] = []byte(value)
}

// FailNext makes the next mutating call fail with err without applying it.
func (v *Vault) FailNext(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.failNext = err
}

// LoseNextResponse applies the next mutating call but reports a timeout,
// like a cloud API that accepted a write and then dropped the connection.
func (v *Vault) LoseNextResponse() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.loseResponse = true
}

// Applied counts mutating operations actually applied.
func (v *Vault) Applied() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.applied
}

// EnableRotation marks a secret as having a rotation function.
func (v *Vault) EnableRotation(ref string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.secrets[ref]; ok {
		s.rotatable = true
	}
}

// DisableRotation removes a secret's rotation function.
func (v *Vault) DisableRotation(ref string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.secrets[ref]; ok {
		s.rotatable = false
	}
}

// FinishRotations completes (or, with fail, fails) every in-progress
// rotation, like a rotation function finishing.
func (v *Vault) FinishRotations(fail bool) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, s := range v.secrets {
		for _, r := range s.rotations {
			if r.state != connectors.RotationInProgress {
				continue
			}
			n++
			if fail {
				r.state = connectors.RotationFailed
				continue
			}
			s.versions = append(s.versions, r.value)
			r.state, r.version = connectors.RotationDone, len(s.versions)
		}
	}
	return n
}

// Rotations counts rotation attempts started, for test assertions.
func (v *Vault) Rotations(ref string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.secrets[ref]; ok {
		return len(s.rotations)
	}
	return 0
}

func versionID(n int) string { return "v" + strconv.Itoa(n) }

type store struct {
	v    *Vault
	conn uuid.UUID
}

func (s *store) Stage(_ context.Context, t connectors.Target, requestID uuid.UUID, value sensitive.Value) (connectors.Staged, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	ref := "fake-staging://" + s.conn.String() + "/" + requestID.String()
	s.v.staged[ref] = append([]byte(nil), value.Reveal()...)
	return connectors.Staged{Ref: ref, Version: "s1"}, nil
}

func (s *store) ReadStaged(_ context.Context, st connectors.Staged) (sensitive.Value, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	b, ok := s.v.staged[st.Ref]
	if !ok {
		return sensitive.Value{}, connectors.ErrNotFound
	}
	return sensitive.New(b), nil
}

func (s *store) DiscardStaged(_ context.Context, st connectors.Staged) error {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	delete(s.v.staged, st.Ref)
	return nil
}

// apply runs op once per key and handles failure injection. Caller holds mu.
func (s *store) apply(key uuid.UUID, op func() (connectors.Result, error)) (connectors.Result, error) {
	if r, ok := s.v.ops[key]; ok {
		return r, nil
	}
	if err := s.v.failNext; err != nil {
		s.v.failNext = nil
		return connectors.Result{}, err
	}
	r, err := op()
	if err != nil {
		return r, err
	}
	r.RequestID = "fake-req-" + randomHex()
	s.v.ops[key] = r
	s.v.applied++
	if s.v.loseResponse {
		s.v.loseResponse = false
		return connectors.Result{}, fmt.Errorf("%w: response lost", connectors.ErrTransient)
	}
	return r, nil
}

func (s *store) Promote(_ context.Context, t connectors.Target, st connectors.Staged, key uuid.UUID) (connectors.Result, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	return s.apply(key, func() (connectors.Result, error) {
		val, ok := s.v.staged[st.Ref]
		if !ok {
			return connectors.Result{}, connectors.ErrNotFound
		}
		ref := t.ProviderRef
		if ref == "" {
			ref = Ref(s.conn, t.Name)
		}
		sec, ok := s.v.secrets[ref]
		if ok && !sec.deleted && t.ProviderRef == "" {
			return connectors.Result{}, connectors.ErrConflict // never overwrite on create
		}
		if !ok || sec.deleted {
			if t.ProviderRef != "" {
				return connectors.Result{}, connectors.ErrNotFound
			}
			sec = &secret{}
			s.v.secrets[ref] = sec
		}
		sec.versions = append(sec.versions, append([]byte(nil), val...))
		return connectors.Result{ProviderRef: ref, VersionID: versionID(len(sec.versions))}, nil
	})
}

func (s *store) Delete(_ context.Context, t connectors.Target, key uuid.UUID) (connectors.Result, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	return s.apply(key, func() (connectors.Result, error) {
		sec, ok := s.v.secrets[t.ProviderRef]
		if !ok || sec.deleted {
			return connectors.Result{}, connectors.ErrNotFound
		}
		sec.deleted = true
		return connectors.Result{ProviderRef: t.ProviderRef}, nil
	})
}

func (s *store) LookupOperation(_ context.Context, op connectors.Operation) (connectors.Result, bool, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	r, ok := s.v.ops[op.Key]
	return r, ok, nil
}

func (s *store) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{SecretCreate: true, SecretUpdate: true, SecretDelete: true, SecretReveal: true,
		Versioning: true, NativeRotation: true, UpdateStaging: "shadow_secret", CreateStaging: "shadow_secret"}
}

// List is not supported: the fake provider holds only what SecretMesh created.
func (s *store) List(context.Context, func(connectors.SecretInfo) error) error { return nil }

func (s *store) Versions(_ context.Context, t connectors.Target) ([]connectors.Version, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	sec, ok := s.v.secrets[t.ProviderRef]
	if !ok || sec.deleted {
		return nil, connectors.ErrNotFound
	}
	out := make([]connectors.Version, len(sec.versions))
	for i := range sec.versions {
		out[len(sec.versions)-1-i] = connectors.Version{ID: versionID(i + 1)}
	}
	out[0].Stages = []string{"current"}
	return out, nil
}

func (s *store) Reveal(_ context.Context, t connectors.Target) (sensitive.Value, string, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	sec, ok := s.v.secrets[t.ProviderRef]
	if !ok || sec.deleted || len(sec.versions) == 0 {
		return sensitive.Value{}, "", connectors.ErrNotFound
	}
	return sensitive.New(sec.versions[len(sec.versions)-1]), versionID(len(sec.versions)), nil
}

func (s *store) RotationConfigured(_ context.Context, t connectors.Target) (bool, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	sec, ok := s.v.secrets[t.ProviderRef]
	if !ok || sec.deleted {
		return false, connectors.ErrNotFound
	}
	return sec.rotatable, nil
}

func (s *store) StartRotation(_ context.Context, t connectors.Target, key uuid.UUID) (connectors.Result, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	return s.apply(key, func() (connectors.Result, error) {
		sec, ok := s.v.secrets[t.ProviderRef]
		if !ok || sec.deleted {
			return connectors.Result{}, connectors.ErrNotFound
		}
		for _, r := range sec.rotations {
			if r.state == connectors.RotationInProgress {
				return connectors.Result{}, connectors.ErrConflict
			}
		}
		if sec.rotations == nil {
			sec.rotations = map[uuid.UUID]*rotation{}
		}
		// The "rotation function" generates the value inside the provider.
		sec.rotations[key] = &rotation{value: []byte("rotated-" + randomHex()), state: connectors.RotationInProgress}
		// The version the value will have once current (AWS uses the key).
		return connectors.Result{ProviderRef: t.ProviderRef, VersionID: versionID(len(sec.versions) + 1)}, nil
	})
}

func (s *store) RotationState(_ context.Context, t connectors.Target, key uuid.UUID) (connectors.RotationState, string, error) {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	sec, ok := s.v.secrets[t.ProviderRef]
	if !ok {
		return 0, "", connectors.ErrNotFound
	}
	r, ok := sec.rotations[key]
	if !ok {
		return connectors.RotationNotStarted, "", nil
	}
	if r.version > 0 {
		return r.state, versionID(r.version), nil
	}
	return r.state, "", nil
}

func (s *store) AbandonRotation(_ context.Context, t connectors.Target, key uuid.UUID) error {
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	if sec, ok := s.v.secrets[t.ProviderRef]; ok {
		if r, ok := sec.rotations[key]; ok && r.state == connectors.RotationInProgress {
			r.state = connectors.RotationFailed
		}
	}
	return nil
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
