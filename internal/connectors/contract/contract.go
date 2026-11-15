// Package contract is the behavioural test suite every connectors.SecretStore
// must pass, so that providers differ only in capabilities, never in the
// guarantees the approval workflow relies on (ADR-0003, ADR-0007):
//
//   - a staged value is invisible to consumers until promotion;
//   - promotion is idempotent for a given journal key;
//   - a rejected or finished request leaves no staging behind;
//   - staging resources never appear in discovery;
//   - lookups report whether an operation took effect.
//
// Connector packages call Run from their own tests with a store connected to
// an emulator (or fake) that starts empty for the test.
package contract

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// NewStore returns a store connected to a provider namespace that other
// tests may share, so names must be unique per test (Run guarantees that).
type NewStore func(t *testing.T) connectors.SecretStore

// Name returns a secret name valid for every provider: lowercase letters,
// digits and dashes, at most 40 characters.
func Name(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
}

type harness struct {
	t     *testing.T
	store connectors.SecretStore
	ctx   context.Context
	conn  uuid.UUID
}

// Run executes the contract against stores built by newStore.
func Run(t *testing.T, newStore NewStore) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*harness)
	}{
		{"create is invisible until promoted", createFlow},
		{"update is invisible until promoted", updateFlow},
		{"promotion is idempotent", idempotentPromotion},
		{"lookup reports applied operations", lookupOperation},
		{"discarded update changes nothing", discardUpdate},
		{"create conflicts with an existing secret", createConflict},
		{"delete removes the secret from consumers and discovery", deleteFlow},
		{"missing secrets are not found", missingSecrets},
		{"staging never appears in discovery", stagingHiddenFromDiscovery},
		{"awkward values survive unchanged", awkwardValues},
	}
	// Providers without a sweeper (the in-memory fake) simply omit that case,
	// so a skipped test never hides a missing one.
	if _, ok := newStore(t).(connectors.StagingSweeper); ok {
		cases = append(cases, struct {
			name string
			fn   func(*harness)
		}{"sweeper removes only orphans", sweeperFlow})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.fn(&harness{t: t, store: newStore(t), ctx: context.Background(), conn: uuid.New()})
		})
	}
}

func (h *harness) must(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) stage(t connectors.Target, value string) (uuid.UUID, connectors.Staged) {
	h.t.Helper()
	id := uuid.New()
	st, err := h.store.Stage(h.ctx, t, id, sensitive.FromString(value))
	h.must(err)
	if st.Ref == "" {
		h.t.Fatal("Stage returned an empty reference")
	}
	return id, st
}

func (h *harness) readStaged(st connectors.Staged) string {
	h.t.Helper()
	v, err := h.store.ReadStaged(h.ctx, st)
	h.must(err)
	defer v.Wipe()
	return v.RevealString()
}

func (h *harness) reveal(t connectors.Target) string {
	h.t.Helper()
	v, _, err := h.store.Reveal(h.ctx, t)
	h.must(err)
	defer v.Wipe()
	return v.RevealString()
}

// create stages, promotes and discards a new secret, returning its target.
func (h *harness) create(name, value string) connectors.Target {
	h.t.Helper()
	t := connectors.Target{ConnectionID: h.conn, Name: name}
	_, st := h.stage(t, value)
	res, err := h.store.Promote(h.ctx, t, st, uuid.New())
	h.must(err)
	if res.ProviderRef == "" {
		h.t.Fatal("Promote returned no provider reference")
	}
	h.must(h.store.DiscardStaged(h.ctx, st))
	t.ProviderRef = res.ProviderRef
	return t
}

// discovery reports whether the store lists its secrets; the assertions
// about discovery only apply to providers that support it.
func (h *harness) discovery() bool { return h.store.Capabilities().Discovery }

func (h *harness) listed(name string) bool {
	h.t.Helper()
	found := false
	h.must(h.store.List(h.ctx, func(s connectors.SecretInfo) error {
		if s.Name == name {
			found = true
		}
		return nil
	}))
	return found
}

func createFlow(h *harness) {
	name := Name("ct-create")
	t := connectors.Target{ConnectionID: h.conn, Name: name}
	_, st := h.stage(t, "created-value-1")
	if got := h.readStaged(st); got != "created-value-1" {
		h.t.Fatalf("staged value read back as %q", got)
	}
	if h.discovery() && h.listed(name) {
		h.t.Fatal("secret is visible to discovery before approval")
	}
	key := uuid.New()
	res, err := h.store.Promote(h.ctx, t, st, key)
	h.must(err)
	t.ProviderRef = res.ProviderRef
	if got := h.reveal(t); got != "created-value-1" {
		h.t.Fatalf("promoted value read back as %q", got)
	}
	if h.discovery() && !h.listed(name) {
		h.t.Fatal("promoted secret is not discovered")
	}
	h.must(h.store.DiscardStaged(h.ctx, st))
	if _, err := h.store.ReadStaged(h.ctx, st); !errors.Is(err, connectors.ErrNotFound) {
		h.t.Fatalf("staging readable after discard: %v", err)
	}
	h.must(h.store.DiscardStaged(h.ctx, st)) // discarding twice is harmless
}

func updateFlow(h *harness) {
	t := h.create(Name("ct-update"), "old-value")
	_, st := h.stage(t, "new-value")
	if got := h.reveal(t); got != "old-value" {
		h.t.Fatalf("consumers see %q while an update is only staged", got)
	}
	if got := h.readStaged(st); got != "new-value" {
		h.t.Fatalf("staged value read back as %q", got)
	}
	res, err := h.store.Promote(h.ctx, t, st, uuid.New())
	h.must(err)
	if res.VersionID == "" {
		h.t.Fatal("Promote returned no version")
	}
	if got := h.reveal(t); got != "new-value" {
		h.t.Fatalf("after promotion consumers see %q", got)
	}
	h.must(h.store.DiscardStaged(h.ctx, st))
	vs, err := h.store.Versions(h.ctx, t)
	h.must(err)
	ids := map[string]bool{}
	for _, v := range vs {
		if v.ID == "" || ids[v.ID] {
			h.t.Fatalf("versions must have unique IDs: %+v", vs)
		}
		ids[v.ID] = true
	}
	if len(vs) < 2 {
		h.t.Fatalf("want at least 2 versions after an update, got %+v", vs)
	}
}

func idempotentPromotion(h *harness) {
	t := h.create(Name("ct-idem"), "v1")
	_, st := h.stage(t, "v2")
	key := uuid.New()
	first, err := h.store.Promote(h.ctx, t, st, key)
	h.must(err)
	again, err := h.store.Promote(h.ctx, t, st, key)
	h.must(err)
	if first.VersionID != again.VersionID {
		h.t.Fatalf("a retry created another version: %q then %q", first.VersionID, again.VersionID)
	}
	vs, err := h.store.Versions(h.ctx, t)
	h.must(err)
	if len(vs) != 2 {
		h.t.Fatalf("a retried promotion left %d versions, want 2", len(vs))
	}

	// Creating twice with the same key must not create two secrets or fail.
	name := Name("ct-idem-create")
	ct := connectors.Target{ConnectionID: h.conn, Name: name}
	_, cst := h.stage(ct, "c1")
	ck := uuid.New()
	a, err := h.store.Promote(h.ctx, ct, cst, ck)
	h.must(err)
	b, err := h.store.Promote(h.ctx, ct, cst, ck)
	h.must(err)
	if a.ProviderRef != b.ProviderRef {
		h.t.Fatalf("a retried create returned %q then %q", a.ProviderRef, b.ProviderRef)
	}
}

func lookupOperation(h *harness) {
	name := Name("ct-lookup")
	ct := connectors.Target{ConnectionID: h.conn, Name: name}
	_, cst := h.stage(ct, "l1")
	ckey := uuid.New()
	cop := connectors.Operation{Kind: "create", Target: ct, Staged: cst, Key: ckey}
	if _, ok, err := h.store.LookupOperation(h.ctx, cop); err != nil || ok {
		h.t.Fatalf("create reported applied before it ran: ok=%v err=%v", ok, err)
	}
	res, err := h.store.Promote(h.ctx, ct, cst, ckey)
	h.must(err)
	if _, ok, err := h.store.LookupOperation(h.ctx, cop); err != nil || !ok {
		h.t.Fatalf("applied create not found: ok=%v err=%v", ok, err)
	}
	h.must(h.store.DiscardStaged(h.ctx, cst))

	t := connectors.Target{ConnectionID: h.conn, Name: name, ProviderRef: res.ProviderRef}
	_, ust := h.stage(t, "l2")
	ukey := uuid.New()
	uop := connectors.Operation{Kind: "update", Target: t, Staged: ust, Key: ukey}
	if _, ok, err := h.store.LookupOperation(h.ctx, uop); err != nil || ok {
		h.t.Fatalf("update reported applied before it ran: ok=%v err=%v", ok, err)
	}
	if _, err := h.store.Promote(h.ctx, t, ust, ukey); err != nil {
		h.t.Fatal(err)
	}
	if _, ok, err := h.store.LookupOperation(h.ctx, uop); err != nil || !ok {
		h.t.Fatalf("applied update not found: ok=%v err=%v", ok, err)
	}
	// A different key (another request) must not be mistaken for this one.
	other := connectors.Operation{Kind: "update", Target: t, Staged: connectors.Staged{Ref: ust.Ref, Version: "unrelated"}, Key: uuid.New()}
	if _, ok, err := h.store.LookupOperation(h.ctx, other); err != nil || ok {
		h.t.Fatalf("an unrelated update was reported applied: ok=%v err=%v", ok, err)
	}
}

func discardUpdate(h *harness) {
	t := h.create(Name("ct-discard"), "keep-me")
	_, st := h.stage(t, "reject-me")
	h.must(h.store.DiscardStaged(h.ctx, st))
	if got := h.reveal(t); got != "keep-me" {
		h.t.Fatalf("a discarded update changed the secret to %q", got)
	}
	// The secret stays updatable after a discard.
	_, again := h.stage(t, "accepted")
	_, err := h.store.Promote(h.ctx, t, again, uuid.New())
	h.must(err)
	if got := h.reveal(t); got != "accepted" {
		h.t.Fatalf("update after a discard produced %q", got)
	}
}

func createConflict(h *harness) {
	name := Name("ct-conflict")
	orig := h.create(name, "original")
	ct := connectors.Target{ConnectionID: h.conn, Name: name}
	_, st := h.stage(ct, "intruder")
	_, err := h.store.Promote(h.ctx, ct, st, uuid.New())
	if !errors.Is(err, connectors.ErrConflict) {
		h.t.Fatalf("create over an existing secret: %v, want ErrConflict", err)
	}
	if got := h.reveal(orig); got != "original" {
		h.t.Fatalf("the original was overwritten with %q", got)
	}
}

func deleteFlow(h *harness) {
	name := Name("ct-delete")
	t := h.create(name, "doomed")
	key := uuid.New()
	_, err := h.store.Delete(h.ctx, t, key)
	h.must(err)
	if _, _, err := h.store.Reveal(h.ctx, t); !errors.Is(err, connectors.ErrNotFound) {
		h.t.Fatalf("a deleted secret can still be revealed: %v", err)
	}
	if h.discovery() && h.listed(name) {
		h.t.Fatal("a deleted secret is still discovered")
	}
	if _, ok, err := h.store.LookupOperation(h.ctx, connectors.Operation{Kind: "delete", Target: t, Key: key}); err != nil || !ok {
		h.t.Fatalf("applied delete not found: ok=%v err=%v", ok, err)
	}
	if _, err := h.store.Delete(h.ctx, t, key); err != nil {
		h.t.Fatalf("a retried delete failed: %v", err)
	}
}

func missingSecrets(h *harness) {
	// A real reference format is provider specific, so take one from a
	// secret that is then deleted.
	t := h.create(Name("ct-missing"), "x")
	_, err := h.store.Delete(h.ctx, t, uuid.New())
	h.must(err)
	if _, _, err := h.store.Reveal(h.ctx, t); !errors.Is(err, connectors.ErrNotFound) {
		h.t.Fatalf("Reveal: %v, want ErrNotFound", err)
	}
	if _, err := h.store.ReadStaged(h.ctx, connectors.Staged{Ref: "does-not-exist", Version: "1"}); err == nil {
		h.t.Fatal("ReadStaged accepted a reference this store never issued")
	}
}

func stagingHiddenFromDiscovery(h *harness) {
	name := Name("ct-hidden")
	ct := connectors.Target{ConnectionID: h.conn, Name: name}
	_, st := h.stage(ct, "secret-in-staging")
	h.must(h.store.List(h.ctx, func(s connectors.SecretInfo) error {
		if strings.Contains(s.Name, "staging") || s.Name == name {
			h.t.Errorf("discovery returned a staging or unpromoted secret: %q", s.Name)
		}
		return nil
	}))
	h.must(h.store.DiscardStaged(h.ctx, st))
}

func awkwardValues(h *harness) {
	values := []string{
		"line one\nline two\r\n\ttabbed",
		`{"user":"svc","password":"p@ss \"quoted\" \\ back"}`,
		"üñíçødé ✓ 秘密 🔐",
		strings.Repeat("A1b2C3d4", 1000), // 8 KB
		" leading and trailing spaces ",
	}
	for i, v := range values {
		t := h.create(Name("ct-value"), v)
		if got := h.reveal(t); got != v {
			h.t.Errorf("value %d changed in transit: got %d bytes, want %d", i, len(got), len(v))
		}
	}
}

func sweeperFlow(h *harness) {
	sw := h.store.(connectors.StagingSweeper)
	orphanTarget := connectors.Target{ConnectionID: h.conn, Name: Name("ct-orphan")}
	orphan, orphanSt := h.stage(orphanTarget, "orphaned")
	liveTarget := connectors.Target{ConnectionID: h.conn, Name: Name("ct-live")}
	liveID, liveSt := h.stage(liveTarget, "in flight")

	// Other tests share the namespace: only ever condemn this test's orphan.
	live := func(id uuid.UUID) (bool, error) { return id != orphan, nil }
	if n, err := sw.SweepStaging(h.ctx, time.Now().Add(-time.Hour), live); err != nil || n != 0 {
		h.t.Fatalf("a sweep inside the grace period removed %d (err %v)", n, err)
	}
	n, err := sw.SweepStaging(h.ctx, time.Now().Add(time.Minute), live)
	if err != nil || n != 1 {
		h.t.Fatalf("sweep removed %d, want 1 (err %v)", n, err)
	}
	if _, err := h.store.ReadStaged(h.ctx, orphanSt); !errors.Is(err, connectors.ErrNotFound) {
		h.t.Errorf("orphan still readable after the sweep: %v", err)
	}
	if got := h.readStaged(liveSt); got != "in flight" {
		h.t.Errorf("a live request's staging was touched: %q", got)
	}
	live = func(id uuid.UUID) (bool, error) { return id != liveID, nil }
	if n, err := sw.SweepStaging(h.ctx, time.Now().Add(time.Minute), live); err != nil || n != 1 {
		h.t.Errorf("sweep after the request finished removed %d, want 1 (err %v)", n, err)
	}
}
