package azure_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/azure"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

const canary = "CANARY-secret-value-do-not-leak-7f3a"

func stage(t *testing.T, s connectors.SecretStore, name, value string) (uuid.UUID, connectors.Staged) {
	t.Helper()
	id := uuid.New()
	st, err := s.Stage(context.Background(), connectors.Target{Name: name}, id, sensitive.FromString(value))
	if err != nil {
		t.Fatal(err)
	}
	return id, st
}

func TestValidateConfig(t *testing.T) {
	ok := func() map[string]string {
		return map[string]string{"vault_url": "https://prod-kv.vault.azure.net", "tenant_id": tenantID, "external_id": azure.NewExternalID()}
	}
	if err := azure.ValidateConfig(ok()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, suffix := range []string{"vault.usgovcloudapi.net", "vault.azure.cn", "vault.microsoftazure.de"} {
		c := ok()
		c["vault_url"] = "https://prod-kv." + suffix
		if err := azure.ValidateConfig(c); err != nil {
			t.Errorf("%s rejected: %v", suffix, err)
		}
	}
	cases := map[string]func(map[string]string){
		"unknown key":          func(c map[string]string) { c["note"] = "x" },
		"client secret":        func(c map[string]string) { c["client_secret"] = "s3cr3t" },
		"access token":         func(c map[string]string) { c["access_token"] = "eyJ" },
		"endpoint":             func(c map[string]string) { c["endpoint"] = "https://evil.example" },
		"http scheme":          func(c map[string]string) { c["vault_url"] = "http://prod-kv.vault.azure.net" },
		"wrong host":           func(c map[string]string) { c["vault_url"] = "https://prod-kv.evil.example" },
		"lookalike suffix":     func(c map[string]string) { c["vault_url"] = "https://prod-kv.vault.azure.net.evil.example" },
		"subdomain trick":      func(c map[string]string) { c["vault_url"] = "https://evil.example/.vault.azure.net" },
		"path":                 func(c map[string]string) { c["vault_url"] = "https://prod-kv.vault.azure.net/secrets" },
		"trailing slash":       func(c map[string]string) { c["vault_url"] = "https://prod-kv.vault.azure.net/" },
		"port":                 func(c map[string]string) { c["vault_url"] = "https://prod-kv.vault.azure.net:8443" },
		"userinfo":             func(c map[string]string) { c["vault_url"] = "https://user:pw@prod-kv.vault.azure.net" },
		"query":                func(c map[string]string) { c["vault_url"] = "https://prod-kv.vault.azure.net?x=1" },
		"vault name too short": func(c map[string]string) { c["vault_url"] = "https://ab.vault.azure.net" },
		"vault name too long": func(c map[string]string) {
			c["vault_url"] = "https://" + strings.Repeat("a", 25) + ".vault.azure.net"
		},
		"double dash":       func(c map[string]string) { c["vault_url"] = "https://prod--kv.vault.azure.net" },
		"leading digit":     func(c map[string]string) { c["vault_url"] = "https://1prod.vault.azure.net" },
		"missing vault":     func(c map[string]string) { delete(c, "vault_url") },
		"bad tenant":        func(c map[string]string) { c["tenant_id"] = "contoso.onmicrosoft.com" },
		"missing tenant":    func(c map[string]string) { delete(c, "tenant_id") },
		"chosen external":   func(c map[string]string) { c["external_id"] = "hunter2" },
		"empty external":    func(c map[string]string) { c["external_id"] = "" },
		"short external id": func(c map[string]string) { c["external_id"] = "secretmesh-1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := ok()
			mutate(c)
			if err := azure.ValidateConfig(c); err == nil {
				t.Errorf("accepted %v", c)
			}
		})
	}
}

func TestProviderConstruction(t *testing.T) {
	for _, bad := range []string{"ftp://x", "http://", "http://u:p@h", "http://h/path", "http://h?q=1", "not a url"} {
		if _, err := azure.New(context.Background(), azure.Options{Endpoint: bad}); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	// Without an injected credential the factory builds the workload-identity
	// chain; that must work without network access or secrets.
	p, err := azure.New(context.Background(), azure.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]string{"vault_url": vaultURL, "tenant_id": tenantID, "external_id": azure.NewExternalID()}
	conn := connectors.Connection{ID: uuid.New(), Provider: azure.ProviderName, Config: cfg}
	s1, err := p.Factory(conn)
	if err != nil {
		t.Fatalf("factory with the default identity chain: %v", err)
	}
	if s2, _ := p.Factory(conn); s1 != s2 {
		t.Error("stores are not cached per connection")
	}
	cfg["client_secret"] = "x"
	if _, err := p.Factory(conn); err == nil {
		t.Error("factory accepted a credential in the config")
	}
	caps := s1.Capabilities()
	if !caps.SecretCreate || !caps.Discovery || !caps.SoftDelete || caps.NativeRotation || caps.UpdateStaging != "shadow_secret" {
		t.Errorf("capabilities: %+v", caps)
	}
}

// The marker secret is the Azure ExternalId: without a matching one the
// connection must do nothing at all.
func TestExternalIDMarker(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"missing", "wrong"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixtureMarker(t, mode)
			f.kv.seed("app-secret", "visible", nil)
			target := connectors.Target{ConnectionID: uuid.New(), Name: "new-secret"}

			calls := map[string]func() error{
				"List": func() error { return f.store.List(ctx, func(connectors.SecretInfo) error { return nil }) },
				"Stage": func() error {
					_, err := f.store.Stage(ctx, target, uuid.New(), sensitive.FromString(canary))
					return err
				},
				"Reveal": func() error {
					_, _, err := f.store.Reveal(ctx, connectors.Target{ProviderRef: vaultURL + "/secrets/app-secret"})
					return err
				},
				"Delete": func() error {
					_, err := f.store.Delete(ctx, connectors.Target{ProviderRef: vaultURL + "/secrets/app-secret"}, uuid.New())
					return err
				},
			}
			for name, call := range calls {
				if err := call(); !errors.Is(err, connectors.ErrAccessDenied) {
					t.Errorf("%s: %v, want ErrAccessDenied", name, err)
				}
			}
			for _, r := range f.kv.requestLog() {
				if r != "GET /secrets/"+azure.MarkerName {
					t.Errorf("a request other than the marker read reached the vault: %s", r)
				}
			}
			if !f.kv.has("app-secret") || f.kv.versionCount("app-secret") != 1 {
				t.Error("the vault was modified")
			}
		})
	}

	t.Run("matching marker is trusted for 15 minutes", func(t *testing.T) {
		f := newFixture(t)
		list := func() error { return f.store.List(ctx, func(connectors.SecretInfo) error { return nil }) }
		if err := list(); err != nil {
			t.Fatal(err)
		}
		f.kv.seed(azure.MarkerName, "rotated-away", nil) // marker changed after verification
		if err := list(); err != nil {
			t.Fatalf("within the trust window: %v", err)
		}
		*f.now = f.now.Add(16 * time.Minute)
		if err := list(); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("after the window with a changed marker: %v, want ErrAccessDenied", err)
		}
		// A failure is never cached: still denied on the next call.
		if err := list(); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("second call after failure: %v", err)
		}
	})

	t.Run("unreadable marker", func(t *testing.T) {
		f := newFixture(t)
		f.kv.setFail(azure.MarkerName, http.StatusForbidden)
		if err := f.store.List(ctx, func(connectors.SecretInfo) error { return nil }); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("403 on the marker: %v", err)
		}
	})
}

func TestReservedAndInvalidNames(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, name := range []string{
		azure.MarkerName, "SecretMesh-External-ID", "smstaging-abc", "SMSTAGING-" + uuid.NewString(),
		"", "a/b", "a_b", "has space", "dot.dot", "../x", strings.Repeat("a", 128),
	} {
		_, err := f.store.Stage(ctx, connectors.Target{Name: name}, uuid.New(), sensitive.FromString("v"))
		if err == nil {
			t.Errorf("Stage accepted target name %q", name)
		}
	}
	// Promote(create) re-checks the name even with a valid staging reference.
	_, st := stage(t, f.store, "fine-name", "v")
	if _, err := f.store.Promote(ctx, connectors.Target{Name: azure.MarkerName}, st, uuid.New()); err == nil {
		t.Error("Promote overwrote the marker")
	}
	if _, err := f.store.Promote(ctx, connectors.Target{Name: "smstaging-" + uuid.NewString()}, st, uuid.New()); err == nil {
		t.Error("Promote created a staging-named secret")
	}

	// References must point into this vault and never at reserved secrets.
	for _, ref := range []string{
		"https://evil.vault.azure.net/secrets/app",
		vaultURL + "/secrets/" + azure.MarkerName,
		vaultURL + "/secrets/smstaging-" + uuid.NewString(),
		vaultURL + "/secrets/",
		vaultURL + "/keys/app",
		"app",
	} {
		if _, _, err := f.store.Reveal(ctx, connectors.Target{ProviderRef: ref}); err == nil {
			t.Errorf("Reveal accepted reference %q", ref)
		}
		if _, err := f.store.Delete(ctx, connectors.Target{ProviderRef: ref}, uuid.New()); err == nil {
			t.Errorf("Delete accepted reference %q", ref)
		}
		if _, err := f.store.Versions(ctx, connectors.Target{ProviderRef: ref}); err == nil {
			t.Errorf("Versions accepted reference %q", ref)
		}
	}
	// Staging references only reach shadow secrets.
	for _, ref := range []string{"shadow:" + azure.MarkerName, "shadow:app-secret", "shadow:smstaging-notauuid", "app", "shadow:"} {
		if _, err := f.store.ReadStaged(ctx, connectors.Staged{Ref: ref, Version: randHex()}); err == nil {
			t.Errorf("ReadStaged accepted %q", ref)
		}
		if err := f.store.DiscardStaged(ctx, connectors.Staged{Ref: ref, Version: randHex()}); err == nil {
			t.Errorf("DiscardStaged accepted %q", ref)
		}
	}
	if _, err := f.store.ReadStaged(ctx, connectors.Staged{Ref: st.Ref, Version: "../../secrets"}); err == nil {
		t.Error("ReadStaged accepted a malformed version")
	}
	// The marker is still intact.
	if f.kv.versionCount(azure.MarkerName) != 1 {
		t.Error("the marker was modified")
	}
}

func TestValueLimits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	target := connectors.Target{Name: "limits"}
	if _, err := f.store.Stage(ctx, target, uuid.New(), sensitive.FromString(strings.Repeat("a", 25*1024+1))); err == nil {
		t.Error("a value over 25 KiB was accepted")
	}
	if _, err := f.store.Stage(ctx, target, uuid.New(), sensitive.New([]byte{0xff, 0xfe, 'a'})); err == nil {
		t.Error("a value that is not UTF-8 was accepted")
	}
	if _, err := f.store.Stage(ctx, target, uuid.New(), sensitive.FromString(strings.Repeat("a", 25*1024))); err != nil {
		t.Errorf("a value of exactly 25 KiB was rejected: %v", err)
	}
	// Updating a secret that does not exist fails at staging.
	_, err := f.store.Stage(ctx, connectors.Target{ProviderRef: vaultURL + "/secrets/ghost"}, uuid.New(), sensitive.FromString("v"))
	if !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("staging an update of a missing secret: %v", err)
	}
}

// Redirects must never be followed: the bearer token would go with them.
func TestRedirectIsNotFollowed(t *testing.T) {
	f := newFixture(t)
	f.kv.seed("app-secret", "v", nil)
	var hits atomic.Int32
	var auth atomic.Value
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth.Store(r.Header.Get("Authorization"))
	}))
	defer evil.Close()

	// Verify the marker first so the redirect hits an ordinary operation.
	if err := f.store.List(context.Background(), func(connectors.SecretInfo) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.kv.redirect = evil.URL
	_, _, err := f.store.Reveal(context.Background(), connectors.Target{ProviderRef: vaultURL + "/secrets/app-secret"})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Reveal through a redirect: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect target received %d requests (Authorization %v)", hits.Load(), auth.Load())
	}
}

func TestNextLinkOnAnotherHostIsRefused(t *testing.T) {
	f := newFixture(t)
	for i := range 5 {
		f.kv.seed("app-"+strings.Repeat("x", i+1), "v", nil)
	}
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer evil.Close()
	f.kv.nextHost = evil.URL

	err := f.store.List(context.Background(), func(connectors.SecretInfo) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("List with a foreign nextLink: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the foreign host received %d requests", hits.Load())
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	f := newFixture(t)
	f.kv.seed("big", "v", nil)
	f.kv.bigBody = true
	_, _, err := f.store.Reveal(context.Background(), connectors.Target{ProviderRef: vaultURL + "/secrets/big"})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("a 3 MiB response: %v", err)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, connectors.ErrAccessDenied},
		{http.StatusForbidden, connectors.ErrAccessDenied},
		{http.StatusNotFound, connectors.ErrNotFound},
		{http.StatusTooManyRequests, connectors.ErrTransient},
		{http.StatusInternalServerError, connectors.ErrTransient},
		{http.StatusServiceUnavailable, connectors.ErrTransient},
	}
	for _, c := range cases {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			f := newFixture(t)
			f.kv.seed("app-secret", "v", nil)
			if err := f.store.List(context.Background(), func(connectors.SecretInfo) error { return nil }); err != nil {
				t.Fatal(err)
			}
			f.kv.setFail("/secrets/app-secret", c.status)
			_, _, err := f.store.Reveal(context.Background(), connectors.Target{ProviderRef: vaultURL + "/secrets/app-secret"})
			if !errors.Is(err, c.want) {
				t.Fatalf("status %d: %v, want %v", c.status, err, c.want)
			}
		})
	}
}

// Neither a secret value nor a provider error message may reach an error or a log.
func TestNothingSensitiveLeaks(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	f := newFixture(t)
	ctx := context.Background()
	var errs []error
	record := func(err error) { errs = append(errs, err) }

	target := connectors.Target{Name: "leak-check"}
	id, st := stage(t, f.store, "leak-check", canary)
	res, err := f.store.Promote(ctx, target, st, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	live := connectors.Target{Name: "leak-check", ProviderRef: res.ProviderRef}
	_, st2 := stage(t, f.store, "leak-check", canary+"2")
	_, err = f.store.Promote(ctx, target, st2, uuid.New()) // conflict
	record(err)
	f.kv.badCode = "BadParameter" // error body carries a message the client must not echo
	_, _, err = f.store.Reveal(ctx, live)
	record(err)
	_, err = f.store.Versions(ctx, live)
	record(err)
	f.kv.badCode = ""
	f.kv.setFail("/secrets/leak-check", http.StatusInternalServerError)
	_, _, err = f.store.Reveal(ctx, live)
	record(err)
	_, err = f.store.Stage(ctx, connectors.Target{ProviderRef: live.ProviderRef}, id, sensitive.FromString(canary))
	record(err)

	for _, err := range errs {
		if err == nil {
			t.Error("an expected failure did not happen")
			continue
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "message that must never reach callers") {
			t.Errorf("error leaks provider content: %v", err)
		}
	}
	if !strings.Contains(errs[1].Error(), "BadParameter") {
		t.Errorf("the provider's error code should be reported: %v", errs[1])
	}
	if strings.Contains(logs.String(), canary) {
		t.Errorf("log output contains the secret value: %s", logs.String())
	}
	if s := sensitive.FromString(canary); strings.Contains(s.String(), canary) {
		t.Error("sensitive.Value renders its content")
	}
}

// A response lost after the vault applied the write must not produce a second version.
func TestLostResponseRetry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	target := connectors.Target{Name: "lossy"}
	_, st := stage(t, f.store, "lossy", "v1")
	res, err := f.store.Promote(ctx, target, st, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	live := connectors.Target{Name: "lossy", ProviderRef: res.ProviderRef}

	_, st2 := stage(t, f.store, "lossy", "v2")
	key := uuid.New()
	f.kv.dropNext = true
	if _, err := f.store.Promote(ctx, live, st2, key); !errors.Is(err, connectors.ErrTransient) {
		t.Fatalf("the dropped connection: %v, want ErrTransient", err)
	}
	if n := f.kv.versionCount("lossy"); n != 2 {
		t.Fatalf("the vault applied the write once, found %d versions", n)
	}
	op := connectors.Operation{Kind: "update", Target: live, Staged: st2, Key: key}
	found, ok, err := f.store.LookupOperation(ctx, op)
	if err != nil || !ok || found.VersionID == "" {
		t.Fatalf("reconciliation did not find the applied write: %+v ok=%v err=%v", found, ok, err)
	}
	again, err := f.store.Promote(ctx, live, st2, key)
	if err != nil {
		t.Fatal(err)
	}
	if again.VersionID != found.VersionID {
		t.Errorf("retry returned version %q, reconciliation %q", again.VersionID, found.VersionID)
	}
	if n := f.kv.versionCount("lossy"); n != 2 {
		t.Fatalf("the retry wrote another version: %d versions", n)
	}
	v, _, err := f.store.Reveal(ctx, live)
	if err != nil || v.RevealString() != "v2" {
		t.Fatalf("current value: %v %v", v.RevealString(), err)
	}
}

// Updating must keep the tags discovery depends on.
func TestUpdateKeepsTagsAndContentType(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.kv.mu.Lock()
	f.kv.putLocked("tagged", "old", "text/plain", map[string]string{"secretmesh:environment": "prod", "owner": "payments"})
	f.kv.mu.Unlock()
	live := connectors.Target{ProviderRef: vaultURL + "/secrets/tagged"}
	_, st := stage(t, f.store, "ignored", "new")
	if _, err := f.store.Promote(ctx, live, st, uuid.New()); err != nil {
		t.Fatal(err)
	}
	var info connectors.SecretInfo
	if err := f.store.List(ctx, func(s connectors.SecretInfo) error {
		if s.Name == "tagged" {
			info = s
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if info.Tags["secretmesh:environment"] != "prod" || info.Tags["owner"] != "payments" {
		t.Errorf("tags after an update: %v", info.Tags)
	}
	if info.ProviderRef != vaultURL+"/secrets/tagged" || info.LastChanged == nil {
		t.Errorf("discovery info: %+v", info)
	}
	f.kv.mu.Lock()
	ct := latestOf(f.kv, "tagged").ctype
	f.kv.mu.Unlock()
	if ct != "text/plain" {
		t.Errorf("content type after an update: %q", ct)
	}
}

func latestOf(k *kv, name string) *fakeVersion { return latest(k.secrets[name]) }

func TestDiscoveryPagingAndExclusions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range 7 {
		f.kv.seed("app-"+strings.Repeat("a", i+1), "v", map[string]string{"n": "x"})
	}
	f.kv.seed("smstaging-"+uuid.NewString(), "staged", map[string]string{"secretmesh-staging": "true"})
	var names []string
	if err := f.store.List(ctx, func(s connectors.SecretInfo) error { names = append(names, s.Name); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(names) != 7 {
		t.Errorf("discovered %v, want the 7 app secrets across 4+ pages (no marker, no staging)", names)
	}
	// A failing callback stops the listing and surfaces its error.
	boom := errors.New("stop")
	if err := f.store.List(ctx, func(connectors.SecretInfo) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("callback error: %v", err)
	}
}

func TestRevealFallsBackFromDisabledVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	live := func() connectors.Target { return connectors.Target{ProviderRef: vaultURL + "/secrets/rotating"} }
	f.kv.seed("rotating", "good", nil)
	f.kv.seed("rotating", "bad", nil)
	f.kv.disableLatest("rotating")
	v, ver, err := f.store.Reveal(ctx, live())
	if err != nil || v.RevealString() != "good" || ver == "" {
		t.Fatalf("Reveal with the newest version disabled: %q %q %v", v.RevealString(), ver, err)
	}
	vs, err := f.store.Versions(ctx, live())
	if err != nil || len(vs) != 2 || len(vs[0].Stages) != 0 || len(vs[1].Stages) != 1 {
		t.Fatalf("versions with the newest disabled: %+v %v", vs, err)
	}
	f.kv.disableLatest("rotating") // disables "bad" again; now disable "good" too
	f.kv.mu.Lock()
	for _, x := range f.kv.secrets["rotating"].versions {
		x.enabled = false
	}
	f.kv.mu.Unlock()
	if _, _, err := f.store.Reveal(ctx, live()); !errors.Is(err, connectors.ErrNotFound) {
		t.Fatalf("Reveal with every version disabled: %v", err)
	}
}

func TestStagingPurgeRefusedIsTolerated(t *testing.T) {
	f := newFixture(t)
	f.kv.purgeProtection = true
	_, st := stage(t, f.store, "purge-protected", canary)
	if err := f.store.DiscardStaged(context.Background(), st); err != nil {
		t.Fatalf("DiscardStaged with purge protection: %v", err)
	}
	// Gone for readers, though still recoverable inside the vault.
	if _, err := f.store.ReadStaged(context.Background(), st); !errors.Is(err, connectors.ErrNotFound) {
		t.Fatalf("staged value readable after discard: %v", err)
	}
	if !f.kv.isSoftDeleted("smstaging-" + strings.TrimPrefix(st.Ref, "shadow:smstaging-")) {
		t.Error("the shadow secret should remain soft-deleted under purge protection")
	}
}

func TestCreateOverSoftDeletedNameConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, st := stage(t, f.store, "recreated", "v1")
	res, err := f.store.Promote(ctx, connectors.Target{Name: "recreated"}, st, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Delete(ctx, connectors.Target{ProviderRef: res.ProviderRef}, uuid.New()); err != nil {
		t.Fatal(err)
	}
	_, st2 := stage(t, f.store, "recreated", "v2")
	_, err = f.store.Promote(ctx, connectors.Target{Name: "recreated"}, st2, uuid.New())
	if !errors.Is(err, connectors.ErrConflict) {
		t.Fatalf("creating over a soft-deleted name: %v, want ErrConflict", err)
	}
	// Deleting something that never existed is an error, not a silent success.
	if _, err := f.store.Delete(ctx, connectors.Target{ProviderRef: vaultURL + "/secrets/never-existed"}, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Fatalf("deleting a missing secret: %v", err)
	}
	// A delete is reported applied once the secret is soft-deleted or gone.
	op := connectors.Operation{Kind: "delete", Target: connectors.Target{ProviderRef: vaultURL + "/secrets/never-existed"}, Key: uuid.New()}
	if _, ok, err := f.store.LookupOperation(ctx, op); err != nil || !ok {
		t.Errorf("a secret that is gone counts as deleted: ok=%v err=%v", ok, err)
	}
	live := connectors.Operation{Kind: "delete", Target: connectors.Target{ProviderRef: vaultURL + "/secrets/app-live"}, Key: uuid.New()}
	f.kv.seed("app-live", "v", nil)
	if _, ok, err := f.store.LookupOperation(ctx, live); err != nil || ok {
		t.Errorf("a live secret was reported deleted: ok=%v err=%v", ok, err)
	}
}

func TestSweeperOnlyTouchesTaggedShadowSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sw := f.store.(connectors.StagingSweeper)

	orphan := uuid.New()
	f.kv.seed("smstaging-"+orphan.String(), "x", map[string]string{"secretmesh-staging": "true"})
	untagged := "smstaging-" + uuid.NewString()
	f.kv.seed(untagged, "someone else's", nil)
	badName := "smstaging-not-a-uuid"
	f.kv.seed(badName, "x", map[string]string{"secretmesh-staging": "true"})
	noPrefix := uuid.NewString()
	f.kv.seed(noPrefix, "x", map[string]string{"secretmesh-staging": "true"})
	f.kv.seed("app-real", "x", map[string]string{"secretmesh-staging": "true"})

	all := func(uuid.UUID) (bool, error) { return false, nil } // every request is dead
	n, err := sw.SweepStaging(ctx, time.Now().Add(time.Hour), all)
	if err != nil || n != 1 {
		t.Fatalf("sweep removed %d (err %v), want exactly the tagged shadow secret", n, err)
	}
	for _, name := range []string{untagged, badName, noPrefix, "app-real", azure.MarkerName} {
		if !f.kv.has(name) {
			t.Errorf("sweeper deleted %q", name)
		}
	}
	if f.kv.has("smstaging-" + orphan.String()) {
		t.Error("sweeper left the orphan")
	}
	boom := errors.New("database down")
	f.kv.seed("smstaging-"+uuid.NewString(), "x", map[string]string{"secretmesh-staging": "true"})
	if _, err := sw.SweepStaging(ctx, time.Now().Add(time.Hour), func(uuid.UUID) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Errorf("liveness errors must surface: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.store.List(ctx, func(connectors.SecretInfo) error { return nil }); err == nil {
		t.Fatal("a cancelled context was ignored")
	}
}
