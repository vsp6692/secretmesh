package gcp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/contract"
	"github.com/secretmesh/secretmesh/internal/connectors/gcp"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func TestContract(t *testing.T) {
	contract.Run(t, func(t *testing.T) connectors.SecretStore {
		s, _ := newFake(t).newStore(t)
		return s
	})
}

func TestCapabilities(t *testing.T) {
	s, _ := newFake(t).newStore(t)
	c := s.Capabilities()
	if !c.SecretCreate || !c.SecretUpdate || !c.SecretDelete || !c.SecretReveal || !c.Discovery || !c.Versioning || !c.SoftDelete || !c.Tags {
		t.Errorf("capabilities: %+v", c)
	}
	if c.NativeRotation || c.VersionLabels || c.UpdateStaging != "shadow_secret" || c.CreateStaging != "shadow_secret" {
		t.Errorf("capabilities: %+v", c)
	}
	if _, ok := s.(connectors.StagingSweeper); !ok {
		t.Error("the store must implement StagingSweeper")
	}
}

func TestValidateConfig(t *testing.T) {
	ok := config("secretmesh-abc")
	with := func(k, v string) map[string]string {
		c := config("secretmesh-abc")
		if v == "" {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	if err := gcp.ValidateConfig(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]map[string]string{
		"unknown key":             with("region", "europe-west1"),
		"key file":                with("credentials_json", `{"type":"service_account"}`),
		"key file path":           with("key_file", "/etc/key.json"),
		"token":                   with("access_token", "ya29.secret"),
		"endpoint":                with("endpoint", "http://evil.example"),
		"missing project":         with("project_id", ""),
		"short project":           with("project_id", "abc"),
		"uppercase project":       with("project_id", "My-Project-123"),
		"project with slash":      with("project_id", "my-project/../x"),
		"missing service account": with("service_account", ""),
		"not a gserviceaccount":   with("service_account", "user@gmail.com"),
		"default compute account": with("service_account", "123456-compute@developer.gserviceaccount.com"),
		"sa with injection":       with("service_account", "a@b.iam.gserviceaccount.com/../x"),
		"external id not ours":    with("external_id", "chosen-by-caller"),
		"external id missing":     with("external_id", ""),
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			err := gcp.ValidateConfig(c)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, v := range c {
				if strings.Contains(v, "ya29.secret") && strings.Contains(err.Error(), "ya29.secret") {
					t.Errorf("error echoes a credential value: %v", err)
				}
			}
		})
	}
	if id := gcp.NewExternalID(); !strings.HasPrefix(id, "secretmesh-") || len(id) != len("secretmesh-")+32 || id == gcp.NewExternalID() {
		t.Errorf("external id %q", id)
	}
}

func TestFactoryRejectsBadConfig(t *testing.T) {
	p := newFake(t).provider(t)
	if _, err := p.Factory(connectors.Connection{ID: uuid.New(), Config: map[string]string{"project_id": "x"}}); err == nil {
		t.Fatal("factory accepted an invalid config")
	}
	c := connectors.Connection{ID: uuid.New(), Config: config("secretmesh-x")}
	a, err := p.Factory(c)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := p.Factory(c); a != b {
		t.Error("factory should cache stores per connection")
	}
}

func TestNewOptions(t *testing.T) {
	ts := staticToken(baseToken)
	for name, o := range map[string]gcp.Options{
		"ftp endpoint":      {Endpoint: "ftp://x", BaseTokenSource: ts},
		"userinfo":          {Endpoint: "http://user:pw@127.0.0.1:1", BaseTokenSource: ts},
		"path in endpoint":  {Endpoint: "http://127.0.0.1:1/v1", BaseTokenSource: ts},
		"bad iam endpoint":  {IAMEndpoint: "not a url", BaseTokenSource: ts},
		"no host":           {Endpoint: "http://", BaseTokenSource: ts},
		"query in endpoint": {Endpoint: "http://127.0.0.1:1?x=1", BaseTokenSource: ts},
	} {
		if _, err := gcp.New(t.Context(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := gcp.New(t.Context(), gcp.Options{BaseTokenSource: ts}); err != nil {
		t.Errorf("production endpoints with an injected token source: %v", err)
	}
}

// writeCredentials stores an ADC file and points the environment at it.
func writeCredentials(t *testing.T, content map[string]any) {
	t.Helper()
	b, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

func TestServiceAccountKeyFileIsRefused(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	writeCredentials(t, map[string]any{
		"type": "service_account", "project_id": "p", "private_key_id": "1", "client_id": "1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "k@p.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
	})
	_, err = gcp.New(t.Context(), gcp.Options{})
	if err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("a service account key was accepted as SecretMesh's identity: %v", err)
	}
	if _, err := gcp.New(t.Context(), gcp.Options{AllowServiceAccountKeys: true}); err != nil {
		t.Fatalf("explicit development opt-in failed: %v", err)
	}
}

func TestKeylessCredentialsAreAccepted(t *testing.T) {
	// Workload Identity Federation: an external_account config, no secret in the file.
	writeCredentials(t, map[string]any{
		"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": "https://sts.googleapis.com/v1/token",
		"credential_source": map[string]any{"file": "/var/run/secrets/token"},
	})
	if _, err := gcp.New(t.Context(), gcp.Options{}); err != nil {
		t.Fatalf("federated credentials rejected: %v", err)
	}
}

func TestMissingCredentialsFailAtStartup(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))
	if _, err := gcp.New(t.Context(), gcp.Options{}); err == nil {
		t.Fatal("startup succeeded without credentials")
	}
}

// ---- ownership marker ----

func TestExternalIDMarker(t *testing.T) {
	ctx := context.Background()
	target := connectors.Target{Name: "app-key"}

	t.Run("missing marker", func(t *testing.T) {
		f := newFake(t)
		s, err := f.provider(t).Factory(connectors.Connection{ID: uuid.New(), Config: config(gcp.NewExternalID())})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Stage(ctx, target, uuid.New(), sensitive.FromString("v"))
		if !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("Stage without the marker secret: %v", err)
		}
		if err := s.List(ctx, func(connectors.SecretInfo) error { return nil }); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("List without the marker secret: %v", err)
		}
		for _, r := range f.requestLog() {
			if strings.Contains(r, "addVersion") || strings.Contains(r, "POST /v1/projects/"+testProject+"/secrets?") {
				t.Fatalf("a write reached the project before ownership was proven: %s", r)
			}
		}
	})

	t.Run("mismatched marker", func(t *testing.T) {
		f := newFake(t)
		f.seed(gcp.MarkerSecret, nil, nil, time.Now(), "secretmesh-someone-elses-id")
		s, err := f.provider(t).Factory(connectors.Connection{ID: uuid.New(), Config: config(gcp.NewExternalID())})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Stage(ctx, target, uuid.New(), sensitive.FromString("v"))
		if !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("Stage with another tenant's marker: %v", err)
		}
		if strings.Contains(err.Error(), "someone-elses") {
			t.Errorf("error discloses the marker value: %v", err)
		}
	})

	t.Run("matching marker with a trailing newline", func(t *testing.T) {
		f := newFake(t)
		extID := gcp.NewExternalID()
		f.seed(gcp.MarkerSecret, nil, nil, time.Now(), extID+"\n")
		s, err := f.provider(t).Factory(connectors.Connection{ID: uuid.New(), Config: config(extID)})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.List(ctx, func(connectors.SecretInfo) error { return nil }); err != nil {
			t.Fatalf("matching marker rejected: %v", err)
		}
	})

	t.Run("re-verified every 15 minutes", func(t *testing.T) {
		f := newFake(t)
		clk := &clock{t: time.Now()}
		s, _ := f.newStore(t, func(o *gcp.Options) { o.Now = clk.Now })
		list := func() error { return s.List(ctx, func(connectors.SecretInfo) error { return nil }) }
		if err := list(); err != nil {
			t.Fatal(err)
		}
		f.addValue(gcp.MarkerSecret, "secretmesh-rotated-away") // the customer revokes the connection
		clk.Advance(14 * time.Minute)
		if err := list(); err != nil {
			t.Fatalf("verification should still be cached after 14 minutes: %v", err)
		}
		clk.Advance(2 * time.Minute)
		if err := list(); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("a revoked marker was not noticed after 15 minutes: %v", err)
		}
	})
}

func TestMarkerAndStagingAreReserved(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	v := sensitive.FromString("v")
	for _, name := range []string{gcp.MarkerSecret, gcp.StagingPrefix + "x", "has/slash", "has space", "", strings.Repeat("a", 256)} {
		if _, err := s.Stage(ctx, connectors.Target{Name: name}, uuid.New(), v); err == nil {
			t.Errorf("Stage accepted the name %q", name)
		}
	}
	// A staged value cannot be promoted into a reserved name either.
	_, st := stage(t, s, "ok-name", "v")
	for _, name := range []string{gcp.MarkerSecret, gcp.StagingPrefix + "x"} {
		if _, err := s.Promote(ctx, connectors.Target{Name: name}, st, uuid.New()); err == nil {
			t.Errorf("Promote created %q", name)
		}
	}
	// The marker is not addressable as a secret: no reveal, update or delete.
	marker := "projects/" + testProject + "/secrets/" + gcp.MarkerSecret
	if _, _, err := s.Reveal(ctx, connectors.Target{ProviderRef: marker}); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Reveal of the marker: %v", err)
	}
	if _, err := s.Delete(ctx, connectors.Target{ProviderRef: marker}, uuid.New()); err == nil {
		t.Error("Delete accepted the marker")
	}
	if _, err := s.Stage(ctx, connectors.Target{ProviderRef: marker}, uuid.New(), v); err == nil {
		t.Error("Stage accepted an update of the marker")
	}
	if sec, ok := f.secret(gcp.MarkerSecret); !ok || len(sec.versions) != 1 {
		t.Error("the marker secret was modified")
	}
}

func stage(t *testing.T, s connectors.SecretStore, name, value string) (uuid.UUID, connectors.Staged) {
	t.Helper()
	id := uuid.New()
	st, err := s.Stage(context.Background(), connectors.Target{Name: name}, id, sensitive.FromString(value))
	if err != nil {
		t.Fatal(err)
	}
	return id, st
}

func create(t *testing.T, s connectors.SecretStore, name, value string) connectors.Target {
	t.Helper()
	_, st := stage(t, s, name, value)
	res, err := s.Promote(context.Background(), connectors.Target{Name: name}, st, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DiscardStaged(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	return connectors.Target{Name: name, ProviderRef: res.ProviderRef}
}

// ---- references and project boundary ----

func TestForeignProjectsAreNeverContacted(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	other := "projects/other-project-999/secrets/x"
	before := len(f.requestLog())
	for name, err := range map[string]error{
		"reveal":   second(s.Reveal(ctx, connectors.Target{ProviderRef: other})),
		"versions": second2(s.Versions(ctx, connectors.Target{ProviderRef: other})),
		"stage":    second3(s.Stage(ctx, connectors.Target{ProviderRef: other}, uuid.New(), sensitive.FromString("v"))),
		"delete":   second4(s.Delete(ctx, connectors.Target{ProviderRef: other}, uuid.New())),
		"read":     second5(s.ReadStaged(ctx, connectors.Staged{Ref: "shadow:projects/other-project-999/secrets/" + gcp.StagingPrefix + uuid.NewString(), Version: "1"})),
		"discard":  s.DiscardStaged(ctx, connectors.Staged{Ref: "shadow:projects/other-project-999/secrets/" + gcp.StagingPrefix + uuid.NewString(), Version: "1"}),
		"promote":  second4(s.Promote(ctx, connectors.Target{ProviderRef: other}, connectors.Staged{Ref: "shadow:projects/" + testProject + "/secrets/" + gcp.StagingPrefix + uuid.NewString(), Version: "1"}, uuid.New())),
	} {
		if err == nil {
			t.Errorf("%s accepted a reference outside the project", name)
		}
	}
	for _, r := range f.requestLog()[before:] {
		if strings.Contains(r, "other-project") {
			t.Errorf("request reached another project: %s", r)
		}
	}
	// Staging references must be SecretMesh staging secrets, not arbitrary ones.
	for _, ref := range []string{"projects/" + testProject + "/secrets/app-key", "shadow:projects/" + testProject + "/secrets/app-key",
		"shadow:projects/" + testProject + "/secrets/" + gcp.StagingPrefix + "not-a-uuid", "shadow:", ""} {
		if _, err := s.ReadStaged(ctx, connectors.Staged{Ref: ref}); err == nil {
			t.Errorf("ReadStaged accepted %q", ref)
		}
		if err := s.DiscardStaged(ctx, connectors.Staged{Ref: ref}); err == nil {
			t.Errorf("DiscardStaged accepted %q", ref)
		}
	}
}

func second(_ sensitive.Value, _ string, err error) error { return err }
func second2(_ []connectors.Version, err error) error     { return err }
func second3(_ connectors.Staged, err error) error        { return err }
func second4(_ connectors.Result, err error) error        { return err }
func second5(_ sensitive.Value, err error) error          { return err }

func TestDiscardRefusesNonStagingSecrets(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	// Same name shape as staging, but not labelled by SecretMesh.
	id := gcp.StagingPrefix + uuid.NewString()
	f.seed(id, nil, nil, time.Now(), "customer data")
	err := s.DiscardStaged(context.Background(), connectors.Staged{Ref: "shadow:projects/" + testProject + "/secrets/" + id, Version: "1"})
	if err == nil {
		t.Fatal("DiscardStaged deleted an unlabelled secret")
	}
	if _, ok := f.secret(id); !ok {
		t.Fatal("the unlabelled secret was deleted")
	}
}

// ---- HTTP hygiene ----

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer trap.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, trap.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	f := newFake(t)
	p := f.provider(t, func(o *gcp.Options) { o.Endpoint = redirector.URL })
	s, err := p.Factory(connectors.Connection{ID: uuid.New(), Config: config(gcp.NewExternalID())})
	if err != nil {
		t.Fatal(err)
	}
	err = s.List(context.Background(), func(connectors.SecretInfo) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect target received %d requests (the bearer token would have leaked)", hits.Load())
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 3<<20))
	}))
	defer big.Close()
	f := newFake(t)
	s, err := f.provider(t, func(o *gcp.Options) { o.Endpoint = big.URL }).Factory(connectors.Connection{ID: uuid.New(), Config: config(gcp.NewExternalID())})
	if err != nil {
		t.Fatal(err)
	}
	err = s.List(context.Background(), func(connectors.SecretInfo) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized response: %v", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     `<html>proxy error</html>`,
		"wrong shapes": `{"name": 42}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			s, err := newFake(t).provider(t, func(o *gcp.Options) { o.Endpoint = srv.URL }).Factory(connectors.Connection{ID: uuid.New(), Config: config(gcp.NewExternalID())})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.List(context.Background(), func(connectors.SecretInfo) error { return nil }); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPayloadIntegrityIsChecked(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	target := create(t, s, "crc-secret", "integrity")
	f.setTamperCRC(true)
	_, _, err := s.Reveal(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "crc32c") {
		t.Fatalf("corrupted payload accepted: %v", err)
	}
	f.setTamperCRC(false)
	if v, _, err := s.Reveal(context.Background(), target); err != nil {
		t.Fatal(err)
	} else if v.RevealString() != "integrity" {
		t.Fatal("wrong value")
	}
}

func TestValuesAreBinarySafeAndBounded(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	raw := []byte{0, 1, 2, 0xff, 0xfe, '\n', 0, 0x80}
	st, err := s.Stage(ctx, connectors.Target{Name: "bin-secret"}, uuid.New(), sensitive.New(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadStaged(ctx, st)
	if err != nil || !bytes.Equal(got.Reveal(), raw) {
		t.Fatalf("binary value changed: %v %v", got.Reveal(), err)
	}
	before := len(f.requestLog())
	huge := sensitive.New(bytes.Repeat([]byte("x"), 64*1024+1))
	if _, err := s.Stage(ctx, connectors.Target{Name: "huge-secret"}, uuid.New(), huge); err == nil {
		t.Fatal("a value over 64 KiB was accepted")
	}
	if _, err := s.Stage(ctx, connectors.Target{Name: "empty-secret"}, uuid.New(), sensitive.Value{}); err == nil {
		t.Fatal("an empty value was accepted")
	}
	for _, r := range f.requestLog()[before:] {
		if strings.HasPrefix(r, "POST") {
			t.Fatalf("an invalid value reached the provider: %s", r)
		}
	}
	max64k := sensitive.New(bytes.Repeat([]byte("y"), 64*1024))
	if _, err := s.Stage(ctx, connectors.Target{Name: "max-secret"}, uuid.New(), max64k); err != nil {
		t.Fatalf("a 64 KiB value was rejected: %v", err)
	}
}

// ---- errors ----

func TestStatusMapping(t *testing.T) {
	cases := []struct {
		http   int
		status string
		want   error
	}{
		{401, "UNAUTHENTICATED", connectors.ErrAccessDenied},
		{403, "PERMISSION_DENIED", connectors.ErrAccessDenied},
		{404, "NOT_FOUND", connectors.ErrNotFound},
		{409, "ALREADY_EXISTS", connectors.ErrConflict},
		{429, "RESOURCE_EXHAUSTED", connectors.ErrTransient},
		{500, "INTERNAL", connectors.ErrTransient},
		{503, "UNAVAILABLE", connectors.ErrTransient},
	}
	for _, c := range cases {
		t.Run(c.status, func(t *testing.T) {
			f := newFake(t)
			s, _ := f.newStore(t)
			target := create(t, s, "status-secret", "v")
			f.addFault(&fault{status: c.http, googleStatus: c.status, match: func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/status-secret")
			}})
			_, _, err := s.Reveal(context.Background(), target)
			if !errors.Is(err, c.want) {
				t.Fatalf("http %d: %v, want %v", c.http, err, c.want)
			}
		})
	}
	t.Run("other client errors are plain", func(t *testing.T) {
		f := newFake(t)
		s, _ := f.newStore(t)
		target := create(t, s, "status-secret", "v")
		f.addFault(&fault{status: 400, googleStatus: "INVALID_ARGUMENT", match: func(r *http.Request) bool {
			return strings.HasSuffix(r.URL.Path, "/secrets/status-secret")
		}})
		_, _, err := s.Reveal(context.Background(), target)
		if err == nil || errors.Is(err, connectors.ErrTransient) || errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("400 INVALID_ARGUMENT: %v", err)
		}
	})
	t.Run("dropped connection is transient", func(t *testing.T) {
		f := newFake(t)
		s, _ := f.newStore(t)
		target := create(t, s, "status-secret", "v")
		f.addFault(&fault{dropAfter: true, match: func(r *http.Request) bool {
			return strings.HasSuffix(r.URL.Path, "/secrets/status-secret")
		}})
		if _, _, err := s.Reveal(context.Background(), target); !errors.Is(err, connectors.ErrTransient) {
			t.Fatalf("dropped connection: %v", err)
		}
	})
	t.Run("cancelled context is transient", func(t *testing.T) {
		s, _ := newFake(t).newStore(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := s.Reveal(ctx, connectors.Target{ProviderRef: "projects/" + testProject + "/secrets/x"}); err == nil {
			t.Fatal("cancelled context ignored")
		}
	})
}

func TestErrorsNeverCarrySecretsOrProviderBodies(t *testing.T) {
	const canary = "CANARY-value-7c1e9"
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "leak-check", canary)
	_, st := stage(t, s, "leak-check", canary+"-next")

	// Every provider failure quotes the value and a body marker in its message.
	body := func(status string) string {
		return `{"error":{"status":"` + status + `","message":"` + canary + " " + providerBodyMarker + `"}}`
	}
	var errs []error
	for _, status := range []struct {
		code   int
		status string
	}{{500, "INTERNAL"}, {403, "PERMISSION_DENIED"}, {400, "INVALID_ARGUMENT"}, {404, "NOT_FOUND"}} {
		f.clearFaults()
		f.addFault(&fault{status: status.code, googleStatus: status.status, body: body(status.status), match: func(r *http.Request) bool { return true }})
		_, _, e1 := s.Reveal(ctx, target)
		_, e2 := s.Versions(ctx, target)
		_, e3 := s.ReadStaged(ctx, st)
		_, e4 := s.Promote(ctx, target, st, uuid.New())
		_, e5 := s.Delete(ctx, target, uuid.New())
		e6 := s.DiscardStaged(ctx, st)
		_, e7 := s.Stage(ctx, connectors.Target{Name: "leak-two"}, uuid.New(), sensitive.FromString(canary))
		e8 := s.List(ctx, func(connectors.SecretInfo) error { return nil })
		_, _, e9 := s.LookupOperation(ctx, connectors.Operation{Kind: "update", Target: target, Key: uuid.New()})
		errs = append(errs, e1, e2, e3, e4, e5, e6, e7, e8, e9)
	}
	n := 0
	for _, err := range errs {
		if err == nil {
			continue
		}
		n++
		if msg := err.Error(); strings.Contains(msg, canary) || strings.Contains(msg, providerBodyMarker) {
			t.Errorf("error leaks provider content: %v", err)
		}
	}
	if n < len(errs)/2 {
		t.Fatalf("only %d of %d calls failed; the fault did not apply", n, len(errs))
	}
	if strings.Contains(logs.String(), canary) {
		t.Error("a secret value reached the log")
	}
	// The Value type itself stays redacted.
	if strings.Contains(sensitive.FromString(canary).String(), canary) {
		t.Error("sensitive.Value prints its content")
	}
}

// ---- identity ----

func TestImpersonation(t *testing.T) {
	ctx := context.Background()
	t.Run("tokens are reused", func(t *testing.T) {
		f := newFake(t)
		s, _ := f.newStore(t)
		for i := range 5 {
			create(t, s, "reuse-"+string(rune('a'+i)), "v")
		}
		if n := f.iamCallCount(); n != 1 {
			t.Fatalf("%d impersonation calls for 5 operations, want 1", n)
		}
	})
	t.Run("no tokenCreator binding", func(t *testing.T) {
		f := newFake(t)
		f.seed(gcp.MarkerSecret, nil, nil, time.Now(), "secretmesh-x")
		cfg := config("secretmesh-x")
		cfg["service_account"] = "someone-else@test-project-123.iam.gserviceaccount.com"
		s, err := f.provider(t).Factory(connectors.Connection{ID: uuid.New(), Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		err = s.List(ctx, func(connectors.SecretInfo) error { return nil })
		if !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("impersonating an unbound service account: %v", err)
		}
		if strings.Contains(err.Error(), providerBodyMarker) {
			t.Errorf("IAM error body leaked: %v", err)
		}
		for _, r := range f.requestLog() {
			t.Errorf("Secret Manager was contacted without a token: %s", r)
		}
	})
	t.Run("SecretMesh's own token is rejected", func(t *testing.T) {
		f := newFake(t)
		s, _ := f.newStore(t, func(o *gcp.Options) { o.BaseTokenSource = staticToken("revoked") })
		if err := s.List(ctx, func(connectors.SecretInfo) error { return nil }); !errors.Is(err, connectors.ErrAccessDenied) {
			t.Fatalf("revoked base identity: %v", err)
		}
	})
	t.Run("base token goes only to the IAM host", func(t *testing.T) {
		f := newFake(t)
		s, _ := f.newStore(t)
		create(t, s, "token-scope", "v")
		f.mu.Lock()
		defer f.mu.Unlock()
		for tok := range f.tokens {
			if tok == baseToken {
				t.Fatal("the base token was used against Secret Manager")
			}
		}
	})
}

// ---- idempotency ----

func TestLostResponseDuringUpdateDoesNotDuplicate(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "lost-update", "v1")
	_, st := stage(t, s, "lost-update", "v2")
	key := uuid.New()

	f.addFault(&fault{dropAfter: true, times: 1, match: func(r *http.Request) bool {
		return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets/lost-update:addVersion")
	}})
	if _, err := s.Promote(ctx, target, st, key); !errors.Is(err, connectors.ErrTransient) {
		t.Fatalf("first attempt: %v, want a transient error", err)
	}
	// The version was added but never recorded: the lookup must not claim success.
	op := connectors.Operation{Kind: "update", Target: target, Staged: st, Key: key}
	if _, ok, err := s.LookupOperation(ctx, op); err != nil || ok {
		t.Fatalf("lookup before the bookkeeping finished: ok=%v err=%v", ok, err)
	}
	res, err := s.Promote(ctx, target, st, key)
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := f.secret("lost-update")
	if len(sec.versions) != 2 || res.VersionID != "2" {
		t.Fatalf("%d versions, result version %q; want exactly 2 versions and version 2", len(sec.versions), res.VersionID)
	}
	if _, ok, _ := s.LookupOperation(ctx, op); !ok {
		t.Fatal("lookup after the retry does not see the update")
	}
	// A third attempt changes nothing.
	if again, err := s.Promote(ctx, target, st, key); err != nil || again.VersionID != "2" {
		t.Fatalf("third attempt: %+v %v", again, err)
	}
	if len(sec.versions) != 2 {
		t.Fatalf("%d versions after a third attempt", len(sec.versions))
	}
}

func TestLostResponseDuringUpdateBeforeTheWrite(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "lost-before", "v1")
	_, st := stage(t, s, "lost-before", "v2")
	key := uuid.New()
	// The intent write fails: nothing was added, the retry adds exactly one version.
	f.addFault(&fault{status: 503, googleStatus: "UNAVAILABLE", times: 1, match: func(r *http.Request) bool {
		return r.Method == http.MethodPatch
	}})
	if _, err := s.Promote(ctx, target, st, key); !errors.Is(err, connectors.ErrTransient) {
		t.Fatalf("first attempt: %v", err)
	}
	if _, err := s.Promote(ctx, target, st, key); err != nil {
		t.Fatal(err)
	}
	if sec, _ := f.secret("lost-before"); len(sec.versions) != 2 {
		t.Fatalf("%d versions, want 2", len(sec.versions))
	}
}

func TestUpdateToTheSameValueAfterIntentDoesNotDuplicate(t *testing.T) {
	// Intent recorded, then the process died before adding. The staged value
	// equals the current one, so the recovery finds it "already there".
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "same-value", "same")
	_, st := stage(t, s, "same-value", "same")
	key := uuid.New()
	f.mu.Lock()
	f.secrets["same-value"].ann["secretmesh-intent-op"] = key.String()
	f.mu.Unlock()
	res, err := s.Promote(ctx, target, st, key)
	if err != nil || res.VersionID != "1" {
		t.Fatalf("%+v %v", res, err)
	}
	if sec, _ := f.secret("same-value"); len(sec.versions) != 1 {
		t.Fatalf("%d versions", len(sec.versions))
	}
}

func TestLostResponseDuringCreate(t *testing.T) {
	for name, match := range map[string]func(r *http.Request) bool{
		"secret created": func(r *http.Request) bool {
			return r.Method == http.MethodPost && r.URL.Query().Get("secretId") == "lost-create"
		},
		"first version added": func(r *http.Request) bool {
			return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets/lost-create:addVersion")
		},
		"bookkeeping written": func(r *http.Request) bool {
			return r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/secrets/lost-create")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			s, _ := f.newStore(t)
			ctx := context.Background()
			_, st := stage(t, s, "lost-create", "first")
			key := uuid.New()
			f.addFault(&fault{dropAfter: true, times: 1, match: match})
			if _, err := s.Promote(ctx, connectors.Target{Name: "lost-create"}, st, key); !errors.Is(err, connectors.ErrTransient) {
				t.Fatalf("first attempt: %v", err)
			}
			res, err := s.Promote(ctx, connectors.Target{Name: "lost-create"}, st, key)
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			sec, ok := f.secret("lost-create")
			if !ok || len(sec.versions) != 1 || res.VersionID != "1" {
				t.Fatalf("secret exists=%v versions=%d result=%+v; want one secret with one version", ok, len(sec.versions), res)
			}
			// Someone else's request for the same name still conflicts.
			_, other := stage(t, s, "lost-create", "intruder")
			if _, err := s.Promote(ctx, connectors.Target{Name: "lost-create"}, other, uuid.New()); !errors.Is(err, connectors.ErrConflict) {
				t.Fatalf("another request: %v, want ErrConflict", err)
			}
		})
	}
}

func TestStageRetryReusesTheShadowSecret(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	id := uuid.New()
	target := connectors.Target{Name: "stage-retry"}
	// The shadow secret is created, the version is added, the answer is lost.
	f.addFault(&fault{dropAfter: true, times: 1, match: func(r *http.Request) bool {
		return strings.HasSuffix(r.URL.Path, ":addVersion")
	}})
	if _, err := s.Stage(ctx, target, id, sensitive.FromString("staged")); err == nil {
		t.Fatal("first Stage should fail")
	}
	// The failed attempt cleans up after itself (best effort), so a retry starts clean.
	st, err := s.Stage(ctx, target, id, sensitive.FromString("staged"))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.ReadStaged(ctx, st); err != nil || v.RevealString() != "staged" {
		t.Fatalf("%v", err)
	}
	// Retrying after success is a no-op that returns the same reference.
	again, err := s.Stage(ctx, target, id, sensitive.FromString("staged"))
	if err != nil || again != st {
		t.Fatalf("%+v vs %+v: %v", again, st, err)
	}
	shadow, _ := f.secret(gcp.StagingPrefix + id.String())
	if len(shadow.versions) != 1 {
		t.Fatalf("%d versions in the shadow secret", len(shadow.versions))
	}
}

func TestStaleEtagIsRetried(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "etag-secret", "v1")
	_, st := stage(t, s, "etag-secret", "v2")
	f.setStaleNext(2) // two concurrent writers in a row
	res, err := s.Promote(ctx, target, st, uuid.New())
	if err != nil || res.VersionID != "2" {
		t.Fatalf("%+v %v", res, err)
	}
	patches := 0
	for _, r := range f.requestLog() {
		if strings.HasPrefix(r, "PATCH") {
			patches++
		}
	}
	if patches < 4 {
		t.Fatalf("only %d PATCH requests; the stale etag was not retried", patches)
	}
	// Persistent contention gives up with a transient error instead of looping.
	f.setStaleNext(1000)
	_, st2 := stage(t, s, "etag-secret", "v3")
	if _, err := s.Promote(ctx, target, st2, uuid.New()); !errors.Is(err, connectors.ErrTransient) {
		t.Fatalf("persistent contention: %v", err)
	}
}

// ---- soft delete ----

func TestDeleteIsReversibleSoftDelete(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	ctx := context.Background()
	target := create(t, s, "doomed", "v1")
	_, st := stage(t, s, "doomed", "v2")
	if _, err := s.Promote(ctx, target, st, uuid.New()); err != nil {
		t.Fatal(err)
	}
	key := uuid.New()
	if _, err := s.Delete(ctx, target, key); err != nil {
		t.Fatal(err)
	}
	sec, ok := f.secret("doomed")
	if !ok {
		t.Fatal("the secret was destroyed; deletes must be reversible")
	}
	if sec.labels["secretmesh-deleted"] != "true" || sec.ann["secretmesh-deleted-at"] == "" {
		t.Errorf("not marked deleted: %v %v", sec.labels, sec.ann)
	}
	for i, st := range f.versionStates("doomed") {
		if st != "DISABLED" {
			t.Errorf("version %d is %s, want DISABLED (never DESTROYED)", i+1, st)
		}
	}
	// Hidden everywhere.
	if _, _, err := s.Reveal(ctx, target); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Reveal: %v", err)
	}
	if _, err := s.Versions(ctx, target); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Versions: %v", err)
	}
	if _, err := s.Stage(ctx, target, uuid.New(), sensitive.FromString("zombie")); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Stage on a deleted secret: %v", err)
	}
	if _, err := s.Promote(ctx, target, st, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Promote on a deleted secret: %v", err)
	}
	if err := s.List(ctx, func(i connectors.SecretInfo) error {
		if i.Name == "doomed" {
			t.Error("a deleted secret is listed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The name stays taken until an administrator purges it.
	_, again := stage(t, s, "doomed", "reborn")
	if _, err := s.Promote(ctx, connectors.Target{Name: "doomed"}, again, uuid.New()); !errors.Is(err, connectors.ErrConflict) {
		t.Errorf("create over a deleted secret: %v, want ErrConflict", err)
	}
	// A different request cannot delete it again; the same one may retry.
	if _, err := s.Delete(ctx, target, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("second delete by another request: %v", err)
	}
	if _, err := s.Delete(ctx, target, key); err != nil {
		t.Errorf("retried delete: %v", err)
	}
	// An interrupted delete is completed by the retry.
	f.mu.Lock()
	f.secrets["doomed"].versions[0].state = "ENABLED"
	f.mu.Unlock()
	if _, err := s.Delete(ctx, target, key); err != nil {
		t.Fatal(err)
	}
	for _, st := range f.versionStates("doomed") {
		if st != "DISABLED" {
			t.Errorf("leftover enabled version after the retry: %v", f.versionStates("doomed"))
		}
	}
	if _, ok, _ := s.LookupOperation(ctx, connectors.Operation{Kind: "delete", Target: target, Key: key}); !ok {
		t.Error("lookup does not see the delete")
	}
	if _, err := s.Delete(ctx, connectors.Target{ProviderRef: "projects/" + testProject + "/secrets/never-existed"}, uuid.New()); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("delete of a missing secret: %v", err)
	}
}

// ---- discovery ----

func TestListMapsLabelsAndSkipsInternalSecrets(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	now := time.Now()
	f.seed("app-one", map[string]string{"secretmesh-environment": "prod", "secretmesh-classification": "restricted", "team": "pay"}, nil, now, "v1", "v2")
	f.seed("app-two", map[string]string{"secretmesh-environment": "staging"}, nil, now, "v1")
	f.seed("app-empty", nil, nil, now) // no versions yet
	f.seed("app-four", nil, nil, now, "v1")
	f.seed("app-five", nil, nil, now, "v1")
	f.seed("app-gone", map[string]string{"secretmesh-deleted": "true"}, nil, now, "v1")
	f.seed(gcp.StagingPrefix+uuid.NewString(), map[string]string{"secretmesh-staging": "true"}, nil, now, "staged")
	f.seed("labelled-staging", map[string]string{"secretmesh-staging": "true"}, nil, now, "staged")
	f.mu.Lock()
	f.secrets["app-four"].versions[0].state = "DISABLED"
	f.mu.Unlock()

	got := map[string]connectors.SecretInfo{}
	if err := s.List(context.Background(), func(i connectors.SecretInfo) error { got[i.Name] = i; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("listed %d secrets, want 5 (marker, staging and deleted excluded): %v", len(got), keys(got))
	}
	one := got["app-one"]
	if one.Tags["secretmesh:environment"] != "prod" || one.Tags["secretmesh:classification"] != "restricted" || one.Tags["team"] != "pay" {
		t.Errorf("tags: %v", one.Tags)
	}
	if one.CurrentVersion != "2" || one.ProviderRef != "projects/"+testProject+"/secrets/app-one" || one.LastChanged == nil {
		t.Errorf("info: %+v", one)
	}
	if got["app-empty"].CurrentVersion != "" || got["app-four"].CurrentVersion != "" {
		t.Errorf("secrets without an enabled version must have no current version: %+v %+v", got["app-empty"], got["app-four"])
	}
	for _, r := range f.requestLog() {
		if strings.Contains(r, ":access") && !strings.Contains(r, gcp.MarkerSecret) {
			t.Errorf("discovery read a secret value: %s", r)
		}
	}
	// A failure while describing one secret aborts the sync.
	f.addFault(&fault{status: 500, googleStatus: "INTERNAL", match: func(r *http.Request) bool {
		return strings.HasSuffix(r.URL.Path, "/app-two/versions/latest")
	}})
	if err := s.List(context.Background(), func(connectors.SecretInfo) error { return nil }); !errors.Is(err, connectors.ErrTransient) {
		t.Errorf("List: %v", err)
	}
	// And so does the callback.
	f.clearFaults()
	stop := errors.New("stop")
	if err := s.List(context.Background(), func(connectors.SecretInfo) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("List ignored the callback error: %v", err)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestVersionsReportStates(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	f.seed("states", nil, nil, time.Now(), "a", "b", "c", "d", "e")
	f.mu.Lock()
	v := f.secrets["states"].versions
	v[0].state, v[1].state, v[4].state = "DISABLED", "DESTROYED", "DISABLED"
	f.mu.Unlock()
	vs, err := s.Versions(context.Background(), connectors.Target{ProviderRef: "projects/" + testProject + "/secrets/states"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 5 || vs[0].ID != "5" || vs[4].ID != "1" {
		t.Fatalf("order: %+v", vs)
	}
	want := map[string]string{"1": "disabled", "2": "destroyed", "3": "", "4": "current", "5": "disabled"}
	for _, ver := range vs {
		got := ""
		if len(ver.Stages) > 0 {
			got = ver.Stages[0]
		}
		if got != want[ver.ID] {
			t.Errorf("version %s stage %q, want %q", ver.ID, got, want[ver.ID])
		}
	}
	// Reading a disabled newest version is not a value.
	f.mu.Lock()
	v[4].state = "DISABLED"
	f.mu.Unlock()
	if _, _, err := s.Reveal(context.Background(), connectors.Target{ProviderRef: "projects/" + testProject + "/secrets/states"}); !errors.Is(err, connectors.ErrNotFound) {
		t.Errorf("Reveal with a disabled newest version: %v", err)
	}
}

// ---- sweeper ----

func TestSweeperOnlyTouchesLabelledStagingSecrets(t *testing.T) {
	f := newFake(t)
	s, _ := f.newStore(t)
	sw := s.(connectors.StagingSweeper)
	old := time.Now().Add(-3 * time.Hour)
	label := map[string]string{"secretmesh-staging": "true"}

	orphan := gcp.StagingPrefix + uuid.NewString()
	live := uuid.New()
	liveName := gcp.StagingPrefix + live.String()
	unlabelled := gcp.StagingPrefix + uuid.NewString()
	notUUID := gcp.StagingPrefix + "not-a-uuid"
	noPrefix := "customer-data"
	young := gcp.StagingPrefix + uuid.NewString()
	f.seed(orphan, label, nil, old, "x")
	f.seed(liveName, label, nil, old, "x")
	f.seed(unlabelled, nil, nil, old, "customer data that merely looks like staging")
	f.seed(notUUID, label, nil, old, "x")
	f.seed(noPrefix, label, nil, old, "customer data")
	f.seed(young, label, nil, time.Now(), "x")

	isLive := func(id uuid.UUID) (bool, error) { return id == live, nil }
	n, err := sw.SweepStaging(context.Background(), time.Now().Add(-time.Hour), isLive)
	if err != nil || n != 1 {
		t.Fatalf("removed %d (err %v), want 1", n, err)
	}
	for name, wantKept := range map[string]bool{orphan: false, liveName: true, unlabelled: true, notUUID: true, noPrefix: true, young: true, gcp.MarkerSecret: true} {
		if _, ok := f.secret(name); ok != wantKept {
			t.Errorf("%s: present=%v, want %v", name, ok, wantKept)
		}
	}
	// A failing liveness check aborts instead of guessing.
	boom := errors.New("db down")
	if _, err := sw.SweepStaging(context.Background(), time.Now().Add(time.Minute), func(uuid.UUID) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Errorf("sweep ignored the liveness error: %v", err)
	}
	if _, ok := f.secret(young); !ok {
		t.Error("a secret was removed although liveness could not be determined")
	}
}
