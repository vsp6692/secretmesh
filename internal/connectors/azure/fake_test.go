// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package azure_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/azure"
)

const (
	vaultURL  = "https://sm-test.vault.azure.net"
	tenantID  = "00000000-0000-0000-0000-000000000001"
	testToken = "test-token"
	pageSize  = 2
)

type staticCred struct{}

func (staticCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: testToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeVersion struct {
	id      string
	value   string
	ctype   string
	tags    map[string]string
	created int64
	enabled bool
}

type fakeSecret struct {
	versions []*fakeVersion
}

// kv is an in-memory Key Vault data plane with the semantics SecretMesh
// relies on: versions with server-generated IDs and per-version tags,
// soft delete with purge, paging, and bearer authentication.
type kv struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	secrets  map[string]*fakeSecret
	deleted  map[string]*fakeSecret
	requests []string
	clock    int64

	purgeProtection bool
	// failures: path substring -> status to return (once per entry when once).
	fail      map[string]int
	dropNext  bool   // apply the next PUT, then cut the connection
	redirect  string // GET /secrets/<name> (non-marker) redirects here
	nextHost  string // nextLink points at this base URL instead of the fake
	bigBody   bool
	badCode   string // error body with a message the client must not echo
	authCalls []string
}

func newKV(t *testing.T) *kv {
	k := &kv{t: t, secrets: map[string]*fakeSecret{}, deleted: map[string]*fakeSecret{}, fail: map[string]int{}, clock: time.Now().Unix()}
	k.srv = httptest.NewServer(http.HandlerFunc(k.serve))
	t.Cleanup(k.srv.Close)
	return k
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// seed stores a secret directly, bypassing the API.
func (k *kv) seed(name, value string, tags map[string]string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.putLocked(name, value, "", tags)
}

func (k *kv) putLocked(name, value, ctype string, tags map[string]string) *fakeVersion {
	s := k.secrets[name]
	if s == nil {
		s = &fakeSecret{}
		k.secrets[name] = s
	}
	k.clock++
	v := &fakeVersion{id: randHex(), value: value, ctype: ctype, tags: tags, created: k.clock, enabled: true}
	s.versions = append(s.versions, v)
	return v
}

func (k *kv) requestLog() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.requests...)
}

func (k *kv) versionCount(name string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s := k.secrets[name]; s != nil {
		return len(s.versions)
	}
	return 0
}

func (k *kv) has(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.secrets[name]
	return ok
}

func (k *kv) isSoftDeleted(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.deleted[name]
	return ok
}

func (k *kv) disableLatest(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.secrets[name]
	s.versions[len(s.versions)-1].enabled = false
}

func (k *kv) setFail(substr string, status int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fail[substr] = status
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-ms-request-id", "fake-"+randHex()[:8])
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func kvError(w http.ResponseWriter, status int, code, inner string) {
	e := map[string]any{"code": code, "message": "message that must never reach callers: " + code}
	if inner != "" {
		e["innererror"] = map[string]string{"code": inner}
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func (k *kv) item(name string, v *fakeVersion, withVersion, withValue bool) map[string]any {
	id := vaultURL + "/secrets/" + name
	if withVersion {
		id += "/" + v.id
	}
	attrs := map[string]any{"enabled": v.enabled, "created": v.created, "updated": v.created}
	m := map[string]any{"id": id, "attributes": attrs}
	if len(v.tags) > 0 {
		m["tags"] = v.tags
	}
	if v.ctype != "" {
		m["contentType"] = v.ctype
	}
	if withValue {
		m["value"] = v.value
	}
	return m
}

func latest(s *fakeSecret) *fakeVersion { return s.versions[len(s.versions)-1] }

func (k *kv) serve(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.requests = append(k.requests, r.Method+" "+r.URL.Path)
	k.authCalls = append(k.authCalls, r.Header.Get("Authorization"))

	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/`+tenantID+`", resource="https://vault.azure.net"`)
		kvError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	if r.URL.Query().Get("api-version") != "7.5" {
		kvError(w, http.StatusBadRequest, "BadParameter", "")
		return
	}
	for sub, status := range k.fail {
		if strings.Contains(r.URL.Path, sub) {
			kvError(w, status, "Injected", "")
			return
		}
	}
	if k.badCode != "" && !strings.Contains(r.URL.Path, azure.MarkerName) {
		kvError(w, http.StatusBadRequest, k.badCode, "")
		return
	}
	if k.bigBody && !strings.Contains(r.URL.Path, azure.MarkerName) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("A", 3<<20) + `"}`))
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case parts[0] == "secrets" && len(parts) == 1 && r.Method == http.MethodGet:
		k.list(w, r, "", "/secrets")
	case parts[0] == "secrets" && len(parts) == 3 && parts[2] == "versions" && r.Method == http.MethodGet:
		k.list(w, r, parts[1], r.URL.Path)
	case parts[0] == "secrets" && len(parts) == 2:
		k.secret(w, r, parts[1])
	case parts[0] == "secrets" && len(parts) == 3 && r.Method == http.MethodGet:
		s := k.secrets[parts[1]]
		if s != nil {
			for _, v := range s.versions {
				if v.id == parts[2] {
					k.respondVersion(w, parts[1], v)
					return
				}
			}
		}
		kvError(w, http.StatusNotFound, "SecretNotFound", "")
	case parts[0] == "deletedsecrets" && len(parts) == 2:
		k.deletedSecret(w, r, parts[1])
	default:
		kvError(w, http.StatusNotFound, "NotFound", "")
	}
}

func (k *kv) respondVersion(w http.ResponseWriter, name string, v *fakeVersion) {
	if !v.enabled {
		kvError(w, http.StatusForbidden, "Forbidden", "SecretDisabled")
		return
	}
	writeJSON(w, http.StatusOK, k.item(name, v, true, true))
}

func (k *kv) secret(w http.ResponseWriter, r *http.Request, name string) {
	switch r.Method {
	case http.MethodGet:
		if k.redirect != "" && name != azure.MarkerName {
			http.Redirect(w, r, k.redirect+r.URL.Path, http.StatusFound)
			return
		}
		s := k.secrets[name]
		if s == nil {
			kvError(w, http.StatusNotFound, "SecretNotFound", "")
			return
		}
		k.respondVersion(w, name, latest(s))
	case http.MethodPut:
		if _, ok := k.deleted[name]; ok {
			kvError(w, http.StatusConflict, "Conflict", "ObjectIsDeletedButRecoverable")
			return
		}
		var in struct {
			Value       string            `json:"value"`
			ContentType string            `json:"contentType"`
			Tags        map[string]string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			kvError(w, http.StatusBadRequest, "BadParameter", "")
			return
		}
		v := k.putLocked(name, in.Value, in.ContentType, in.Tags)
		if k.dropNext {
			k.dropNext = false
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		writeJSON(w, http.StatusOK, k.item(name, v, true, true))
	case http.MethodDelete:
		s := k.secrets[name]
		if s == nil {
			kvError(w, http.StatusNotFound, "SecretNotFound", "")
			return
		}
		delete(k.secrets, name)
		k.deleted[name] = s
		writeJSON(w, http.StatusOK, map[string]any{"id": vaultURL + "/secrets/" + name, "recoveryId": vaultURL + "/deletedsecrets/" + name})
	default:
		kvError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "")
	}
}

func (k *kv) deletedSecret(w http.ResponseWriter, r *http.Request, name string) {
	_, ok := k.deleted[name]
	if !ok {
		kvError(w, http.StatusNotFound, "SecretNotFound", "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"id": vaultURL + "/secrets/" + name})
	case http.MethodDelete: // purge
		if k.purgeProtection {
			kvError(w, http.StatusForbidden, "Forbidden", "ForbiddenByPolicy")
			return
		}
		delete(k.deleted, name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// list serves /secrets and /secrets/<name>/versions with real paging.
func (k *kv) list(w http.ResponseWriter, r *http.Request, name, path string) {
	type entry struct {
		name string
		v    *fakeVersion
	}
	var all []entry
	if name == "" {
		names := make([]string, 0, len(k.secrets))
		for n := range k.secrets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			all = append(all, entry{n, latest(k.secrets[n])})
		}
	} else {
		s := k.secrets[name]
		if s == nil {
			kvError(w, http.StatusNotFound, "SecretNotFound", "")
			return
		}
		for _, v := range s.versions {
			all = append(all, entry{name, v})
		}
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("skiptoken"))
	end := min(start+pageSize, len(all))
	items := []map[string]any{}
	for _, e := range all[start:end] {
		items = append(items, k.item(e.name, e.v, name != "", false))
	}
	body := map[string]any{"value": items}
	if end < len(all) {
		base := "http://" + r.Host
		if k.nextHost != "" {
			base = k.nextHost
		}
		body["nextLink"] = fmt.Sprintf("%s%s?api-version=7.5&skiptoken=%d", base, path, end)
	}
	writeJSON(w, http.StatusOK, body)
}

// fixture is a store connected to a fresh fake whose marker secret matches.
type fixture struct {
	kv    *kv
	store connectors.SecretStore
	ext   string
	now   *time.Time
}

// newFixture returns a store whose vault holds the correct marker (with the
// trailing newline a CLI would add, which is tolerated).
func newFixture(t *testing.T) *fixture { return newFixtureMarker(t, "ok") }

// newFixtureMarker builds a store and a vault whose marker is "ok", "missing"
// or "wrong".
func newFixtureMarker(t *testing.T, marker string) *fixture {
	t.Helper()
	k := newKV(t)
	ext := azure.NewExternalID()
	switch marker {
	case "ok":
		k.seed(azure.MarkerName, ext+"\r\n", nil)
	case "wrong":
		k.seed(azure.MarkerName, azure.NewExternalID(), nil)
	}
	now := time.Now()
	p, err := azure.New(context.Background(), azure.Options{Endpoint: k.srv.URL, Credential: staticCred{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Factory(connectors.Connection{ID: uuid.New(), Provider: azure.ProviderName,
		Config: map[string]string{"vault_url": vaultURL, "tenant_id": tenantID, "external_id": ext}})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{kv: k, store: s, ext: ext, now: &now}
}
