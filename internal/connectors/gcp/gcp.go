// Package gcp connects SecretMesh to Google Cloud Secret Manager.
//
// SecretMesh authenticates as its own workload identity (Application Default
// Credentials: GKE Workload Identity, Workload Identity Federation or an
// attached service account; key files are refused) and impersonates a
// customer-owned service account for each connection, holding only 15-minute
// access tokens. Because Google has no ExternalId, the project must also hold
// a secret "secretmesh-external-id" whose value is the connection's
// SecretMesh-generated external ID: a tenant cannot point a connection at
// another tenant's project (confused deputy).
//
// Pending values are staged in the customer's project (ADR-0003) as a shadow
// secret "smstaging-<request>" for both creates and updates. Google gives
// versions no labels and no caller-chosen IDs, so idempotency is recorded as
// annotations on the target secret:
//
//   - secretmesh-intent-op=<key> is written before a version is added;
//   - secretmesh-applied-op=<key> and secretmesh-applied-version=<n> after.
//
// A retry with the same key returns the recorded version when applied is
// set. When only intent is set, the latest version is compared with the staged
// value (constant time): if equal the version exists and only the bookkeeping
// is finished, otherwise the version is added. One key therefore never yields
// two versions. A create is the same, with the intent written when the secret
// is created, so a 409 on a secret that carries this key's intent is a retry.
//
// Secret Manager deletes are permanent, so a SecretMesh delete is a reversible
// soft delete: the secret is labelled secretmesh-deleted=true and all its
// versions are disabled (never destroyed). Deleted secrets are hidden and
// block a create of the same name until an administrator purges them.
package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

const (
	ProviderName = "gcp"

	// MarkerSecret holds the connection's external ID (see package comment).
	MarkerSecret = "secretmesh-external-id" //nolint:gosec // a secret name, not a credential
	// StagingPrefix names shadow secrets.
	StagingPrefix = "smstaging-"

	scope            = "https://www.googleapis.com/auth/cloud-platform"
	defaultSMBase    = "https://secretmanager.googleapis.com"
	defaultIAMBase   = "https://iamcredentials.googleapis.com"
	tokenLifetime    = "900s"
	tokenEarlyExpiry = 2 * time.Minute
	markerRecheck    = 15 * time.Minute
	maxPayload       = 64 * 1024
	refShadow        = "shadow:"

	lblStaging = "secretmesh-staging"
	lblRequest = "secretmesh-request"
	lblManaged = "secretmesh-managed"
	lblDeleted = "secretmesh-deleted"
	lblEnv     = "secretmesh-environment"
	lblClass   = "secretmesh-classification"

	annCreated        = "secretmesh-created"
	annIntent         = "secretmesh-intent-op"
	annApplied        = "secretmesh-applied-op"
	annAppliedVersion = "secretmesh-applied-version"
	annDeletedAt      = "secretmesh-deleted-at"
	annDeletedOp      = "secretmesh-deleted-op"

	// Tag keys discovery reads (internal/inventory). GCP labels cannot
	// contain ':', so they come from the lblEnv and lblClass labels.
	tagEnv   = "secretmesh:environment"
	tagClass = "secretmesh:classification"
)

var (
	projectRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	saRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	idRE       = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,255}$`)
	verRE      = regexp.MustCompile(`^(latest|[1-9][0-9]{0,17})$`)
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
)

// NewExternalID returns a random ExternalId for a new connection. SecretMesh
// generates it so tenants cannot choose one that another tenant knows.
func NewExternalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "secretmesh-" + hex.EncodeToString(b)
}

// ValidateConfig checks a connection's settings. Only project_id,
// service_account and the generated external_id are accepted: never key
// files, tokens or endpoints.
func ValidateConfig(c map[string]string) error {
	for k := range c {
		if k != "project_id" && k != "service_account" && k != "external_id" {
			return fmt.Errorf("unknown setting %q (allowed: project_id, service_account)", k)
		}
	}
	if !projectRE.MatchString(c["project_id"]) {
		return errors.New("project_id must be a Google Cloud project ID such as my-project-123")
	}
	if !saRE.MatchString(c["service_account"]) {
		return errors.New("service_account must be a service account email such as secretmesh@my-project-123.iam.gserviceaccount.com")
	}
	if !strings.HasPrefix(c["external_id"], "secretmesh-") {
		return errors.New("external_id is generated by SecretMesh")
	}
	return nil
}

// Options are process-wide settings. The zero value is the production
// configuration; the rest exists for tests and local emulators.
type Options struct {
	// Endpoint overrides the Secret Manager base URL (emulators only).
	Endpoint string
	// IAMEndpoint overrides the IAM Credentials base URL (emulators only).
	IAMEndpoint string
	// BaseTokenSource replaces Application Default Credentials.
	BaseTokenSource oauth2.TokenSource
	// AllowServiceAccountKeys accepts an ADC service account key file.
	// Development only: keys are long-lived credentials.
	AllowServiceAccountKeys bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Provider builds per-connection stores from SecretMesh's own Google identity.
type Provider struct {
	sm, iam *client
	base    oauth2.TokenSource
	now     func() time.Time

	mu     sync.Mutex
	stores map[string]*store
}

// New loads SecretMesh's base Google identity.
func New(ctx context.Context, o Options) (*Provider, error) {
	smBase, iamBase := defaultSMBase, defaultIAMBase
	if o.Endpoint != "" {
		smBase = o.Endpoint
	}
	if o.IAMEndpoint != "" {
		iamBase = o.IAMEndpoint
	}
	smURL, smHost, err := parseEndpoint(smBase)
	if err != nil {
		return nil, err
	}
	iamURL, iamHost, err := parseEndpoint(iamBase)
	if err != nil {
		return nil, err
	}
	if (o.Endpoint == "" && !strings.HasPrefix(smURL, "https://")) || (o.IAMEndpoint == "" && !strings.HasPrefix(iamURL, "https://")) {
		return nil, errors.New("gcp: Google APIs are only reached over https")
	}
	base := o.BaseTokenSource
	if base == nil {
		creds, err := google.FindDefaultCredentials(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("gcp application default credentials: %w", err)
		}
		if err := checkCredentialType(creds.JSON, o.AllowServiceAccountKeys); err != nil {
			return nil, err
		}
		base = creds.TokenSource
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	hc := newHTTPClient()
	return &Provider{
		sm:     &client{http: hc, base: smURL, host: smHost},
		iam:    &client{http: hc, base: iamURL, host: iamHost, ts: base},
		base:   base,
		now:    now,
		stores: map[string]*store{},
	}, nil
}

// checkCredentialType refuses long-lived key files as SecretMesh's identity.
func checkCredentialType(adcJSON []byte, allowKeys bool) error {
	if len(adcJSON) == 0 {
		return nil // metadata server: an attached service account
	}
	var c struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(adcJSON, &c) == nil && c.Type == "service_account" && !allowKeys {
		return errors.New("gcp: application default credentials are a service account key file; use Workload Identity (GKE or Federation) or an attached service account instead")
	}
	return nil
}

func (p *Provider) Factory(c connectors.Connection) (connectors.SecretStore, error) {
	if err := ValidateConfig(c.Config); err != nil {
		return nil, fmt.Errorf("gcp connection %s: %w", c.ID, err)
	}
	key := c.ID.String() + "|" + c.Config["project_id"] + "|" + c.Config["service_account"] + "|" + c.Config["external_id"]
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.stores[key]; ok {
		return s, nil
	}
	ts := oauth2.ReuseTokenSourceWithExpiry(nil, p.impersonate(c.Config["service_account"]), tokenEarlyExpiry)
	s := &store{
		c:          &client{http: p.sm.http, base: p.sm.base, host: p.sm.host, ts: ts},
		project:    c.Config["project_id"],
		externalID: c.Config["external_id"],
		now:        p.now,
	}
	p.stores[key] = s
	return s, nil
}

type tokenFunc func() (*oauth2.Token, error)

func (f tokenFunc) Token() (*oauth2.Token, error) { return f() }

// impersonate mints short-lived access tokens for the customer's service
// account (IAM Credentials generateAccessToken), authorized by SecretMesh's
// own identity.
func (p *Provider) impersonate(sa string) oauth2.TokenSource {
	return tokenFunc(func() (*oauth2.Token, error) {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		req := struct {
			Scope    []string `json:"scope"`
			Lifetime string   `json:"lifetime"`
		}{[]string{scope}, tokenLifetime}
		var resp struct {
			AccessToken string `json:"accessToken"`
			ExpireTime  string `json:"expireTime"`
		}
		if err := p.iam.do(ctx, http.MethodPost, "/v1/projects/-/serviceAccounts/"+sa+":generateAccessToken", nil, req, &resp); err != nil {
			return nil, fmt.Errorf("impersonating the connection's service account: %w", err)
		}
		exp, err := time.Parse(time.RFC3339, resp.ExpireTime)
		if err != nil || resp.AccessToken == "" {
			return nil, errors.New("gcp: malformed impersonation response")
		}
		return &oauth2.Token{AccessToken: resp.AccessToken, Expiry: exp}, nil
	})
}

type store struct {
	c          *client
	project    string
	externalID string
	now        func() time.Time

	mu         sync.Mutex
	verifiedAt time.Time
}

func (s *store) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		SecretCreate: true, SecretUpdate: true, SecretDelete: true, SecretReveal: true, Discovery: true,
		Versioning: true, SoftDelete: true, Tags: true,
		UpdateStaging: "shadow_secret", CreateStaging: "shadow_secret",
	}
}

// ---- wire types ----

type secretResource struct {
	Name        string            `json:"name,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Etag        string            `json:"etag,omitempty"`
	Replication *replication      `json:"replication,omitempty"`
}

type replication struct {
	Automatic *struct{} `json:"automatic,omitempty"`
}

type versionResource struct {
	Name       string `json:"name"`
	CreateTime string `json:"createTime"`
	State      string `json:"state"`
}

// int64Str is a proto3 int64: a JSON string on the wire, tolerated as a number.
type int64Str int64

func (i int64Str) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatInt(int64(i), 10) + `"`), nil
}

func (i *int64Str) UnmarshalJSON(b []byte) error {
	n, err := strconv.ParseInt(strings.Trim(string(b), `"`), 10, 64)
	*i = int64Str(n)
	return err
}

type payload struct {
	Data       string    `json:"data"`
	DataCrc32c *int64Str `json:"dataCrc32c,omitempty"`
}

func crcOf(b []byte) int64Str { return int64Str(crc32.Checksum(b, castagnoli)) }

// ---- names ----

func reserved(id string) bool { return id == MarkerSecret || strings.HasPrefix(id, StagingPrefix) }

func (s *store) resource(id string) string { return "projects/" + s.project + "/secrets/" + id }

func checkID(id string) error {
	if !idRE.MatchString(id) {
		return errors.New("gcp: secret names may only contain letters, digits, '-' and '_' (at most 255)")
	}
	if reserved(id) {
		return fmt.Errorf("gcp: the name %q is reserved by SecretMesh", id)
	}
	return nil
}

// parseRef returns the secret ID of a reference inside this connection's
// project. References to other projects are refused outright.
func (s *store) parseRef(ref string) (string, error) {
	id, ok := strings.CutPrefix(ref, s.resource(""))
	if !ok || !idRE.MatchString(id) {
		return "", errors.New("gcp: reference is not a secret in this connection's project")
	}
	return id, nil
}

// targetID resolves a user-visible secret reference (never a reserved one).
func (s *store) targetID(ref string) (string, error) {
	id, err := s.parseRef(ref)
	if err != nil {
		return "", err
	}
	if reserved(id) {
		return "", fmt.Errorf("%w: reserved secret", connectors.ErrNotFound)
	}
	return id, nil
}

func (s *store) parseStaged(ref string) (string, error) {
	r, ok := strings.CutPrefix(ref, refShadow)
	if !ok {
		return "", errors.New("gcp: unrecognized staging reference")
	}
	id, err := s.parseRef(r)
	if err != nil {
		return "", err
	}
	if rest, ok := strings.CutPrefix(id, StagingPrefix); !ok || uuid.Validate(rest) != nil {
		return "", errors.New("gcp: staging reference is not a SecretMesh staging secret")
	}
	return id, nil
}

// ---- API calls ----

func (s *store) getSecret(ctx context.Context, id string) (*secretResource, error) {
	var out secretResource
	if err := s.c.do(ctx, http.MethodGet, "/v1/"+s.resource(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *store) createSecret(ctx context.Context, id string, labels, annotations map[string]string) (*secretResource, error) {
	body := secretResource{Labels: labels, Annotations: annotations, Replication: &replication{Automatic: &struct{}{}}}
	var out secretResource
	err := s.c.do(ctx, http.MethodPost, "/v1/projects/"+s.project+"/secrets", url.Values{"secretId": {id}}, body, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *store) deleteSecret(ctx context.Context, id string) error {
	return s.c.do(ctx, http.MethodDelete, "/v1/"+s.resource(id), nil, nil, nil)
}

// addVersion stores value as a new version and returns its number.
func (s *store) addVersion(ctx context.Context, id string, value []byte) (string, error) {
	if len(value) > maxPayload {
		return "", errors.New("gcp: the value exceeds Secret Manager's 64 KiB limit")
	}
	crc := crcOf(value)
	body := struct {
		Payload payload `json:"payload"`
	}{payload{Data: base64.StdEncoding.EncodeToString(value), DataCrc32c: &crc}}
	var out versionResource
	if err := s.c.do(ctx, http.MethodPost, "/v1/"+s.resource(id)+":addVersion", nil, body, &out); err != nil {
		return "", err
	}
	return s.versionNumber(id, out.Name)
}

// versionNumber extracts <n> from projects/<p>/secrets/<id>/versions/<n>.
func (s *store) versionNumber(id, name string) (string, error) {
	n, ok := strings.CutPrefix(name, s.resource(id)+"/versions/")
	if !ok || !verRE.MatchString(n) || n == "latest" {
		return "", errors.New("gcp: unexpected version name in response")
	}
	return n, nil
}

// access reads one version (a number or "latest") and verifies its checksum.
func (s *store) access(ctx context.Context, id, version string) (sensitive.Value, string, error) {
	if !verRE.MatchString(version) {
		return sensitive.Value{}, "", errors.New("gcp: invalid version")
	}
	var out struct {
		Name    string  `json:"name"`
		Payload payload `json:"payload"`
	}
	if err := s.c.do(ctx, http.MethodGet, "/v1/"+s.resource(id)+"/versions/"+version+":access", nil, nil, &out); err != nil {
		if hasStatus(err, "FAILED_PRECONDITION") {
			return sensitive.Value{}, "", fmt.Errorf("%w: version is not enabled", connectors.ErrNotFound)
		}
		return sensitive.Value{}, "", err
	}
	data, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return sensitive.Value{}, "", errors.New("gcp: malformed payload")
	}
	if out.Payload.DataCrc32c != nil && *out.Payload.DataCrc32c != crcOf(data) {
		clear(data)
		return sensitive.Value{}, "", errors.New("gcp: payload integrity check failed (crc32c)")
	}
	num, err := s.versionNumber(id, out.Name)
	if err != nil {
		clear(data)
		return sensitive.Value{}, "", err
	}
	v := sensitive.New(data)
	clear(data)
	return v, num, nil
}

func (s *store) listVersions(ctx context.Context, id string) ([]versionResource, error) {
	var all []versionResource
	token := ""
	for {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Versions      []versionResource `json:"versions"`
			NextPageToken string            `json:"nextPageToken"`
		}
		if err := s.c.do(ctx, http.MethodGet, "/v1/"+s.resource(id)+"/versions", q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Versions...)
		if page.NextPageToken == "" {
			return all, nil
		}
		token = page.NextPageToken
	}
}

func (s *store) forEachSecret(ctx context.Context, fn func(*secretResource, string) error) error {
	token := ""
	for {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Secrets       []secretResource `json:"secrets"`
			NextPageToken string           `json:"nextPageToken"`
		}
		if err := s.c.do(ctx, http.MethodGet, "/v1/projects/"+s.project+"/secrets", q, nil, &page); err != nil {
			return err
		}
		for i := range page.Secrets {
			id, err := s.parseRef(page.Secrets[i].Name)
			if err != nil {
				continue // not ours to interpret
			}
			if err := fn(&page.Secrets[i], id); err != nil {
				return err
			}
		}
		if page.NextPageToken == "" {
			return nil
		}
		token = page.NextPageToken
	}
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// patchMeta rewrites labels and annotations under the secret's etag. On a
// stale etag it reloads and retries, so concurrent writers never lose updates.
func (s *store) patchMeta(ctx context.Context, id string, sec *secretResource, mask string, mutate func(labels, ann map[string]string)) (*secretResource, error) {
	for range 5 {
		labels, ann := clone(sec.Labels), clone(sec.Annotations)
		mutate(labels, ann)
		body := secretResource{Labels: labels, Annotations: ann, Etag: sec.Etag}
		var out secretResource
		err := s.c.do(ctx, http.MethodPatch, "/v1/"+s.resource(id), url.Values{"updateMask": {mask}}, body, &out)
		if err == nil {
			return &out, nil
		}
		if !isStale(err) {
			return nil, err
		}
		fresh, gerr := s.getSecret(ctx, id)
		if gerr != nil {
			return nil, gerr
		}
		sec = fresh
	}
	return nil, fmt.Errorf("%w: the secret kept changing (etag conflicts)", connectors.ErrTransient)
}

// ---- ownership ----

// verify proves the project belongs to this connection: the marker secret
// must hold the connection's external ID. A success is trusted for 15 minutes.
func (s *store) verify(ctx context.Context) error {
	s.mu.Lock()
	ok := !s.verifiedAt.IsZero() && s.now().Sub(s.verifiedAt) < markerRecheck
	s.mu.Unlock()
	if ok {
		return nil
	}
	v, _, err := s.access(ctx, MarkerSecret, "latest")
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return fmt.Errorf("%w: the project has no %s secret holding this connection's external ID", connectors.ErrAccessDenied, MarkerSecret)
		}
		return err
	}
	defer v.Wipe()
	if subtle.ConstantTimeCompare(bytes.TrimSpace(v.Reveal()), []byte(s.externalID)) != 1 {
		return fmt.Errorf("%w: %s does not hold this connection's external ID", connectors.ErrAccessDenied, MarkerSecret)
	}
	s.mu.Lock()
	s.verifiedAt = s.now()
	s.mu.Unlock()
	return nil
}

// ---- helpers over secret state ----

func isDeleted(sec *secretResource) bool { return sec.Labels[lblDeleted] == "true" }

func (s *store) applied(sec *secretResource, id string, key uuid.UUID) (connectors.Result, bool) {
	if v := sec.Annotations[annAppliedVersion]; sec.Annotations[annApplied] == key.String() && v != "" {
		return connectors.Result{ProviderRef: s.resource(id), VersionID: v}, true
	}
	return connectors.Result{}, false
}

// latestMatches reports whether the newest version holds exactly value.
func (s *store) latestMatches(ctx context.Context, id string, value []byte) (string, bool, error) {
	cur, ver, err := s.access(ctx, id, "latest")
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	defer cur.Wipe()
	return ver, subtle.ConstantTimeCompare(cur.Reveal(), value) == 1, nil
}

// ---- SecretStore ----

func (s *store) Stage(ctx context.Context, t connectors.Target, requestID uuid.UUID, value sensitive.Value) (connectors.Staged, error) {
	if err := s.verify(ctx); err != nil {
		return connectors.Staged{}, err
	}
	if t.ProviderRef != "" {
		id, err := s.targetID(t.ProviderRef)
		if err != nil {
			return connectors.Staged{}, err
		}
		sec, err := s.getSecret(ctx, id)
		if err != nil {
			return connectors.Staged{}, err
		}
		if isDeleted(sec) {
			return connectors.Staged{}, fmt.Errorf("%w: secret was deleted", connectors.ErrNotFound)
		}
	} else if err := checkID(t.Name); err != nil {
		return connectors.Staged{}, err
	}
	if value.IsZero() || len(value.Reveal()) > maxPayload {
		return connectors.Staged{}, errors.New("gcp: a value must be 1 byte to 64 KiB")
	}

	shadow := StagingPrefix + requestID.String()
	_, err := s.createSecret(ctx, shadow,
		map[string]string{lblStaging: "true", lblRequest: requestID.String()},
		map[string]string{annCreated: s.now().UTC().Format(time.RFC3339)})
	if err != nil {
		if !errors.Is(err, connectors.ErrConflict) {
			return connectors.Staged{}, err
		}
		// A retried Stage: reuse our own shadow secret, never someone else's.
		sec, gerr := s.getSecret(ctx, shadow)
		if gerr != nil {
			return connectors.Staged{}, gerr
		}
		if sec.Labels[lblStaging] != "true" || sec.Labels[lblRequest] != requestID.String() {
			return connectors.Staged{}, err
		}
		if ver, ok, merr := s.latestMatches(ctx, shadow, value.Reveal()); merr != nil {
			return connectors.Staged{}, merr
		} else if ok {
			return connectors.Staged{Ref: refShadow + s.resource(shadow), Version: ver}, nil
		}
	}
	ver, err := s.addVersion(ctx, shadow, value.Reveal())
	if err != nil {
		// Do not leave an empty shadow secret behind; the sweeper is the backstop.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		_ = s.deleteSecret(dctx, shadow)
		return connectors.Staged{}, err
	}
	return connectors.Staged{Ref: refShadow + s.resource(shadow), Version: ver}, nil
}

func (s *store) ReadStaged(ctx context.Context, st connectors.Staged) (sensitive.Value, error) {
	id, err := s.parseStaged(st.Ref)
	if err != nil {
		return sensitive.Value{}, err
	}
	if err := s.verify(ctx); err != nil {
		return sensitive.Value{}, err
	}
	ver := st.Version
	if ver == "" {
		ver = "latest"
	}
	// Read by version number: a version's content is immutable.
	v, _, err := s.access(ctx, id, ver)
	return v, err
}

func (s *store) DiscardStaged(ctx context.Context, st connectors.Staged) error {
	id, err := s.parseStaged(st.Ref)
	if err != nil {
		return err
	}
	if err := s.verify(ctx); err != nil {
		return err
	}
	sec, err := s.getSecret(ctx, id)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return nil
		}
		return err
	}
	if sec.Labels[lblStaging] != "true" {
		return errors.New("gcp: refusing to delete a secret that is not a SecretMesh staging secret")
	}
	if err := s.deleteSecret(ctx, id); err != nil && !errors.Is(err, connectors.ErrNotFound) {
		return err
	}
	return nil
}

func (s *store) Promote(ctx context.Context, t connectors.Target, st connectors.Staged, key uuid.UUID) (connectors.Result, error) {
	if err := s.verify(ctx); err != nil {
		return connectors.Result{}, err
	}
	stagedID, err := s.parseStaged(st.Ref)
	if err != nil {
		return connectors.Result{}, err
	}
	create := t.ProviderRef == ""
	var id string
	if create {
		if err := checkID(t.Name); err != nil {
			return connectors.Result{}, err
		}
		id = t.Name
	} else if id, err = s.targetID(t.ProviderRef); err != nil {
		return connectors.Result{}, err
	}

	existing, err := s.getSecret(ctx, id)
	switch {
	case err == nil:
		if isDeleted(existing) {
			if create {
				return connectors.Result{}, fmt.Errorf("%w: a deleted secret of that name still exists in the project", connectors.ErrConflict)
			}
			return connectors.Result{}, fmt.Errorf("%w: secret was deleted", connectors.ErrNotFound)
		}
		if res, ok := s.applied(existing, id, key); ok {
			return res, nil
		}
		if create && existing.Annotations[annIntent] != key.String() {
			return connectors.Result{}, fmt.Errorf("%w: a secret named %q already exists", connectors.ErrConflict, id)
		}
	case errors.Is(err, connectors.ErrNotFound) && create:
		existing = nil
	default:
		return connectors.Result{}, err
	}

	value, _, err := s.access(ctx, stagedID, st.Version)
	if err != nil {
		return connectors.Result{}, err
	}
	defer value.Wipe()

	if existing == nil {
		existing, err = s.createSecret(ctx, id,
			map[string]string{lblManaged: "true"},
			map[string]string{annIntent: key.String(), annCreated: s.now().UTC().Format(time.RFC3339)})
		if errors.Is(err, connectors.ErrConflict) {
			// Lost a race, or an earlier attempt of this key created it.
			existing, err = s.getSecret(ctx, id)
			if err == nil && existing.Annotations[annIntent] != key.String() {
				return connectors.Result{}, fmt.Errorf("%w: a secret named %q already exists", connectors.ErrConflict, id)
			}
		}
		if err != nil {
			return connectors.Result{}, err
		}
	}
	ver, err := s.applyVersion(ctx, existing, id, key, value.Reveal())
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{ProviderRef: s.resource(id), VersionID: ver}, nil
}

// applyVersion adds value as a version exactly once for key (see the package
// comment for the protocol).
func (s *store) applyVersion(ctx context.Context, sec *secretResource, id string, key uuid.UUID, value []byte) (string, error) {
	var ver string
	if sec.Annotations[annIntent] != key.String() {
		var err error
		if sec, err = s.patchMeta(ctx, id, sec, "annotations", func(_, ann map[string]string) {
			ann[annIntent] = key.String()
		}); err != nil {
			return "", err
		}
	} else if v, ok, err := s.latestMatches(ctx, id, value); err != nil {
		return "", err
	} else if ok {
		ver = v // an earlier attempt added it but did not record it
	}
	if ver == "" {
		var err error
		if ver, err = s.addVersion(ctx, id, value); err != nil {
			return "", err
		}
	}
	if _, err := s.patchMeta(ctx, id, sec, "annotations", func(_, ann map[string]string) {
		ann[annApplied] = key.String()
		ann[annAppliedVersion] = ver
	}); err != nil {
		return "", err
	}
	return ver, nil
}

func (s *store) Delete(ctx context.Context, t connectors.Target, key uuid.UUID) (connectors.Result, error) {
	if err := s.verify(ctx); err != nil {
		return connectors.Result{}, err
	}
	id, err := s.targetID(t.ProviderRef)
	if err != nil {
		return connectors.Result{}, err
	}
	sec, err := s.getSecret(ctx, id)
	if err != nil {
		return connectors.Result{}, err
	}
	if isDeleted(sec) {
		if sec.Annotations[annDeletedOp] != key.String() {
			return connectors.Result{}, fmt.Errorf("%w: secret was already deleted", connectors.ErrNotFound)
		}
	} else if _, err := s.patchMeta(ctx, id, sec, "labels,annotations", func(labels, ann map[string]string) {
		labels[lblDeleted] = "true"
		ann[annDeletedAt] = s.now().UTC().Format(time.RFC3339)
		ann[annDeletedOp] = key.String()
	}); err != nil {
		return connectors.Result{}, err
	}
	// Disable, never destroy: an administrator can re-enable the versions.
	versions, err := s.listVersions(ctx, id)
	if err != nil {
		return connectors.Result{}, err
	}
	for _, v := range versions {
		if v.State != "ENABLED" {
			continue
		}
		n, err := s.versionNumber(id, v.Name)
		if err != nil {
			return connectors.Result{}, err
		}
		if err := s.c.do(ctx, http.MethodPost, "/v1/"+s.resource(id)+"/versions/"+n+":disable", nil, struct{}{}, nil); err != nil {
			return connectors.Result{}, err
		}
	}
	return connectors.Result{ProviderRef: s.resource(id)}, nil
}

func (s *store) LookupOperation(ctx context.Context, op connectors.Operation) (connectors.Result, bool, error) {
	if err := s.verify(ctx); err != nil {
		return connectors.Result{}, false, err
	}
	var id string
	var err error
	if op.Kind == "create" {
		if err = checkID(op.Target.Name); err == nil {
			id = op.Target.Name
		}
	} else {
		id, err = s.targetID(op.Target.ProviderRef)
	}
	if err != nil {
		return connectors.Result{}, false, err
	}
	sec, err := s.getSecret(ctx, id)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return connectors.Result{}, false, nil
		}
		return connectors.Result{}, false, err
	}
	switch op.Kind {
	case "create", "update":
		if isDeleted(sec) {
			return connectors.Result{}, false, nil
		}
		res, ok := s.applied(sec, id, op.Key)
		return res, ok, nil
	case "delete":
		return connectors.Result{ProviderRef: s.resource(id)}, isDeleted(sec), nil
	}
	return connectors.Result{}, false, nil
}

func parseTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return &t
}

func (s *store) List(ctx context.Context, fn func(connectors.SecretInfo) error) error {
	if err := s.verify(ctx); err != nil {
		return err
	}
	return s.forEachSecret(ctx, func(sec *secretResource, id string) error {
		if reserved(id) || sec.Labels[lblStaging] == "true" || isDeleted(sec) {
			return nil
		}
		info := connectors.SecretInfo{
			ProviderRef: s.resource(id), Name: id, Tags: map[string]string{}, LastChanged: parseTime(sec.CreateTime),
		}
		for k, v := range sec.Labels {
			switch k {
			case lblEnv:
				info.Tags[tagEnv] = v
			case lblClass:
				info.Tags[tagClass] = v
			default:
				info.Tags[k] = v
			}
		}
		// Metadata of the newest version only, never its value.
		var ver versionResource
		err := s.c.do(ctx, http.MethodGet, "/v1/"+s.resource(id)+"/versions/latest", nil, nil, &ver)
		switch {
		case err == nil:
			if ver.State == "ENABLED" {
				info.CurrentVersion, _ = s.versionNumber(id, ver.Name)
			}
			if t := parseTime(ver.CreateTime); t != nil {
				info.LastChanged = t
			}
		case errors.Is(err, connectors.ErrNotFound) || hasStatus(err, "FAILED_PRECONDITION"):
		default:
			return err
		}
		return fn(info)
	})
}

func (s *store) Versions(ctx context.Context, t connectors.Target) ([]connectors.Version, error) {
	if err := s.verify(ctx); err != nil {
		return nil, err
	}
	id, err := s.targetID(t.ProviderRef)
	if err != nil {
		return nil, err
	}
	sec, err := s.getSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	if isDeleted(sec) {
		return nil, fmt.Errorf("%w: secret was deleted", connectors.ErrNotFound)
	}
	vs, err := s.listVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]connectors.Version, 0, len(vs))
	newest := -1
	for _, v := range vs {
		n, err := s.versionNumber(id, v.Name)
		if err != nil {
			return nil, err
		}
		num, _ := strconv.Atoi(n)
		cv := connectors.Version{ID: n, CreatedAt: parseTime(v.CreateTime)}
		switch v.State {
		case "ENABLED":
			if num > newest {
				newest = num
			}
		case "DISABLED":
			cv.Stages = []string{"disabled"}
		case "DESTROYED":
			cv.Stages = []string{"destroyed"}
		}
		out = append(out, cv)
	}
	for i := range out {
		if n, _ := strconv.Atoi(out[i].ID); n == newest {
			out[i].Stages = []string{"current"}
		}
	}
	slices.SortFunc(out, func(a, b connectors.Version) int {
		an, _ := strconv.Atoi(a.ID)
		bn, _ := strconv.Atoi(b.ID)
		return bn - an
	})
	return out, nil
}

func (s *store) Reveal(ctx context.Context, t connectors.Target) (sensitive.Value, string, error) {
	if err := s.verify(ctx); err != nil {
		return sensitive.Value{}, "", err
	}
	id, err := s.targetID(t.ProviderRef)
	if err != nil {
		return sensitive.Value{}, "", err
	}
	sec, err := s.getSecret(ctx, id)
	if err != nil {
		return sensitive.Value{}, "", err
	}
	if isDeleted(sec) {
		return sensitive.Value{}, "", fmt.Errorf("%w: secret was deleted", connectors.ErrNotFound)
	}
	return s.access(ctx, id, "latest")
}

// SweepStaging deletes shadow secrets whose change request is gone or
// finished. A secret is only touched when it has the staging prefix, a
// request UUID in its name and the secretmesh-staging label.
func (s *store) SweepStaging(ctx context.Context, olderThan time.Time, live func(uuid.UUID) (bool, error)) (int, error) {
	if err := s.verify(ctx); err != nil {
		return 0, err
	}
	removed := 0
	err := s.forEachSecret(ctx, func(sec *secretResource, id string) error {
		rest, ok := strings.CutPrefix(id, StagingPrefix)
		if !ok || sec.Labels[lblStaging] != "true" {
			return nil
		}
		reqID, err := uuid.Parse(rest)
		if err != nil {
			return nil
		}
		created := parseTime(sec.CreateTime)
		if created == nil || !created.Before(olderThan) {
			return nil
		}
		isLive, err := live(reqID)
		if err != nil {
			return err
		}
		if isLive {
			return nil
		}
		if err := s.deleteSecret(ctx, id); err != nil && !errors.Is(err, connectors.ErrNotFound) {
			return err
		}
		removed++
		return nil
	})
	return removed, err
}
