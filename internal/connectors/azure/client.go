package azure

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/secretmesh/secretmesh/internal/connectors"
)

// store is the connectors.SecretStore for one connection.
type store struct {
	vaultURL string // canonical vault URL, the prefix of every provider reference
	base     *url.URL
	scope    string
	external string
	cred     azcore.TokenCredential
	now      func() time.Time
	http     *http.Client

	mu         sync.Mutex
	verifiedAt time.Time
}

func newStore(vaultURL string, base *url.URL, scope, externalID string, cred azcore.TokenCredential, now func() time.Time) *store {
	return &store{
		vaultURL: vaultURL, base: base, scope: scope, external: externalID, cred: cred, now: now,
		http: &http.Client{
			Timeout: 30 * time.Second,
			// A bearer token must never follow a redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// apiError is a failed Key Vault call. It carries the status and the provider's
// error code, never the provider's message (which could echo request data).
type apiError struct {
	status int
	code   string
	kind   error
}

var codeRE = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

func (e *apiError) Error() string {
	msg := fmt.Sprintf("azure key vault: HTTP %d", e.status)
	if e.code != "" {
		msg += " " + e.code
	}
	if e.kind != nil {
		return e.kind.Error() + ": " + msg
	}
	return msg
}

func (e *apiError) Unwrap() error { return e.kind }

func newAPIError(status int, body []byte) *apiError {
	e := &apiError{status: status}
	var env struct {
		Error struct {
			Code       string `json:"code"`
			InnerError struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		code := env.Error.InnerError.Code
		if code == "" {
			code = env.Error.Code
		}
		if codeRE.MatchString(code) {
			e.code = code
		}
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = connectors.ErrAccessDenied
	case status == http.StatusNotFound:
		e.kind = connectors.ErrNotFound
	case status == http.StatusConflict:
		e.kind = connectors.ErrConflict
	case status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500:
		e.kind = connectors.ErrTransient
	}
	return e
}

func isCode(err error, code string) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.code == code
}

type response struct {
	header http.Header
	body   []byte
}

// endpoint builds a URL on the configured base. Paths contain only validated
// names and version IDs, so they need no escaping.
func (s *store) endpoint(path string, q url.Values) string {
	u := *s.base
	u.Path = path
	if q == nil {
		q = url.Values{}
	}
	q.Set("api-version", apiVersion)
	u.RawQuery = q.Encode()
	return u.String()
}

// do sends one authenticated request. It refuses any URL outside the
// configured host, so a hostile nextLink never receives the token.
func (s *store) do(ctx context.Context, method, rawURL string, body []byte) (*response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != s.base.Scheme || !strings.EqualFold(u.Host, s.base.Host) {
		return nil, errors.New("azure key vault: refusing a request outside the configured vault")
	}
	tok, err := s.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{s.scope}})
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %w", connectors.ErrTransient, ctx.Err())
		}
		// azidentity messages can carry identity-provider response bodies.
		return nil, fmt.Errorf("%w: azure: no access token for the vault (check the workload identity, tenant_id and network)", connectors.ErrTransient)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secretmesh")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: azure key vault request failed: %w", connectors.ErrTransient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading azure key vault response: %w", connectors.ErrTransient, err)
	}
	if len(raw) > maxBody {
		clear(raw)
		return nil, errors.New("azure key vault: response too large")
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("azure key vault: unexpected redirect (HTTP %d)", resp.StatusCode)
	case resp.StatusCode >= 400:
		return nil, newAPIError(resp.StatusCode, raw)
	}
	return &response{header: resp.Header, body: raw}, nil
}

// call checks the external-id marker, then sends the request.
func (s *store) call(ctx context.Context, method, path string, q url.Values, body []byte) (*response, error) {
	if err := s.verify(ctx); err != nil {
		return nil, err
	}
	return s.do(ctx, method, s.endpoint(path, q), body)
}

// verify proves the vault owner created the marker for this connection. A
// success is trusted for 15 minutes; a failure is never cached.
func (s *store) verify(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.verifiedAt.IsZero() && s.now().Sub(s.verifiedAt) < markerRecheck {
		return nil
	}
	s.verifiedAt = time.Time{}
	resp, err := s.do(ctx, http.MethodGet, s.endpoint("/secrets/"+MarkerName, nil), nil)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return fmt.Errorf("%w: the vault has no %q secret; create it with this connection's external_id", connectors.ErrAccessDenied, MarkerName)
		}
		return err
	}
	var b bundle
	if err := decode(resp, &b); err != nil || b.Value == nil {
		return fmt.Errorf("%w: the %q secret is unreadable", connectors.ErrAccessDenied, MarkerName)
	}
	got := strings.TrimRight(*b.Value, "\r\n")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.external)) != 1 {
		return fmt.Errorf("%w: the %q secret does not match this connection's external_id", connectors.ErrAccessDenied, MarkerName)
	}
	s.verifiedAt = s.now()
	return nil
}

type attributes struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Created *int64 `json:"created,omitempty"`
	Updated *int64 `json:"updated,omitempty"`
}

type bundle struct {
	ID          string            `json:"id"`
	Value       *string           `json:"value,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Attributes  attributes        `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
}

func (b bundle) enabled() bool { return b.Attributes.Enabled == nil || *b.Attributes.Enabled }

type page struct {
	Value    []bundle `json:"value"`
	NextLink string   `json:"nextLink"`
}

// decode unmarshals a response and wipes the raw bytes, which may hold a value.
func decode(resp *response, out any) error {
	defer clear(resp.body)
	if err := json.Unmarshal(resp.body, out); err != nil {
		return errors.New("azure key vault: malformed response")
	}
	return nil
}

// pages calls fn for every item of a paged listing. Every nextLink must stay
// on the configured vault host.
func (s *store) pages(ctx context.Context, path string, q url.Values, fn func(bundle) error) error {
	if err := s.verify(ctx); err != nil {
		return err
	}
	next := s.endpoint(path, q)
	seen := map[string]bool{}
	for next != "" {
		if seen[next] {
			return errors.New("azure key vault: paging did not advance")
		}
		seen[next] = true
		resp, err := s.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		var p page
		if err := decode(resp, &p); err != nil {
			return err
		}
		for _, b := range p.Value {
			if err := fn(b); err != nil {
				return err
			}
		}
		next = p.NextLink
	}
	return nil
}

// splitID extracts the secret name and version from a Key Vault object ID.
// Only the path is used; the host is never trusted.
func splitID(id string) (name, version string) {
	u, err := url.Parse(id)
	if err != nil {
		return "", ""
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 || segs[0] != "secrets" {
		return "", ""
	}
	name = segs[1]
	if len(segs) > 2 {
		version = segs[2]
	}
	return name, version
}

func unixTime(n *int64) *time.Time {
	if n == nil {
		return nil
	}
	t := time.Unix(*n, 0).UTC()
	return &t
}
