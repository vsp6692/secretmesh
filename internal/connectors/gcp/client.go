// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/secretmesh/secretmesh/internal/connectors"
)

const (
	requestTimeout = 30 * time.Second
	// maxResponse caps what is read from any response, so a misbehaving
	// endpoint cannot exhaust memory. Secret Manager payloads are at most
	// 64 KiB (about 88 KiB as base64 JSON).
	maxResponse = 2 << 20
)

// apiError is a failed Secret Manager or IAM call. It carries the HTTP status
// and Google's canonical status code (NOT_FOUND, ...) only: provider error
// messages can quote request details, so they are never kept.
type apiError struct {
	HTTP   int
	Status string
}

func (e *apiError) Error() string {
	if e.Status == "" {
		return fmt.Sprintf("gcp: http %d", e.HTTP)
	}
	return fmt.Sprintf("gcp: http %d %s", e.HTTP, e.Status)
}

var statusRE = regexp.MustCompile(`^[A-Z_]{1,40}$`)

func parseAPIError(code int, body []byte) *apiError {
	e := &apiError{HTTP: code}
	var env struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && statusRE.MatchString(env.Error.Status) {
		e.Status = env.Error.Status
	}
	return e
}

// client talks to one API host (Secret Manager or IAM Credentials). It never
// follows redirects and sends its token only to that host.
type client struct {
	http *http.Client
	base string // scheme://host[:port], no trailing slash
	host string
	ts   oauth2.TokenSource
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		// A redirect could carry the bearer token to another host; a 3xx
		// is reported as an error instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// do sends one JSON request and decodes the response into out (if not nil).
// Errors are mapped to the connectors sentinels and still unwrap to *apiError.
func (c *client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("gcp: encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("gcp: build request: %w", err)
	}
	if req.URL.Host != c.host {
		return errors.New("gcp: request host does not match the configured endpoint")
	}
	tok, err := c.ts.Token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the URL (secret names only, never values).
		return fmt.Errorf("%w: %w", connectors.ErrTransient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("%w: reading response: %w", connectors.ErrTransient, err)
	}
	if len(raw) > maxResponse {
		return errors.New("gcp: response exceeds the size limit")
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("gcp: unexpected redirect (http %d), not followed", resp.StatusCode)
	case resp.StatusCode >= 400:
		return mapAPIError(parseAPIError(resp.StatusCode, raw))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("gcp: malformed response")
	}
	return nil
}

func mapAPIError(e *apiError) error {
	switch {
	case e.HTTP == http.StatusUnauthorized || e.HTTP == http.StatusForbidden:
		return fmt.Errorf("%w: %w", connectors.ErrAccessDenied, e)
	case e.HTTP == http.StatusNotFound:
		return fmt.Errorf("%w: %w", connectors.ErrNotFound, e)
	case e.HTTP == http.StatusConflict:
		return fmt.Errorf("%w: %w", connectors.ErrConflict, e)
	case e.HTTP == http.StatusTooManyRequests || e.HTTP >= 500:
		return fmt.Errorf("%w: %w", connectors.ErrTransient, e)
	}
	return e
}

// hasStatus reports whether err is an API error with the given Google status.
func hasStatus(err error, status string) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == status
}

// isStale reports an etag precondition failure on a metadata update.
func isStale(err error) bool {
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.HTTP == http.StatusPreconditionFailed || ae.Status == "ABORTED" || ae.Status == "FAILED_PRECONDITION"
}

// parseEndpoint validates a base URL override. Plain http is allowed because
// an override only exists for local emulators and tests.
func parseEndpoint(raw string) (base, host string, err error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("gcp: endpoint must be a plain http(s) base URL")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/"), u.Host, nil
}
