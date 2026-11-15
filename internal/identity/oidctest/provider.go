// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package oidctest is a minimal in-process OIDC provider for tests. It
// implements discovery, the authorization endpoint (auto-approving as the
// configured user), PKCE-checked code exchange and JWKS.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims describe the user the provider authenticates.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	// OmitEmailVerified leaves out the email_verified claim (like Entra ID).
	OmitEmailVerified bool
	Name              string
	AMR               []string
	ACR               string
	// AuthTime is when the user last authenticated; zero means now. A request
	// with max_age=0 always re-authenticates (auth_time = now) unless
	// IgnoreMaxAge is set. OmitAuthTime leaves the claim out.
	AuthTime     time.Time
	OmitAuthTime bool
	IgnoreMaxAge bool
}

type pendingCode struct {
	clientID, redirectURI, nonce, challenge string
	claims                                  Claims
	authTime                                time.Time
}

// LastAuthorize is the query of the most recent authorization request.
func (p *Provider) LastAuthorize() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastAuthorize
}

type Provider struct {
	*httptest.Server
	ClientID     string
	ClientSecret string

	t      testing.TB
	key    *rsa.PrivateKey
	mu     sync.Mutex
	user   Claims
	codes  map[string]pendingCode
	signer jose.Signer

	lastAuthorize url.Values
}

func New(t testing.TB, clientID, clientSecret string) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}

	p := &Provider{ClientID: clientID, ClientSecret: clientSecret, t: t, key: key, codes: map[string]pendingCode{}, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /jwks", p.jwks)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// SetUser sets who the next authorization request authenticates as.
func (p *Provider) SetUser(c Claims) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = c
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	authTime := p.user.AuthTime
	if authTime.IsZero() || (q.Get("max_age") == "0" && !p.user.IgnoreMaxAge) {
		authTime = time.Now()
	}
	p.lastAuthorize = q
	p.codes[code] = pendingCode{
		clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"),
		nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), claims: p.user, authTime: authTime,
	}
	p.mu.Unlock()

	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := url.Values{"code": {code}, "state": {q.Get("state")}}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}

	code := r.PostForm.Get("code")
	p.mu.Lock()
	pc, found := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || pc.redirectURI != r.PostForm.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss": p.URL, "sub": pc.claims.Subject, "aud": pc.clientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": pc.nonce, "email": pc.claims.Email, "name": pc.claims.Name,
	}
	if !pc.claims.OmitEmailVerified {
		claims["email_verified"] = pc.claims.EmailVerified
	}
	if !pc.claims.OmitAuthTime {
		claims["auth_time"] = pc.authTime.Unix()
	}
	if len(pc.claims.AMR) > 0 {
		claims["amr"] = pc.claims.AMR
	}
	if pc.claims.ACR != "" {
		claims["acr"] = pc.claims.ACR
	}
	payload, _ := json.Marshal(claims)
	jws, err := p.signer.Sign(payload)
	if err != nil {
		p.t.Errorf("sign id token: %v", err)
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	idToken, _ := jws.CompactSerialize()
	writeJSON(w, map[string]any{
		"access_token": randomString(), "token_type": "Bearer",
		"expires_in": 300, "id_token": idToken,
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: "test", Algorithm: string(jose.RS256), Use: "sig",
	}}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
