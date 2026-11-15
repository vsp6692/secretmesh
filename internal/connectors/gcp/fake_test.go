// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package gcp_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/gcp"
)

const (
	testProject = "test-project-123"
	testSA      = "secretmesh@test-project-123.iam.gserviceaccount.com"
	baseToken   = "base-adc-token"
	// providerBodyMarker is inside every error message the fake sends; it
	// must never reach a connector error.
	providerBodyMarker = "PROVIDER-BODY-MARKER"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type fversion struct {
	n     int
	state string
	data  []byte
	at    time.Time
}

type fsecret struct {
	id       string
	created  time.Time
	labels   map[string]string
	ann      map[string]string
	etag     string
	versions []*fversion
}

// fault injects a failure into matching Secret Manager requests.
type fault struct {
	match func(r *http.Request) bool
	// status != 0 answers with that HTTP status (and Google status) instead of running the request.
	status       int
	googleStatus string
	body         string
	// dropAfter runs the request, then closes the connection without answering.
	dropAfter bool
	// times limits how often it fires (0 = always).
	times int
	fired int
}

// fakeGCP is an in-memory Secret Manager plus IAM Credentials, with the
// semantics the connector depends on: etags (412 when stale), numbered
// versions with states, crc32c integrity, latest alias, 409 on duplicates,
// paging of two items, and bearer tokens issued only by the IAM endpoint.
type fakeGCP struct {
	t   *testing.T
	SM  *httptest.Server
	IAM *httptest.Server

	mu        sync.Mutex
	secrets   map[string]*fsecret
	etagN     int
	tokens    map[string]bool
	tokenN    int
	iamCalls  int
	requests  []string
	faults    []*fault
	tamperCRC bool
	// staleNext makes the next n PATCH requests see a concurrent writer.
	staleNext int
}

func newFake(t *testing.T) *fakeGCP {
	t.Helper()
	f := &fakeGCP{t: t, secrets: map[string]*fsecret{}, tokens: map[string]bool{}}
	f.SM = httptest.NewServer(http.HandlerFunc(f.serveSM))
	f.IAM = httptest.NewServer(http.HandlerFunc(f.serveIAM))
	t.Cleanup(f.SM.Close)
	t.Cleanup(f.IAM.Close)
	return f
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, status string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{
		"code": code, "status": status, "message": providerBodyMarker + " " + status + " details of the request",
	}})
}

func (f *fakeGCP) serveIAM(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.iamCalls++
	if r.Header.Get("Authorization") != "Bearer "+baseToken {
		writeErr(w, 401, "UNAUTHENTICATED")
		return
	}
	sa, ok := strings.CutPrefix(r.URL.Path, "/v1/projects/-/serviceAccounts/")
	sa, ok2 := strings.CutSuffix(sa, ":generateAccessToken")
	if r.Method != http.MethodPost || !ok || !ok2 {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	if sa != testSA {
		writeErr(w, 403, "PERMISSION_DENIED") // no tokenCreator binding on that account
		return
	}
	var body struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Lifetime != "900s" ||
		len(body.Scope) != 1 || body.Scope[0] != "https://www.googleapis.com/auth/cloud-platform" {
		writeErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	f.tokenN++
	tok := fmt.Sprintf("imp-token-%d", f.tokenN)
	f.tokens[tok] = true
	writeJSON(w, 200, map[string]string{"accessToken": tok, "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
}

func (f *fakeGCP) addFault(ft *fault) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = append(f.faults, ft)
	return ft
}

func (f *fakeGCP) clearFaults() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = nil
}

func (f *fakeGCP) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeGCP) serveSM(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !f.tokens[tok] {
		writeErr(w, 401, "UNAUTHENTICATED")
		return
	}
	var dropAfter bool
	for _, ft := range f.faults {
		if !ft.match(r) || (ft.times > 0 && ft.fired >= ft.times) {
			continue
		}
		ft.fired++
		if ft.status != 0 {
			body := ft.body
			if body == "" {
				body = fmt.Sprintf(`{"error":{"code":%d,"status":%q,"message":%q}}`, ft.status, ft.googleStatus, providerBodyMarker)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ft.status)
			_, _ = w.Write([]byte(body))
			return
		}
		dropAfter = ft.dropAfter
	}
	rec := httptest.NewRecorder()
	f.route(rec, r)
	if dropAfter {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (f *fakeGCP) newEtag() string {
	f.etagN++
	return "etag-" + strconv.Itoa(f.etagN)
}

func (f *fakeGCP) secretJSON(s *fsecret) map[string]any {
	return map[string]any{
		"name": "projects/" + testProject + "/secrets/" + s.id, "createTime": s.created.UTC().Format(time.RFC3339Nano),
		"labels": s.labels, "annotations": s.ann, "etag": s.etag, "replication": map[string]any{"automatic": map[string]any{}},
	}
}

func versionJSON(id string, v *fversion) map[string]any {
	return map[string]any{
		"name":       "projects/" + testProject + "/secrets/" + id + "/versions/" + strconv.Itoa(v.n),
		"createTime": v.at.UTC().Format(time.RFC3339Nano), "state": v.state,
	}
}

func (f *fakeGCP) route(w http.ResponseWriter, r *http.Request) {
	path, ok := strings.CutPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if !ok || len(parts) < 3 || parts[0] != "projects" || parts[2] != "secrets" {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	if parts[1] != testProject {
		writeErr(w, 403, "PERMISSION_DENIED")
		return
	}
	switch {
	case len(parts) == 3 && r.Method == http.MethodPost:
		f.create(w, r)
	case len(parts) == 3 && r.Method == http.MethodGet:
		f.list(w, r)
	case len(parts) == 4:
		id, verb, _ := strings.Cut(parts[3], ":")
		if verb == "addVersion" && r.Method == http.MethodPost {
			f.addVersion(w, r, id)
			return
		}
		f.secretOp(w, r, id)
	case len(parts) == 5 && parts[4] == "versions" && r.Method == http.MethodGet:
		f.listVersions(w, r, parts[3])
	case len(parts) == 6 && parts[4] == "versions":
		f.versionOp(w, r, parts[3], parts[5])
	default:
		writeErr(w, 404, "NOT_FOUND")
	}
}

func (f *fakeGCP) create(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("secretId")
	var body struct {
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	}
	if id == "" || json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	if _, dup := f.secrets[id]; dup {
		writeErr(w, 409, "ALREADY_EXISTS")
		return
	}
	s := &fsecret{id: id, created: time.Now(), labels: orEmpty(body.Labels), ann: orEmpty(body.Annotations), etag: f.newEtag()}
	f.secrets[id] = s
	writeJSON(w, 200, f.secretJSON(s))
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (f *fakeGCP) sortedIDs() []string {
	ids := make([]string, 0, len(f.secrets))
	for id := range f.secrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (f *fakeGCP) list(w http.ResponseWriter, r *http.Request) {
	ids := f.sortedIDs()
	from, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
	to := min(from+2, len(ids))
	next := ""
	if to < len(ids) {
		next = strconv.Itoa(to)
	}
	out := []any{}
	for _, id := range ids[min(from, len(ids)):to] {
		out = append(out, f.secretJSON(f.secrets[id]))
	}
	writeJSON(w, 200, map[string]any{"secrets": out, "nextPageToken": next, "totalSize": len(ids)})
}

func (f *fakeGCP) secretOp(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := f.secrets[id]
	if !ok {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, f.secretJSON(s))
	case http.MethodPatch:
		var body struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			Etag        string            `json:"etag"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeErr(w, 400, "INVALID_ARGUMENT")
			return
		}
		if f.staleNext > 0 {
			f.staleNext--
			s.etag = f.newEtag() // a concurrent writer got in first
		}
		if body.Etag != "" && body.Etag != s.etag {
			writeErr(w, 412, "FAILED_PRECONDITION")
			return
		}
		for _, field := range strings.Split(r.URL.Query().Get("updateMask"), ",") {
			switch field {
			case "labels":
				s.labels = orEmpty(body.Labels)
			case "annotations":
				s.ann = orEmpty(body.Annotations)
			default:
				writeErr(w, 400, "INVALID_ARGUMENT")
				return
			}
		}
		s.etag = f.newEtag()
		writeJSON(w, 200, f.secretJSON(s))
	case http.MethodDelete:
		if e := r.URL.Query().Get("etag"); e != "" && e != s.etag {
			writeErr(w, 412, "FAILED_PRECONDITION")
			return
		}
		delete(f.secrets, id)
		writeJSON(w, 200, map[string]any{})
	default:
		writeErr(w, 405, "INVALID_ARGUMENT")
	}
}

func (f *fakeGCP) addVersion(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := f.secrets[id]
	if !ok {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	var body struct {
		Payload struct {
			Data string          `json:"data"`
			CRC  json.RawMessage `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.Payload.Data)
	if err != nil || len(data) > 64*1024 {
		writeErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	if len(body.Payload.CRC) > 0 {
		got, _ := strconv.ParseInt(strings.Trim(string(body.Payload.CRC), `"`), 10, 64)
		if got != int64(crc32.Checksum(data, castagnoli)) {
			writeErr(w, 400, "INVALID_ARGUMENT")
			return
		}
	}
	v := &fversion{n: len(s.versions) + 1, state: "ENABLED", data: data, at: time.Now()}
	s.versions = append(s.versions, v)
	writeJSON(w, 200, versionJSON(id, v))
}

func (f *fakeGCP) listVersions(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := f.secrets[id]
	if !ok {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	from, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
	n := len(s.versions)
	to := min(from+2, n)
	next := ""
	if to < n {
		next = strconv.Itoa(to)
	}
	out := []any{}
	// Newest first, like the real API.
	for i := from; i < to; i++ {
		out = append(out, versionJSON(id, s.versions[n-1-i]))
	}
	writeJSON(w, 200, map[string]any{"versions": out, "nextPageToken": next})
}

func (f *fakeGCP) versionOp(w http.ResponseWriter, r *http.Request, id, last string) {
	s, ok := f.secrets[id]
	if !ok {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	ref, verb, _ := strings.Cut(last, ":")
	var v *fversion
	if ref == "latest" {
		if len(s.versions) > 0 {
			v = s.versions[len(s.versions)-1]
		}
	} else if n, err := strconv.Atoi(ref); err == nil && n >= 1 && n <= len(s.versions) {
		v = s.versions[n-1]
	}
	if v == nil {
		writeErr(w, 404, "NOT_FOUND")
		return
	}
	switch {
	case verb == "access" && r.Method == http.MethodGet:
		if v.state != "ENABLED" {
			writeErr(w, 400, "FAILED_PRECONDITION")
			return
		}
		crc := int64(crc32.Checksum(v.data, castagnoli))
		if f.tamperCRC {
			crc++
		}
		writeJSON(w, 200, map[string]any{
			"name":    versionJSON(id, v)["name"],
			"payload": map[string]any{"data": base64.StdEncoding.EncodeToString(v.data), "dataCrc32c": strconv.FormatInt(crc, 10)},
		})
	case verb == "disable" && r.Method == http.MethodPost:
		if v.state == "ENABLED" {
			v.state = "DISABLED"
		}
		writeJSON(w, 200, versionJSON(id, v))
	case verb == "" && r.Method == http.MethodGet:
		writeJSON(w, 200, versionJSON(id, v))
	default:
		writeErr(w, 404, "NOT_FOUND")
	}
}

// ---- direct access for assertions and seeding ----

func (f *fakeGCP) seed(id string, labels, ann map[string]string, created time.Time, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &fsecret{id: id, created: created, labels: orEmpty(labels), ann: orEmpty(ann), etag: f.newEtag()}
	for i, v := range values {
		s.versions = append(s.versions, &fversion{n: i + 1, state: "ENABLED", data: []byte(v), at: created})
	}
	f.secrets[id] = s
}

func (f *fakeGCP) addValue(id, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.secrets[id]
	s.versions = append(s.versions, &fversion{n: len(s.versions) + 1, state: "ENABLED", data: []byte(value), at: time.Now()})
}

func (f *fakeGCP) secret(id string) (*fsecret, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[id]
	return s, ok
}

func (f *fakeGCP) setTamperCRC(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tamperCRC = v
}

func (f *fakeGCP) setStaleNext(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staleNext = n
}

func (f *fakeGCP) iamCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iamCalls
}

func (f *fakeGCP) versionStates(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, v := range f.secrets[id].versions {
		out = append(out, v.state)
	}
	return out
}

// ---- provider construction ----

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func staticToken(tok string) oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok})
}

func (f *fakeGCP) provider(t *testing.T, mutate ...func(*gcp.Options)) *gcp.Provider {
	t.Helper()
	o := gcp.Options{Endpoint: f.SM.URL, IAMEndpoint: f.IAM.URL, BaseTokenSource: staticToken(baseToken)}
	for _, m := range mutate {
		m(&o)
	}
	p, err := gcp.New(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func config(extID string) map[string]string {
	return map[string]string{"project_id": testProject, "service_account": testSA, "external_id": extID}
}

// newStore connects a store whose project already holds the marker secret.
func (f *fakeGCP) newStore(t *testing.T, mutate ...func(*gcp.Options)) (connectors.SecretStore, string) {
	t.Helper()
	extID := gcp.NewExternalID()
	if _, ok := f.secret(gcp.MarkerSecret); !ok {
		f.seed(gcp.MarkerSecret, nil, nil, time.Now(), extID)
	} else {
		extID = string(f.secrets[gcp.MarkerSecret].versions[0].data)
	}
	s, err := f.provider(t, mutate...).Factory(connectors.Connection{ID: uuid.New(), Provider: gcp.ProviderName, Config: config(extID)})
	if err != nil {
		t.Fatal(err)
	}
	return s, extID
}
