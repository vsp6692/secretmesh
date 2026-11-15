// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func (s *store) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		SecretCreate: true, SecretUpdate: true, SecretDelete: true, SecretReveal: true, Discovery: true,
		Versioning: true, VersionLabels: false, SoftDelete: true, NativeRotation: false, Tags: true,
		UpdateStaging: "shadow_secret", CreateStaging: "shadow_secret",
	}
}

func isReserved(name string) bool {
	l := strings.ToLower(name)
	return l == MarkerName || strings.HasPrefix(l, StagingPrefix)
}

// validTarget checks a name SecretMesh may create or change.
func validTarget(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("azure: a secret name has 1 to 127 letters, digits and dashes")
	}
	if isReserved(name) {
		return fmt.Errorf("azure: names %q and %q* are reserved by SecretMesh", MarkerName, StagingPrefix)
	}
	return nil
}

func (s *store) ref(name string) string { return s.vaultURL + "/secrets/" + name }

// refName returns the secret name in a provider reference, which must point
// into this connection's vault.
func (s *store) refName(ref string) (string, error) {
	prefix := s.vaultURL + "/secrets/"
	if len(ref) <= len(prefix) || !strings.EqualFold(ref[:len(prefix)], prefix) {
		return "", errors.New("azure: provider reference does not belong to this vault")
	}
	name := ref[len(prefix):]
	if err := validTarget(name); err != nil {
		return "", err
	}
	return name, nil
}

// targetName resolves a Target to a secret name; create is true when the
// secret does not exist yet.
func (s *store) targetName(t connectors.Target) (name string, create bool, err error) {
	if t.ProviderRef == "" {
		return t.Name, true, validTarget(t.Name)
	}
	name, err = s.refName(t.ProviderRef)
	return name, false, err
}

// stagingName returns the shadow secret named by a staging reference. Only
// shadow secrets can be read or discarded through it.
func stagingName(ref string) (string, error) {
	name, ok := strings.CutPrefix(ref, refShadow)
	if ok {
		if rest, ok := strings.CutPrefix(name, StagingPrefix); ok {
			if _, err := uuid.Parse(rest); err == nil {
				return name, nil
			}
		}
	}
	return "", errors.New("unrecognized staging reference")
}

func checkValue(v sensitive.Value) error {
	if len(v.Reveal()) > maxValueBytes {
		return errors.New("azure: a Key Vault secret value is limited to 25 KiB")
	}
	if !utf8.Valid(v.Reveal()) {
		return errors.New("azure: Key Vault stores text; the value is not valid UTF-8")
	}
	return nil
}

type setBody struct {
	Value       string            `json:"value"`
	ContentType string            `json:"contentType,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// put writes a new version and returns it. The request body holds the value
// and is wiped after use.
func (s *store) put(ctx context.Context, name string, value sensitive.Value, contentType string, tags map[string]string) (bundle, string, error) {
	body, err := json.Marshal(setBody{Value: value.RevealString(), ContentType: contentType, Tags: tags})
	if err != nil {
		return bundle{}, "", err
	}
	defer clear(body)
	resp, err := s.call(ctx, http.MethodPut, "/secrets/"+name, nil, body)
	if err != nil {
		return bundle{}, "", err
	}
	reqID := resp.header.Get("x-ms-request-id")
	var b bundle
	if err := decode(resp, &b); err != nil {
		return bundle{}, "", err
	}
	return b, reqID, nil
}

// get reads one version, or the latest when version is empty.
func (s *store) get(ctx context.Context, name, version string) (bundle, error) {
	path := "/secrets/" + name
	if version != "" {
		if !versionRE.MatchString(version) {
			return bundle{}, errors.New("azure: malformed version ID")
		}
		path += "/" + version
	}
	resp, err := s.call(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return bundle{}, err
	}
	var b bundle
	if err := decode(resp, &b); err != nil {
		return bundle{}, err
	}
	return b, nil
}

// versions lists every version of a secret, newest first. A secret that does
// not exist yields connectors.ErrNotFound.
func (s *store) versions(ctx context.Context, name string) ([]bundle, error) {
	var out []bundle
	if err := s.pages(ctx, "/secrets/"+name+"/versions", nil, func(b bundle) error {
		out = append(out, b)
		return nil
	}); err != nil {
		return nil, err
	}
	slices.SortStableFunc(out, func(a, b bundle) int {
		var ca, cb int64
		if a.Attributes.Created != nil {
			ca = *a.Attributes.Created
		}
		if b.Attributes.Created != nil {
			cb = *b.Attributes.Created
		}
		return int(cb - ca)
	})
	return out, nil
}

func (s *store) Stage(ctx context.Context, t connectors.Target, requestID uuid.UUID, value sensitive.Value) (connectors.Staged, error) {
	name, create, err := s.targetName(t)
	if err != nil {
		return connectors.Staged{}, err
	}
	if err := checkValue(value); err != nil {
		return connectors.Staged{}, err
	}
	if !create {
		// Fail now, not at approval time, if the target is gone.
		if _, err := s.versions(ctx, name); err != nil {
			return connectors.Staged{}, err
		}
	}
	shadow := StagingPrefix + requestID.String()
	b, _, err := s.put(ctx, shadow, value, "", map[string]string{
		stagingTag: "true",
		requestTag: requestID.String(),
		createdTag: s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return connectors.Staged{}, err
	}
	_, version := splitID(b.ID)
	if !versionRE.MatchString(version) {
		return connectors.Staged{}, errors.New("azure key vault: no version in the response")
	}
	return connectors.Staged{Ref: refShadow + shadow, Version: version}, nil
}

func (s *store) ReadStaged(ctx context.Context, st connectors.Staged) (sensitive.Value, error) {
	name, err := stagingName(st.Ref)
	if err != nil {
		return sensitive.Value{}, err
	}
	return s.read(ctx, name, st.Version)
}

func (s *store) read(ctx context.Context, name, version string) (sensitive.Value, error) {
	b, err := s.get(ctx, name, version)
	if err != nil {
		return sensitive.Value{}, err
	}
	if b.Value == nil {
		return sensitive.Value{}, errors.New("azure key vault: no value in the response")
	}
	return sensitive.FromString(*b.Value), nil
}

// DiscardStaged deletes the shadow secret and tries to purge it. Purge is
// best effort: with purge protection the value stays soft-deleted in the
// customer's vault for the retention period (and nowhere else).
func (s *store) DiscardStaged(ctx context.Context, st connectors.Staged) error {
	name, err := stagingName(st.Ref)
	if err != nil {
		return err
	}
	return s.destroyShadow(ctx, name)
}

func (s *store) destroyShadow(ctx context.Context, name string) error {
	if _, err := s.call(ctx, http.MethodDelete, "/secrets/"+name, nil, nil); err != nil && !errors.Is(err, connectors.ErrNotFound) {
		return err
	}
	_, _ = s.call(ctx, http.MethodDelete, "/deletedsecrets/"+name, nil, nil)
	return nil
}

// findOp returns the version a promotion with this journal key wrote.
func findOp(vs []bundle, key uuid.UUID) (bundle, bool) {
	for _, v := range vs {
		if v.Tags[opTag] == key.String() {
			return v, true
		}
	}
	return bundle{}, false
}

func (s *store) result(name string, b bundle, reqID string) connectors.Result {
	_, version := splitID(b.ID)
	return connectors.Result{ProviderRef: s.ref(name), VersionID: version, RequestID: reqID}
}

// Promote writes the staged value to the target as a new version tagged with
// the journal key. A retry with the same key returns that version instead of
// writing another. Creating checks that the name is free first; a concurrent
// creator between that check and the write is the one race left, and the
// write then fails with a conflict if the name is taken or soft-deleted.
func (s *store) Promote(ctx context.Context, t connectors.Target, st connectors.Staged, key uuid.UUID) (connectors.Result, error) {
	name, create, err := s.targetName(t)
	if err != nil {
		return connectors.Result{}, err
	}
	shadow, err := stagingName(st.Ref)
	if err != nil {
		return connectors.Result{}, err
	}
	vs, err := s.versions(ctx, name)
	switch {
	case err == nil:
		if v, ok := findOp(vs, key); ok {
			return s.result(name, v, ""), nil
		}
		if create {
			return connectors.Result{}, fmt.Errorf("%w: a secret named %q already exists", connectors.ErrConflict, name)
		}
	case errors.Is(err, connectors.ErrNotFound) && create:
		vs = nil
	default:
		return connectors.Result{}, err
	}

	value, err := s.read(ctx, shadow, st.Version)
	if err != nil {
		return connectors.Result{}, err
	}
	defer value.Wipe()

	tags := map[string]string{opTag: key.String()}
	contentType := ""
	if create {
		tags[managedTag] = "true"
	} else if len(vs) > 0 {
		// A new version starts without tags: carry the current ones over, or
		// discovery would lose the secret's environment and classification.
		for k, v := range vs[0].Tags {
			tags[k] = v
		}
		contentType = vs[0].ContentType
		tags[opTag] = key.String()
	}
	b, reqID, err := s.put(ctx, name, value, contentType, tags)
	if err != nil {
		return connectors.Result{}, err
	}
	return s.result(name, b, reqID), nil
}

// Delete soft-deletes the secret; it stays recoverable in the vault and
// SecretMesh never purges targets. Deleting a deleted secret succeeds.
func (s *store) Delete(ctx context.Context, t connectors.Target, _ uuid.UUID) (connectors.Result, error) {
	name, err := s.refName(t.ProviderRef)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := s.call(ctx, http.MethodDelete, "/secrets/"+name, nil, nil)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			if deleted, derr := s.isDeleted(ctx, name); derr == nil && deleted {
				return connectors.Result{ProviderRef: t.ProviderRef}, nil
			}
		}
		return connectors.Result{}, err
	}
	return connectors.Result{ProviderRef: t.ProviderRef, RequestID: resp.header.Get("x-ms-request-id")}, nil
}

func (s *store) isDeleted(ctx context.Context, name string) (bool, error) {
	_, err := s.call(ctx, http.MethodGet, "/deletedsecrets/"+name, nil, nil)
	if errors.Is(err, connectors.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *store) LookupOperation(ctx context.Context, op connectors.Operation) (connectors.Result, bool, error) {
	var name string
	var err error
	if op.Kind == "create" {
		name = op.Target.Name
		err = validTarget(name)
	} else {
		name, err = s.refName(op.Target.ProviderRef)
	}
	if err != nil {
		return connectors.Result{}, false, err
	}
	if op.Kind == "delete" {
		if deleted, err := s.isDeleted(ctx, name); err != nil || deleted {
			return connectors.Result{ProviderRef: s.ref(name)}, deleted, err
		}
		_, err := s.versions(ctx, name)
		if errors.Is(err, connectors.ErrNotFound) {
			return connectors.Result{ProviderRef: s.ref(name)}, true, nil // gone
		}
		return connectors.Result{}, false, err
	}
	vs, err := s.versions(ctx, name)
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return connectors.Result{}, false, nil
		}
		return connectors.Result{}, false, err
	}
	if v, ok := findOp(vs, op.Key); ok {
		return s.result(name, v, ""), true, nil
	}
	return connectors.Result{}, false, nil
}

// List reports every secret except SecretMesh's own (the marker and staging).
// It reads metadata only, never values.
func (s *store) List(ctx context.Context, fn func(connectors.SecretInfo) error) error {
	return s.pages(ctx, "/secrets", nil, func(b bundle) error {
		name, version := splitID(b.ID)
		if name == "" || isReserved(name) {
			return nil
		}
		info := connectors.SecretInfo{
			ProviderRef: s.ref(name), Name: name, CurrentVersion: version,
			Tags: map[string]string{}, LastChanged: unixTime(b.Attributes.Updated),
		}
		for k, v := range b.Tags {
			info.Tags[k] = v
		}
		return fn(info)
	})
}

func (s *store) Versions(ctx context.Context, t connectors.Target) ([]connectors.Version, error) {
	name, err := s.refName(t.ProviderRef)
	if err != nil {
		return nil, err
	}
	vs, err := s.versions(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]connectors.Version, 0, len(vs))
	currentSet := false
	for _, v := range vs {
		_, id := splitID(v.ID)
		cv := connectors.Version{ID: id, CreatedAt: unixTime(v.Attributes.Created)}
		if !currentSet && v.enabled() {
			cv.Stages, currentSet = []string{"current"}, true
		}
		out = append(out, cv)
	}
	return out, nil
}

// Reveal reads the newest enabled version.
func (s *store) Reveal(ctx context.Context, t connectors.Target) (sensitive.Value, string, error) {
	name, err := s.refName(t.ProviderRef)
	if err != nil {
		return sensitive.Value{}, "", err
	}
	b, err := s.get(ctx, name, "")
	if isCode(err, "SecretDisabled") {
		// The latest version is disabled: fall back to the newest enabled one.
		vs, verr := s.versions(ctx, name)
		if verr != nil {
			return sensitive.Value{}, "", verr
		}
		i := slices.IndexFunc(vs, bundle.enabled)
		if i < 0 {
			return sensitive.Value{}, "", fmt.Errorf("%w: every version is disabled", connectors.ErrNotFound)
		}
		_, version := splitID(vs[i].ID)
		b, err = s.get(ctx, name, version)
	}
	if err != nil {
		return sensitive.Value{}, "", err
	}
	if b.Value == nil {
		return sensitive.Value{}, "", errors.New("azure key vault: no value in the response")
	}
	_, version := splitID(b.ID)
	return sensitive.FromString(*b.Value), version, nil
}

// SweepStaging deletes shadow secrets whose change request is gone or
// finished. A secret is only touched when it has the staging prefix, a
// request ID as its name and the secretmesh-staging tag.
func (s *store) SweepStaging(ctx context.Context, olderThan time.Time, live func(uuid.UUID) (bool, error)) (int, error) {
	var orphans []string
	err := s.pages(ctx, "/secrets", url.Values{}, func(b bundle) error {
		name, _ := splitID(b.ID)
		rest, ok := strings.CutPrefix(name, StagingPrefix)
		if !ok || b.Tags[stagingTag] != "true" || b.Attributes.Created == nil {
			return nil
		}
		if !time.Unix(*b.Attributes.Created, 0).Before(olderThan) {
			return nil
		}
		id, err := uuid.Parse(rest)
		if err != nil {
			return nil
		}
		isLive, err := live(id)
		if err != nil {
			return err
		}
		if !isLive {
			orphans = append(orphans, name)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, name := range orphans {
		if err := s.destroyShadow(ctx, name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
