package httpapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	awsconn "github.com/secretmesh/secretmesh/internal/connectors/aws"
	azureconn "github.com/secretmesh/secretmesh/internal/connectors/azure"
	gcpconn "github.com/secretmesh/secretmesh/internal/connectors/gcp"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/tenancy"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ---- Environments and connections ----

func (a *api) ListEnvironments(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgRead); !ok {
		return
	}
	envs, err := a.d.Inventory.Environments(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list environments", err)
		return
	}
	out := make([]Environment, 0, len(envs))
	for _, e := range envs {
		out = append(out, Environment{Id: e.ID, Name: e.Name, Kind: EnvironmentKind(e.Kind), CreatedAt: e.CreatedAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"environments": out})
}

func (a *api) CreateEnvironment(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgWrite); !ok {
		return
	}
	var body CreateEnvironment
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	kind := inventory.EnvironmentKind(body.Kind)
	if !kind.Valid() || !slugRE.MatchString(body.Name) {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "name must be a lower-case slug and kind development, staging or production")
		return
	}
	e, err := a.d.Inventory.CreateEnvironment(r.Context(), orgID, body.Name, kind)
	if errors.Is(err, inventory.ErrConflict) {
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "an environment with this name exists")
		return
	}
	if err != nil {
		a.internal(w, r, "create environment", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, Environment{Id: e.ID, Name: e.Name, Kind: EnvironmentKind(e.Kind), CreatedAt: e.CreatedAt})
}

func (a *api) connectionJSON(c inventory.Connection, orgID uuid.UUID) Connection {
	out := Connection{Id: c.ID, Name: c.Name, Provider: c.Provider, Config: c.Config, Status: c.Status,
		CreatedAt: c.CreatedAt, DefaultEnvironmentId: c.DefaultEnvironmentID, LastSyncedAt: c.LastSyncedAt,
		LastSyncError: c.LastSyncError}
	if store, err := a.d.Connectors.Store(connectors.Connection{ID: c.ID, OrganizationID: orgID, Provider: c.Provider, Config: c.Config}); err == nil {
		caps := store.Capabilities()
		out.Capabilities = &Capabilities{SecretCreate: caps.SecretCreate, SecretUpdate: caps.SecretUpdate,
			SecretDelete: caps.SecretDelete, SecretReveal: caps.SecretReveal, Discovery: caps.Discovery,
			Versioning: caps.Versioning, VersionLabels: caps.VersionLabels, SoftDelete: caps.SoftDelete,
			NativeRotation: caps.NativeRotation, Tags: caps.Tags, UpdateStaging: caps.UpdateStaging,
			CreateStaging: caps.CreateStaging}
	}
	return out
}

func (a *api) ListConnections(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgRead); !ok {
		return
	}
	conns, err := a.d.Inventory.Connections(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list connections", err)
		return
	}
	out := make([]Connection, 0, len(conns))
	for _, c := range conns {
		out = append(out, a.connectionJSON(c, orgID))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"connections": out})
}

func (a *api) CreateConnection(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorizeOn(w, r, orgID, auth.ConnectionManage, uuid.Nil)
	if !ok {
		return
	}
	var body CreateConnection
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if !a.requireStepUp(w, r, access) {
		return
	}
	if !slugRE.MatchString(body.Name) {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "name must be a lower-case slug")
		return
	}
	if !a.d.Connectors.Enabled(string(body.Provider)) {
		httpx.WriteError(w, r, http.StatusBadRequest, "provider_unavailable", "provider "+string(body.Provider)+" is not available in this deployment")
		return
	}
	config := map[string]string{}
	if body.Config != nil {
		for k, v := range *body.Config {
			config[k] = v
		}
	}
	for k := range config {
		// Connections authenticate with workload identity; never accept credentials.
		if looksLikeCredential(k) {
			httpx.WriteError(w, r, http.StatusBadRequest, "invalid_config", "connection config must not contain credentials ("+k+")")
			return
		}
	}
	if p, ok := providerConfigs[body.Provider]; ok {
		// SecretMesh generates the external ID that proves, on the provider
		// side, that the customer set the connection up for this deployment.
		if _, ok := config["external_id"]; ok {
			httpx.WriteError(w, r, http.StatusBadRequest, "invalid_config", "external_id is generated by SecretMesh")
			return
		}
		config["external_id"] = p.newExternalID()
		if err := p.validate(config); err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, "invalid_config", err.Error())
			return
		}
	}
	c, err := a.d.Inventory.CreateConnection(r.Context(), orgID, body.Name, string(body.Provider), config, body.DefaultEnvironmentId)
	if errors.Is(err, inventory.ErrUnknownEnvironment) {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "unknown default environment")
		return
	}
	if errors.Is(err, inventory.ErrConflict) {
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "a connection with this name exists")
		return
	}
	if err != nil {
		a.internal(w, r, "create connection", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a.connectionJSON(c, orgID))
}

func (a *api) GetConnection(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgRead); !ok {
		return
	}
	c, err := a.d.Inventory.Connection(r.Context(), orgID, id)
	if errors.Is(err, inventory.ErrNotFound) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "get connection", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.connectionJSON(c, orgID))
}

func (a *api) SyncConnection(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	if _, ok := a.authorizeOn(w, r, orgID, auth.ConnectionManage, uuid.Nil); !ok {
		return
	}
	if a.d.Discovery == nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "unsupported", "discovery is not enabled in this deployment")
		return
	}
	res, err := a.d.Discovery.Sync(r.Context(), orgID, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		notFound(w, r)
		return
	case errors.Is(err, inventory.ErrDiscoveryUnsupported):
		httpx.WriteError(w, r, http.StatusBadRequest, "unsupported", "this provider does not support discovery")
		return
	case err != nil:
		a.providerError(w, r, "sync connection", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, SyncResult{Rotated: res.Rotated, Imported: res.Imported, Updated: res.Updated, Removed: res.Removed, Unassigned: res.Unassigned})
}

// providerError maps connector errors without echoing provider messages,
// which can contain account details.
func (a *api) providerError(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, connectors.ErrAccessDenied):
		httpx.WriteError(w, r, http.StatusBadGateway, "provider_access_denied", "the provider denied access; check the connection's identity, trust setup, ExternalId and permissions")
	case errors.Is(err, connectors.ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "provider_not_found", "not found in the provider")
	case errors.Is(err, connectors.ErrTransient):
		a.d.Logger.WarnContext(r.Context(), what, "error", err)
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "the provider is temporarily unavailable")
	case errors.Is(err, connectors.ErrProviderUnavailable):
		httpx.WriteError(w, r, http.StatusBadRequest, "provider_unavailable", "the connection's provider is not available in this deployment")
	default:
		a.internal(w, r, what, err)
	}
}

// providerConfigs holds, per cloud provider, how a new connection's config is
// completed and validated.
var providerConfigs = map[CreateConnectionProvider]struct {
	newExternalID func() string
	validate      func(map[string]string) error
}{
	Aws:   {awsconn.NewExternalID, awsconn.ValidateConfig},
	Azure: {azureconn.NewExternalID, azureconn.ValidateConfig},
	Gcp:   {gcpconn.NewExternalID, gcpconn.ValidateConfig},
}

// looksLikeCredential reports config keys that could hold credentials.
// Identifiers of keys (key IDs, ARNs) are allowed.
func looksLikeCredential(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"secret", "password", "passwd", "token", "credential", "private", "auth"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return (strings.HasSuffix(k, "key") || strings.HasSuffix(k, "key_value")) &&
		!strings.HasSuffix(k, "key_id") && !strings.HasSuffix(k, "key_arn")
}

// ---- Role bindings ----

func roleBindingJSON(b tenancy.RoleBinding) RoleBinding {
	return RoleBinding{Id: b.ID, UserId: b.UserID, Email: b.Email, Role: BindingRole(b.Role),
		EnvironmentId: b.EnvironmentID, CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt}
}

func (a *api) ListRoleBindings(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.MembersRead); !ok {
		return
	}
	bs, err := a.d.Tenancy.RoleBindings(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list role bindings", err)
		return
	}
	out := make([]RoleBinding, 0, len(bs))
	for _, b := range bs {
		out = append(out, roleBindingJSON(b))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"role_bindings": out})
}

func (a *api) CreateRoleBinding(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.MembersWrite)
	if !ok {
		return
	}
	var body CreateRoleBinding
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	// Granting access is privilege management: people only, recently authenticated.
	if !a.requireStepUp(w, r, access) {
		return
	}
	role := auth.BindingRole(body.Role)
	if !role.Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "unknown role")
		return
	}
	env := uuid.Nil
	if body.EnvironmentId != nil {
		env = *body.EnvironmentId
	}
	b, err := a.d.Tenancy.AddBinding(r.Context(), orgID, body.UserId, role, env, access.Principal.UserID)
	switch {
	case errors.Is(err, tenancy.ErrConflict):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "this binding already exists")
		return
	case errors.Is(err, tenancy.ErrNotFound):
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "user is not a member or environment does not exist")
		return
	case err != nil:
		a.internal(w, r, "create role binding", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, roleBindingJSON(b))
}

func (a *api) DeleteRoleBinding(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	if _, ok := a.authorize(w, r, orgID, auth.MembersWrite); !ok {
		return
	}
	err := a.d.Tenancy.RemoveBinding(r.Context(), orgID, id)
	if errors.Is(err, tenancy.ErrNotFound) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "remove role binding", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Approval policy ----

func policyJSON(p approvals.Policy) ApprovalPolicy {
	out := ApprovalPolicy{Rules: make([]ApprovalRule, 0, len(p.Rules))}
	for _, r := range p.Rules {
		out.Rules = append(out.Rules, ApprovalRule{
			Environment: ApprovalRuleEnvironment(r.Environment), Operation: ApprovalRuleOperation(r.Operation),
			Classification: ApprovalRuleClassification(r.Classification), RequiredApprovals: r.RequiredApprovals,
		})
	}
	return out
}

func (a *api) GetApprovalPolicy(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgRead); !ok {
		return
	}
	p, err := a.d.Approvals.Policy(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "get approval policy", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, policyJSON(p))
}

func (a *api) UpdateApprovalPolicy(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorizeOn(w, r, orgID, auth.PolicyManage, uuid.Nil)
	if !ok {
		return
	}
	var body ApprovalPolicy
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if !a.requireStepUp(w, r, access) {
		return
	}
	p := approvals.Policy{Rules: make([]approvals.Rule, 0, len(body.Rules))}
	for _, rule := range body.Rules {
		p.Rules = append(p.Rules, approvals.Rule{
			Environment: string(rule.Environment), Operation: string(rule.Operation),
			Classification: string(rule.Classification), RequiredApprovals: rule.RequiredApprovals,
		})
	}
	if err := a.d.Approvals.SetPolicy(r.Context(), orgID, access.Principal.UserID, p); err != nil {
		a.changeError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, policyJSON(p))
}

// ---- Secrets ----

func secretJSON(s inventory.Secret) Secret {
	origin := SecretOrigin(s.Origin)
	out := Secret{Id: s.ID, ConnectionId: s.ConnectionID, EnvironmentId: s.EnvironmentID,
		EnvironmentKind: EnvironmentKind(s.EnvironmentKind), Name: s.Name, ProviderRef: s.ProviderRef,
		Classification: Classification(s.Classification), CurrentVersion: s.CurrentVersion, Status: s.Status,
		Origin: &origin, LastSeenAt: s.LastSeenAt, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
		OwnerUserId: s.OwnerUserID, LastRotatedAt: s.LastRotatedAt, RotationEnabled: s.RotationEnabled,
		NextRotationAt: s.NextRotationAt}
	if s.RotationStrategy != nil {
		st := RotationStrategy(*s.RotationStrategy)
		out.RotationStrategy = &st
	}
	if s.Description != "" {
		out.Description = &s.Description
	}
	if len(s.Tags) > 0 {
		out.Tags = &s.Tags
	}
	if len(s.ProviderMetadata) > 0 {
		out.ProviderMetadata = &s.ProviderMetadata
	}
	return out
}

// readableSecret loads a secret the caller may read, or writes 404.
func (a *api) readableSecret(w http.ResponseWriter, r *http.Request, access auth.Access, id uuid.UUID) (inventory.Secret, bool) {
	s, err := a.d.Inventory.Secret(r.Context(), access.OrganizationID, id)
	if errors.Is(err, inventory.ErrNotFound) || (err == nil && (!access.CanOn(auth.SecretRead, s.EnvironmentID) || s.Status != "active")) {
		notFound(w, r)
		return s, false
	}
	if err != nil {
		a.internal(w, r, "get secret", err)
		return s, false
	}
	return s, true
}

func (a *api) secretStore(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, s inventory.Secret) (connectors.SecretStore, bool) {
	conn, err := a.d.Inventory.Connection(r.Context(), orgID, s.ConnectionID)
	if err != nil {
		a.internal(w, r, "load connection", err)
		return nil, false
	}
	store, err := a.d.Connectors.Store(connectors.Connection{ID: conn.ID, OrganizationID: orgID, Provider: conn.Provider, Config: conn.Config})
	if err != nil {
		a.providerError(w, r, "connector", err)
		return nil, false
	}
	return store, true
}

func (a *api) ListSecretVersions(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	s, ok := a.readableSecret(w, r, access, id)
	if !ok {
		return
	}
	store, ok := a.secretStore(w, r, orgID, s)
	if !ok {
		return
	}
	versions, err := store.Versions(r.Context(), connectors.Target{ConnectionID: s.ConnectionID, Name: s.Name, ProviderRef: s.ProviderRef})
	if err != nil {
		a.providerError(w, r, "list versions", err)
		return
	}
	out := make([]SecretVersion, 0, len(versions))
	for _, v := range versions {
		stages := v.Stages
		if stages == nil {
			stages = []string{}
		}
		out = append(out, SecretVersion{Id: v.ID, Stages: stages, CreatedAt: v.CreatedAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"versions": out})
}

// RevealSecret is the only endpoint that returns a secret value. It requires
// secret.reveal, a recent sign-in and, for production or restricted secrets,
// an MFA session. The value is fetched from the provider, the reveal is
// audited (without the value), and only then is the value returned.
func (a *api) RevealSecret(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	s, ok := a.readableSecret(w, r, access, id)
	if !ok {
		return
	}
	if !access.CanOn(auth.SecretReveal, s.EnvironmentID) {
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "missing permission secret.reveal")
		return
	}
	if !a.requireStepUp(w, r, access) {
		return
	}
	if (s.EnvironmentKind == inventory.Production || s.Classification == inventory.Restricted) && !access.Principal.SessionMFA {
		httpx.WriteError(w, r, http.StatusForbidden, "mfa_required", "revealing production or restricted secrets requires an MFA sign-in")
		return
	}
	store, ok := a.secretStore(w, r, orgID, s)
	if !ok {
		return
	}
	if !store.Capabilities().SecretReveal {
		httpx.WriteError(w, r, http.StatusBadRequest, "unsupported", "this provider does not support reveal")
		return
	}
	value, version, err := store.Reveal(r.Context(), connectors.Target{ConnectionID: s.ConnectionID, Name: s.Name, ProviderRef: s.ProviderRef})
	defer value.Wipe()
	if err != nil {
		a.providerError(w, r, "reveal secret", err)
		return
	}
	err = postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		_, err := audit.Append(r.Context(), tx, orgID, audit.Event{
			Action: "secret.revealed", ResourceType: "secret", ResourceID: s.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"version_id": version, "mfa": fmt.Sprint(access.Principal.SessionMFA)},
		})
		return err
	})
	if err != nil {
		a.internal(w, r, "audit reveal", err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "secret revealed", "organization_id", orgID, "secret_id", s.ID, "user_id", access.Principal.UserID)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"value": value.RevealString(), "version_id": version})
}

func (a *api) ListSecrets(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	secrets, err := a.d.Inventory.Secrets(r.Context(), orgID)
	if err != nil {
		a.internal(w, r, "list secrets", err)
		return
	}
	out := make([]Secret, 0, len(secrets))
	for _, s := range secrets {
		if access.CanOn(auth.SecretRead, s.EnvironmentID) {
			out = append(out, secretJSON(s))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

func (a *api) GetSecret(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	s, ok := a.readableSecret(w, r, access, id)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, secretJSON(s))
}

// ---- Change requests ----

func changeRequestJSON(c approvals.ChangeRequest) ChangeRequest {
	opt := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	optID := func(id uuid.UUID) *uuid.UUID {
		if id == uuid.Nil {
			return nil
		}
		return &id
	}
	out := ChangeRequest{
		Id: c.ID, Operation: ChangeRequestOperation(c.Operation), Status: ChangeRequestStatus(c.Status),
		SecretId: optID(c.SecretID), ConnectionId: c.ConnectionID, EnvironmentId: c.EnvironmentID,
		EnvironmentKind: EnvironmentKind(c.EnvironmentKind), SecretName: c.SecretName,
		Classification: Classification(c.Classification), BindingHash: hex.EncodeToString(c.BindingHash),
		RequiredApprovals: c.RequiredApprovals, BreakGlass: &c.BreakGlass, Reason: opt(c.Reason), RequestedBy: c.RequestedBy,
		RequesterTokenId: optID(c.RequesterTokenID), CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		ExpiresAt: c.ExpiresAt, CompletedAt: c.CompletedAt, FailureCode: opt(c.FailureCode),
		ProviderVersionId: opt(c.ProviderVersionID), CloudRequestId: opt(c.CloudRequestID),
		Decisions: make([]Decision, 0, len(c.Decisions)),
	}
	for _, d := range c.Decisions {
		out.Decisions = append(out.Decisions, Decision{ApproverId: d.ApproverID, Decision: DecisionDecision(d.Decision),
			Mfa: d.ApproverMFA, Comment: opt(d.Comment), CreatedAt: d.CreatedAt})
	}
	return out
}

func (a *api) changeError(w http.ResponseWriter, r *http.Request, err error) {
	var invalid approvals.InvalidError
	switch {
	case errors.As(err, &invalid):
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", invalid.Msg)
	case errors.Is(err, approvals.ErrNotFound):
		notFound(w, r)
	case errors.Is(err, approvals.ErrForbidden):
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "not permitted in this environment")
	case errors.Is(err, approvals.ErrRotationInProgress):
		httpx.WriteError(w, r, http.StatusConflict, "rotation_in_progress", err.Error())
	case errors.Is(err, approvals.ErrBreakGlassDenied):
		httpx.WriteError(w, r, http.StatusForbidden, "break_glass_denied", err.Error())
	case errors.Is(err, approvals.ErrSelfApproval):
		httpx.WriteError(w, r, http.StatusForbidden, "self_approval", err.Error())
	case errors.Is(err, approvals.ErrConflict):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, approvals.ErrBindingMismatch):
		httpx.WriteError(w, r, http.StatusConflict, "binding_mismatch", err.Error())
	case errors.Is(err, approvals.ErrNotPending):
		httpx.WriteError(w, r, http.StatusConflict, "not_pending", err.Error())
	case errors.Is(err, approvals.ErrExpired):
		httpx.WriteError(w, r, http.StatusConflict, "expired", err.Error())
	case errors.Is(err, approvals.ErrAlreadyDecided):
		httpx.WriteError(w, r, http.StatusConflict, "already_decided", err.Error())
	case errors.Is(err, connectors.ErrProviderUnavailable):
		httpx.WriteError(w, r, http.StatusBadRequest, "provider_unavailable", "the connection's provider is not available in this deployment")
	default:
		a.internal(w, r, "change request", err)
	}
}

func (a *api) ListChangeRequests(w http.ResponseWriter, r *http.Request, orgID OrgId, params ListChangeRequestsParams) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	status := ""
	if params.Status != nil {
		status = string(*params.Status)
	}
	crs, err := a.d.Approvals.List(r.Context(), orgID, status, params.BreakGlass != nil && *params.BreakGlass)
	if err != nil {
		a.internal(w, r, "list change requests", err)
		return
	}
	out := make([]ChangeRequest, 0, len(crs))
	for _, c := range crs {
		if access.CanOn(auth.SecretRead, c.EnvironmentID) {
			out = append(out, changeRequestJSON(c))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"change_requests": out})
}

func (a *api) GetChangeRequest(w http.ResponseWriter, r *http.Request, orgID OrgId, id ChangeRequestId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	c, err := a.d.Approvals.Get(r.Context(), orgID, id)
	if err == nil && !access.CanOn(auth.SecretRead, c.EnvironmentID) {
		err = approvals.ErrNotFound
	}
	if err != nil {
		a.changeError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, changeRequestJSON(c))
}

func (a *api) CreateChangeRequest(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	// Decoded into sensitive.Value directly; the generated type would hold
	// the value in a plain string.
	var body struct {
		Operation      string          `json:"operation"`
		SecretID       uuid.UUID       `json:"secret_id"`
		ConnectionID   uuid.UUID       `json:"connection_id"`
		EnvironmentID  uuid.UUID       `json:"environment_id"`
		Name           string          `json:"name"`
		Classification string          `json:"classification"`
		Value          sensitive.Value `json:"value"`
		Reason         string          `json:"reason"`
		BreakGlass     bool            `json:"break_glass"`
	}
	defer body.Value.Wipe()
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	c, err := a.d.Approvals.Submit(r.Context(), access, approvals.SubmitInput{
		Operation: body.Operation, SecretID: body.SecretID, ConnectionID: body.ConnectionID,
		EnvironmentID: body.EnvironmentID, Name: body.Name, Classification: body.Classification,
		Value: body.Value, Reason: body.Reason, BreakGlass: body.BreakGlass,
	})
	if err != nil {
		a.changeError(w, r, err)
		return
	}
	a.d.Logger.InfoContext(r.Context(), "change request submitted", "organization_id", orgID,
		"change_request_id", c.ID, "operation", c.Operation, "status", c.Status)
	httpx.WriteJSON(w, http.StatusCreated, changeRequestJSON(c))
}

func (a *api) DecideChangeRequest(w http.ResponseWriter, r *http.Request, orgID OrgId, id ChangeRequestId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	var body DecideChangeRequest
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	hash, err := hex.DecodeString(body.BindingHash)
	if err != nil || len(hash) != 32 {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "binding_hash must be 64 hex characters")
		return
	}
	if body.Decision != DecideChangeRequestDecisionApprove && body.Decision != DecideChangeRequestDecisionReject {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "decision must be approve or reject")
		return
	}
	// Approvers authenticate independently and recently.
	if !a.requireStepUp(w, r, access) {
		return
	}
	comment := ""
	if body.Comment != nil {
		comment = *body.Comment
	}
	c, err := a.d.Approvals.Decide(r.Context(), access, id, body.Decision == DecideChangeRequestDecisionApprove, hash, comment)
	if err != nil {
		a.changeError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, changeRequestJSON(c))
}

func (a *api) CancelChangeRequest(w http.ResponseWriter, r *http.Request, orgID OrgId, id ChangeRequestId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	if err := a.d.Approvals.Cancel(r.Context(), access, id); err != nil {
		a.changeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Audit ----

func (a *api) ListAuditEvents(w http.ResponseWriter, r *http.Request, orgID OrgId, params ListAuditEventsParams) {
	if _, ok := a.authorizeOn(w, r, orgID, auth.AuditRead, uuid.Nil); !ok {
		return
	}
	limit := 100
	if params.Limit != nil {
		limit = min(max(*params.Limit, 1), 500)
	}
	var before int64
	if params.Before != nil {
		before = *params.Before
	}
	var recs []audit.Record
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		var err error
		recs, err = audit.List(r.Context(), tx, orgID, before, limit)
		return err
	})
	if err != nil {
		a.internal(w, r, "list audit events", err)
		return
	}
	optID := func(id uuid.UUID) *uuid.UUID {
		if id == uuid.Nil {
			return nil
		}
		return &id
	}
	out := make([]AuditEvent, 0, len(recs))
	for _, e := range recs {
		ev := AuditEvent{
			Seq: e.Seq, Id: e.ID, OccurredAt: e.OccurredAt, ActorType: AuditEventActorType(e.ActorType),
			ActorId: optID(e.ActorID), ActorTokenId: optID(e.ActorTokenID), Action: e.Action,
			ResourceType: e.ResourceType, ResourceId: e.ResourceID, Decision: AuditEventDecision(e.Decision),
			ChangeRequestId: optID(e.ChangeRequestID), Details: e.Details,
			PrevHash: hex.EncodeToString(e.PrevHash), Hash: hex.EncodeToString(e.Hash),
		}
		if e.CloudRequestID != "" {
			ev.CloudRequestId = &e.CloudRequestID
		}
		out = append(out, ev)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (a *api) VerifyAudit(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorizeOn(w, r, orgID, auth.AuditRead, uuid.Nil); !ok {
		return
	}
	var rep audit.Report
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		var err error
		rep, err = audit.Verify(r.Context(), tx, a.d.Keyring, orgID)
		return err
	})
	if err != nil {
		a.internal(w, r, "verify audit chain", err)
		return
	}
	out := AuditVerification{Valid: rep.Valid, EventsChecked: rep.EventsChecked, HeadSeq: rep.HeadSeq,
		CheckpointsVerified: rep.CheckpointsVerified}
	if len(rep.HeadHash) > 0 {
		h := hex.EncodeToString(rep.HeadHash)
		out.HeadHash = &h
	}
	if rep.LastCheckpointSeq > 0 {
		out.LastCheckpointSeq = &rep.LastCheckpointSeq
	}
	if !rep.Valid {
		out.FirstInvalidSeq, out.Problem = &rep.FirstInvalidSeq, &rep.Problem
	}
	var exported *int64
	err = postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT max(to_seq) FROM audit_exports WHERE organization_id = $1`, orgID).Scan(&exported)
	})
	if err != nil {
		a.internal(w, r, "read audit exports", err)
		return
	}
	out.LastExportedSeq = exported
	httpx.WriteJSON(w, http.StatusOK, out)
}
