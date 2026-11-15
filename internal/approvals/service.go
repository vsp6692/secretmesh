// Package approvals implements change requests and the approval state
// machine (gate 3):
//
//	pending ──approve×N──▶ approved ──worker──▶ executing ──▶ succeeded | failed
//	   │                      │
//	   ├─reject──▶ rejected    ├─cancel──▶ cancelled
//	   ├─cancel──▶ cancelled   └─timeout─▶ expired
//	   └─timeout─▶ expired
//
// Submitting stages the proposed value in the provider (ADR-0003) and stores
// only a keyed MAC of it, bound with every other field into a binding hash
// that approvers approve (ADR-0004).
package approvals

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

var (
	ErrNotFound        = errors.New("change request not found")
	ErrForbidden       = errors.New("not permitted")
	ErrConflict        = errors.New("an open change request or secret with this name already exists")
	ErrSelfApproval    = errors.New("requesters cannot decide their own change requests")
	ErrBindingMismatch = errors.New("the change request differs from the one reviewed")
	ErrNotPending      = errors.New("change request is not pending")
	ErrExpired         = errors.New("change request has expired")
	ErrAlreadyDecided  = errors.New("you already decided this change request")
	// ErrBreakGlassDenied: missing break_glass role, MFA session or recent sign-in.
	ErrBreakGlassDenied = errors.New("break-glass requires the break_glass role, an MFA session and a sign-in within 5 minutes")
	// ErrRotationInProgress: the secret is being rotated; changes wait.
	ErrRotationInProgress = errors.New("the secret is being rotated; try again when the rotation finishes")
)

// BreakGlassMaxAuthAge is how recent the sign-in must be for break-glass.
const BreakGlassMaxAuthAge = 5 * time.Minute

// MinBreakGlassReason is the minimum justification length.
const MinBreakGlassReason = 20

// InvalidError reports invalid input.
type InvalidError struct{ Msg string }

func (e InvalidError) Error() string { return e.Msg }

const (
	MaxValueBytes = 64 << 10
	DefaultTTL    = 72 * time.Hour
)

var validName = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,256}$`)

// Jobs enqueues background work in the caller's transaction, so jobs exist
// exactly when the state change commits.
type Jobs interface {
	EnqueueExecution(ctx context.Context, tx pgx.Tx, org, request uuid.UUID) error
	EnqueueDiscard(ctx context.Context, tx pgx.Tx, org, request uuid.UUID) error
}

type ChangeRequest struct {
	ID                uuid.UUID
	OrganizationID    uuid.UUID
	Operation         string
	Status            string
	SecretID          uuid.UUID // zero for create (until executed)
	ConnectionID      uuid.UUID
	EnvironmentID     uuid.UUID
	EnvironmentKind   string
	SecretName        string
	Classification    string
	ProviderRef       string
	StagingRef        string
	StagingVersion    string
	ValueMAC          []byte
	Nonce             []byte
	BindingHash       []byte
	RequiredApprovals int
	Reason            string
	RequestedBy       uuid.UUID
	RequesterTokenID  uuid.UUID
	RequesterMFA      bool
	BreakGlass        bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ExpiresAt         time.Time
	CompletedAt       *time.Time
	FailureCode       string
	ProviderVersionID string
	CloudRequestID    string
	Decisions         []Decision
}

type Decision struct {
	ApproverID   uuid.UUID
	Decision     string
	ApprovedHash []byte
	ApproverMFA  bool
	Comment      string
	CreatedAt    time.Time
}

// Binding reconstructs the approval binding from stored fields.
func (c ChangeRequest) Binding() Binding {
	return Binding{
		OrganizationID: c.OrganizationID, RequestID: c.ID, Operation: c.Operation, SecretID: c.secretIDForBinding(),
		ConnectionID: c.ConnectionID, EnvironmentID: c.EnvironmentID, SecretName: c.SecretName,
		Classification: c.Classification, ProviderRef: c.ProviderRef, StagingRef: c.StagingRef,
		StagingVersion: c.StagingVersion, ValueMAC: c.ValueMAC, Nonce: c.Nonce, ExpiresAt: c.ExpiresAt,
		BreakGlass: c.BreakGlass,
	}
}

// Create requests are bound before the secret exists; the secret ID recorded
// after execution is not part of the binding.
func (c ChangeRequest) secretIDForBinding() uuid.UUID {
	if c.Operation == "create" {
		return uuid.Nil
	}
	return c.SecretID
}

// Target is the provider target of the change.
func (c ChangeRequest) Target() connectors.Target {
	return connectors.Target{ConnectionID: c.ConnectionID, Name: c.SecretName, ProviderRef: c.ProviderRef}
}

func (c ChangeRequest) Staged() connectors.Staged {
	return connectors.Staged{Ref: c.StagingRef, Version: c.StagingVersion}
}

// Permission is the resource permission the operation requires.
func Permission(operation string) auth.Permission {
	switch operation {
	case "create":
		return auth.SecretCreate
	case "update":
		return auth.SecretUpdate
	case "delete":
		return auth.SecretDelete
	}
	return "invalid"
}

const crColumns = `id, organization_id, operation, status, secret_id, connection_id, environment_id, environment_kind,
	secret_name, classification, provider_ref, staging_ref, staging_version, value_mac, nonce, binding_hash,
	required_approvals, reason, requested_by, requester_token_id, requester_mfa, created_at, updated_at, expires_at,
	completed_at, failure_code, provider_version_id, cloud_request_id, break_glass`

func scan(row pgx.Row) (ChangeRequest, error) {
	var c ChangeRequest
	var secretID, tokenID *uuid.UUID
	var providerRef, stagingRef, stagingVersion, failure, version, cloudReq *string
	err := row.Scan(&c.ID, &c.OrganizationID, &c.Operation, &c.Status, &secretID, &c.ConnectionID, &c.EnvironmentID,
		&c.EnvironmentKind, &c.SecretName, &c.Classification, &providerRef, &stagingRef, &stagingVersion, &c.ValueMAC,
		&c.Nonce, &c.BindingHash, &c.RequiredApprovals, &c.Reason, &c.RequestedBy, &tokenID, &c.RequesterMFA,
		&c.CreatedAt, &c.UpdatedAt, &c.ExpiresAt, &c.CompletedAt, &failure, &version, &cloudReq, &c.BreakGlass)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	if secretID != nil {
		c.SecretID = *secretID
	}
	if tokenID != nil {
		c.RequesterTokenID = *tokenID
	}
	c.ProviderRef, c.StagingRef, c.StagingVersion = deref(providerRef), deref(stagingRef), deref(stagingVersion)
	c.FailureCode, c.ProviderVersionID, c.CloudRequestID = deref(failure), deref(version), deref(cloudReq)
	return c, err
}

// LoadTx reads a change request with its decisions; forUpdate locks the row.
func LoadTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, forUpdate bool) (ChangeRequest, error) {
	q := `SELECT ` + crColumns + ` FROM change_requests WHERE organization_id = $1 AND id = $2`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	c, err := scan(tx.QueryRow(ctx, q, org, id))
	if err != nil {
		return c, err
	}
	rows, err := tx.Query(ctx, `SELECT approver_id, decision, approved_hash, approver_mfa, comment, created_at
		FROM approval_decisions WHERE organization_id = $1 AND change_request_id = $2 ORDER BY created_at`, org, id)
	if err != nil {
		return c, err
	}
	c.Decisions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Decision, error) {
		var d Decision
		return d, r.Scan(&d.ApproverID, &d.Decision, &d.ApprovedHash, &d.ApproverMFA, &d.Comment, &d.CreatedAt)
	})
	return c, err
}

// SetStatusTx moves a request from one of the from states to to, returning
// false if it was not in any of them.
func SetStatusTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, to string, from []string, failure string) (bool, error) {
	var failureArg *string
	if failure != "" {
		failureArg = &failure
	}
	tag, err := tx.Exec(ctx, `
		UPDATE change_requests SET status = $3, failure_code = coalesce($5, failure_code), updated_at = now(),
			completed_at = CASE WHEN $3 IN ('rejected', 'cancelled', 'expired', 'succeeded', 'failed') THEN now() ELSE completed_at END
		WHERE organization_id = $1 AND id = $2 AND status = ANY($4)`, org, id, to, from, failureArg)
	return err == nil && tag.RowsAffected() == 1, err
}

type Service struct {
	pool     *pgxpool.Pool
	registry *connectors.Registry
	keyring  keys.Keyring
	jobs     Jobs
	logger   *slog.Logger
	TTL      time.Duration
	Now      func() time.Time
}

func NewService(pool *pgxpool.Pool, registry *connectors.Registry, keyring keys.Keyring, jobs Jobs, logger *slog.Logger) *Service {
	return &Service{pool: pool, registry: registry, keyring: keyring, jobs: jobs, logger: logger, TTL: DefaultTTL, Now: time.Now}
}

// SetJobs sets the job queue (which itself depends on the service).
func (s *Service) SetJobs(j Jobs) { s.jobs = j }

// SubmitInput describes a requested change. Value is required for create and
// update and forbidden for delete.
type SubmitInput struct {
	Operation      string
	SecretID       uuid.UUID // update, delete
	ConnectionID   uuid.UUID // create
	EnvironmentID  uuid.UUID // create
	Name           string    // create
	Classification string    // create
	Value          sensitive.Value
	Reason         string
	// BreakGlass skips prior approval in an emergency (see ADR-0010).
	BreakGlass bool
}

// Submit validates and authorizes the change, stages the value in the
// provider and records the request. Changes that need no approval are
// approved immediately and queued for execution; the worker still enforces
// every gate.
func (s *Service) Submit(ctx context.Context, access auth.Access, in SubmitInput) (ChangeRequest, error) {
	org := access.OrganizationID
	c := ChangeRequest{
		ID: uuid.New(), OrganizationID: org, Operation: in.Operation, Reason: in.Reason,
		RequestedBy: access.Principal.UserID, RequesterTokenID: access.Principal.TokenID,
		RequesterMFA: access.Principal.Kind == auth.KindUser && access.Principal.SessionMFA,
		BreakGlass:   in.BreakGlass,
		Nonce:        make([]byte, 16),
	}
	_, _ = rand.Read(c.Nonce)

	switch {
	case in.Operation != "create" && in.Operation != "update" && in.Operation != "delete":
		return c, InvalidError{"operation must be create, update or delete"}
	case len(in.Reason) > 1000:
		return c, InvalidError{"reason must be at most 1000 characters"}
	case in.Operation == "delete" && !in.Value.IsZero():
		return c, InvalidError{"delete does not take a value"}
	case in.Operation != "delete" && in.Value.IsZero():
		return c, InvalidError{"value is required"}
	case len(in.Value.Reveal()) > MaxValueBytes:
		return c, InvalidError{fmt.Sprintf("value must be at most %d bytes", MaxValueBytes)}
	case in.BreakGlass && len(in.Reason) < MinBreakGlassReason:
		return c, InvalidError{fmt.Sprintf("break-glass changes need a reason of at least %d characters", MinBreakGlassReason)}
	}

	var conn inventory.Connection
	var policy Policy
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if in.Operation == "create" {
			if !validName.MatchString(in.Name) {
				return InvalidError{"name must be 1-256 characters of letters, digits and /_+=.@-"}
			}
			if !inventory.Classification(in.Classification).Valid() {
				return InvalidError{"classification must be internal, confidential or restricted"}
			}
			var kind string
			err := tx.QueryRow(ctx, `SELECT kind FROM environments WHERE organization_id = $1 AND id = $2`,
				org, in.EnvironmentID).Scan(&kind)
			if errors.Is(err, pgx.ErrNoRows) {
				return InvalidError{"unknown environment"}
			}
			if err != nil {
				return err
			}
			c.EnvironmentID, c.EnvironmentKind = in.EnvironmentID, kind
			c.ConnectionID, c.SecretName, c.Classification = in.ConnectionID, in.Name, in.Classification
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM secrets WHERE organization_id = $1
				AND connection_id = $2 AND name = $3 AND status = 'active')`, org, in.ConnectionID, in.Name).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return ErrConflict
			}
		} else {
			sec, err := inventory.SecretTx(ctx, tx, org, in.SecretID)
			if errors.Is(err, inventory.ErrNotFound) || (err == nil && sec.Status != "active") {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			c.SecretID, c.ConnectionID, c.EnvironmentID = sec.ID, sec.ConnectionID, sec.EnvironmentID
			c.EnvironmentKind, c.SecretName = string(sec.EnvironmentKind), sec.Name
			c.Classification, c.ProviderRef = string(sec.Classification), sec.ProviderRef
			var rotating bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rotation_executions WHERE organization_id = $1
				AND secret_id = $2 AND status IN ('scheduled', 'rotating', 'verifying'))`, org, sec.ID).Scan(&rotating); err != nil {
				return err
			}
			if rotating {
				return ErrRotationInProgress
			}
		}
		if !access.CanOn(Permission(in.Operation), c.EnvironmentID) {
			return ErrForbidden
		}
		if in.BreakGlass && (!access.CanOn(auth.SecretBreakGlass, c.EnvironmentID) || !access.Principal.SessionMFA ||
			!access.Principal.AuthenticatedWithin(BreakGlassMaxAuthAge, s.Now())) {
			return ErrBreakGlassDenied
		}
		var err error
		if conn, err = inventory.ConnectionTx(ctx, tx, org, c.ConnectionID); errors.Is(err, inventory.ErrNotFound) {
			return InvalidError{"unknown or disabled connection"}
		} else if err != nil {
			return err
		}
		policy, err = policyTx(ctx, tx, org)
		return err
	})
	if err != nil {
		return c, err
	}

	store, err := s.registry.Store(connectors.Connection{ID: conn.ID, OrganizationID: org, Provider: conn.Provider, Config: conn.Config})
	if err != nil {
		return c, err
	}
	c.ExpiresAt = s.Now().Add(s.TTL).UTC().Truncate(time.Microsecond)
	c.RequiredApprovals = policy.Required(c.EnvironmentKind, c.Operation, c.Classification)
	if c.BreakGlass {
		c.RequiredApprovals = 0
	}
	c.Status = "pending"
	if c.RequiredApprovals == 0 {
		c.Status = "approved"
	}

	if in.Operation != "delete" {
		staged, err := store.Stage(ctx, c.Target(), c.ID, in.Value)
		if err != nil {
			return c, fmt.Errorf("stage value: %w", err)
		}
		c.StagingRef, c.StagingVersion = staged.Ref, staged.Version
		if c.ValueMAC, err = s.keyring.TenantMAC(ctx, org, keys.PurposeValueMAC, in.Value.Reveal()); err != nil {
			s.discard(ctx, store, c)
			return c, err
		}
	}
	c.BindingHash = c.Binding().Hash()

	err = postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO change_requests (id, organization_id, operation, status, secret_id, connection_id, environment_id,
				environment_kind, secret_name, classification, provider_ref, staging_ref, staging_version, value_mac, nonce,
				binding_hash, required_approvals, reason, requested_by, requester_token_id, requester_mfa, expires_at, break_glass)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
			RETURNING created_at, updated_at`,
			c.ID, org, c.Operation, c.Status, nullUUID(c.SecretID), c.ConnectionID, c.EnvironmentID, c.EnvironmentKind,
			c.SecretName, c.Classification, nullString(c.ProviderRef), nullString(c.StagingRef), nullString(c.StagingVersion),
			c.ValueMAC, c.Nonce, c.BindingHash, c.RequiredApprovals, c.Reason, c.RequestedBy, nullUUID(c.RequesterTokenID),
			c.RequesterMFA, c.ExpiresAt, c.BreakGlass).Scan(&c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "change_request.submitted", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.Allow,
			ChangeRequestID: c.ID, Details: map[string]string{
				"operation": c.Operation, "environment_kind": c.EnvironmentKind, "secret_name": c.SecretName,
				"required_approvals": strconv.Itoa(c.RequiredApprovals),
			},
		}); err != nil {
			return err
		}
		if err := notifySubmittedTx(ctx, tx, c); err != nil {
			return err
		}
		if c.Status != "approved" {
			return nil
		}
		ev := audit.Event{
			Action: "change_request.approved", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.Allow,
			ChangeRequestID: c.ID, Details: map[string]string{"approvals": "0", "reason": "no approval required"},
		}
		if c.BreakGlass {
			ev.Action = "change_request.break_glass"
			ev.Details = map[string]string{"environment_kind": c.EnvironmentKind, "justification": c.Reason}
		}
		if _, err := audit.Append(ctx, tx, org, ev); err != nil {
			return err
		}
		return s.jobs.EnqueueExecution(ctx, tx, org, c.ID)
	})
	if err != nil {
		s.discard(ctx, store, c)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return c, ErrConflict
		}
		return c, err
	}
	return c, nil
}

func (c ChangeRequest) resourceID() string {
	if c.SecretID != uuid.Nil {
		return c.SecretID.String()
	}
	return "new:" + c.ConnectionID.String() + "/" + c.SecretName
}

func (s *Service) discard(ctx context.Context, store connectors.SecretStore, c ChangeRequest) {
	if c.StagingRef == "" {
		return
	}
	if err := store.DiscardStaged(ctx, c.Staged()); err != nil {
		s.logger.WarnContext(ctx, "discard staged value", "change_request_id", c.ID, "error", err)
	}
}

// Decide records an approver's decision. The caller must have verified that
// the approver authenticated recently (step-up). The approver must hold
// approval.decide in the request's environment, must not be the requester and
// must present the binding hash they reviewed.
func (s *Service) Decide(ctx context.Context, access auth.Access, id uuid.UUID, approve bool, reviewedHash []byte, comment string) (ChangeRequest, error) {
	org := access.OrganizationID
	var c ChangeRequest
	if access.Principal.Kind != auth.KindUser {
		return c, ErrForbidden
	}
	if len(comment) > 1000 {
		return c, InvalidError{"comment must be at most 1000 characters"}
	}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if c, err = LoadTx(ctx, tx, org, id, true); err != nil {
			return err
		}
		switch {
		case !access.CanOn(auth.ApprovalDecide, c.EnvironmentID):
			return ErrForbidden
		case c.RequestedBy == access.Principal.UserID:
			return ErrSelfApproval
		case c.Status != "pending":
			return ErrNotPending
		case !s.Now().Before(c.ExpiresAt):
			return ErrExpired
		case subtle.ConstantTimeCompare(reviewedHash, c.BindingHash) != 1:
			return ErrBindingMismatch
		}
		decision := "reject"
		if approve {
			decision = "approve"
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO approval_decisions (organization_id, change_request_id, approver_id, decision, approved_hash,
				approver_mfa, approver_auth_time, comment)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			org, id, access.Principal.UserID, decision, reviewedHash, access.Principal.SessionMFA,
			access.Principal.AuthTime, comment)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return ErrAlreadyDecided
		}
		if err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "change_request.decision", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.Allow,
			ChangeRequestID: id, Details: map[string]string{"decision": decision, "mfa": strconv.FormatBool(access.Principal.SessionMFA)},
		}); err != nil {
			return err
		}

		if !approve {
			if _, err := SetStatusTx(ctx, tx, org, id, "rejected", []string{"pending"}, ""); err != nil {
				return err
			}
			c.Status = "rejected"
			if _, err := audit.Append(ctx, tx, org, audit.Event{
				Action: "change_request.rejected", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.Deny,
				ChangeRequestID: id,
			}); err != nil {
				return err
			}
			if err := NotifyOutcomeTx(ctx, tx, c, "was rejected", comment); err != nil {
				return err
			}
			return s.jobs.EnqueueDiscard(ctx, tx, org, id)
		}

		var approvals int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM approval_decisions
			WHERE organization_id = $1 AND change_request_id = $2 AND decision = 'approve'`, org, id).Scan(&approvals); err != nil {
			return err
		}
		if approvals < c.RequiredApprovals {
			return nil
		}
		if _, err := SetStatusTx(ctx, tx, org, id, "approved", []string{"pending"}, ""); err != nil {
			return err
		}
		c.Status = "approved"
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "change_request.approved", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.Allow,
			ChangeRequestID: id, Details: map[string]string{"approvals": strconv.Itoa(approvals)},
		}); err != nil {
			return err
		}
		return s.jobs.EnqueueExecution(ctx, tx, org, id)
	})
	if err != nil {
		return c, err
	}
	return s.Get(ctx, org, id)
}

// Cancel withdraws a pending or approved request. Only the requester (or, for
// a token's request, the token's creator) may cancel.
func (s *Service) Cancel(ctx context.Context, access auth.Access, id uuid.UUID) error {
	org := access.OrganizationID
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := LoadTx(ctx, tx, org, id, true)
		if err != nil {
			return err
		}
		if c.RequestedBy != access.Principal.UserID {
			if access.CanOn(auth.SecretRead, c.EnvironmentID) {
				return ErrForbidden
			}
			return ErrNotFound
		}
		ok, err := SetStatusTx(ctx, tx, org, id, "cancelled", []string{"pending", "approved"}, "")
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotPending
		}
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "change_request.cancelled", ResourceType: "secret", ResourceID: c.resourceID(), Decision: audit.None,
			ChangeRequestID: id,
		}); err != nil {
			return err
		}
		return s.jobs.EnqueueDiscard(ctx, tx, org, id)
	})
}

func (s *Service) Get(ctx context.Context, org, id uuid.UUID) (ChangeRequest, error) {
	var c ChangeRequest
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		c, err = LoadTx(ctx, tx, org, id, false)
		return err
	})
	return c, err
}

// List returns up to 200 requests, newest first, optionally filtered by
// status and to break-glass changes.
func (s *Service) List(ctx context.Context, org uuid.UUID, status string, breakGlassOnly bool) ([]ChangeRequest, error) {
	var out []ChangeRequest
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+crColumns+` FROM change_requests
			WHERE organization_id = $1 AND ($2 = '' OR status = $2) AND (NOT $3 OR break_glass)
			ORDER BY created_at DESC LIMIT 200`, org, status, breakGlassOnly)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ChangeRequest, error) { return scan(r) })
		return err
	})
	return out, err
}

// ExpireDue expires pending and approved requests past their deadline in all
// organizations. Due items are found through a narrow SECURITY DEFINER
// function; each is expired under its own organization's scope.
func (s *Service) ExpireDue(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT organization_id, change_request_id FROM secretmesh_expired_change_requests(100)`)
	if err != nil {
		return 0, err
	}
	type item struct{ org, id uuid.UUID }
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var i item
		return i, r.Scan(&i.org, &i.id)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		ctx := postgres.WithScope(ctx, postgres.Scope{OrganizationID: it.org})
		err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE change_requests SET status = 'expired', updated_at = now(), completed_at = now()
				WHERE organization_id = $1 AND id = $2 AND status IN ('pending', 'approved') AND expires_at <= now()`, it.org, it.id)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			n++
			if _, err := audit.Append(ctx, tx, it.org, audit.Event{
				Action: "change_request.expired", ResourceType: "change_request", ResourceID: it.id.String(),
				Decision: audit.Deny, ChangeRequestID: it.id,
			}); err != nil {
				return err
			}
			c, err := LoadTx(ctx, tx, it.org, it.id, false)
			if err != nil {
				return err
			}
			if err := NotifyOutcomeTx(ctx, tx, c, "expired", ""); err != nil {
				return err
			}
			return s.jobs.EnqueueDiscard(ctx, tx, it.org, it.id)
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// DiscardStaging destroys the staged value of a request that can no longer
// execute. It is idempotent.
func (s *Service) DiscardStaging(ctx context.Context, org, id uuid.UUID) error {
	return DiscardStaging(ctx, s.pool, s.registry, org, id)
}

// DiscardStaging destroys the staged value of a terminal request.
func DiscardStaging(ctx context.Context, pool *pgxpool.Pool, registry *connectors.Registry, org, id uuid.UUID) error {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	var c ChangeRequest
	var conn inventory.Connection
	err := postgres.Tx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		if c, err = LoadTx(ctx, tx, org, id, false); err != nil {
			return err
		}
		conn, err = inventory.ConnectionTx(ctx, tx, org, c.ConnectionID)
		return err
	})
	if err != nil {
		return err
	}
	switch c.Status {
	case "rejected", "cancelled", "expired", "failed", "succeeded":
	default:
		return nil // still live
	}
	if c.StagingRef == "" {
		return nil
	}
	store, err := registry.Store(connectors.Connection{ID: conn.ID, OrganizationID: org, Provider: conn.Provider, Config: conn.Config})
	if err != nil {
		return err
	}
	if err := store.DiscardStaged(ctx, c.Staged()); err != nil && !errors.Is(err, connectors.ErrNotFound) {
		return err
	}
	return nil
}

func policyTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) (Policy, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT rules FROM approval_policies WHERE organization_id = $1`, org).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPolicy, nil
	}
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p.Rules); err != nil {
		return Policy{}, fmt.Errorf("stored approval policy: %w", err)
	}
	return p, nil
}

// PolicyTx returns the organization's approval policy (the default if unset).
func PolicyTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) (Policy, error) {
	return policyTx(ctx, tx, org)
}

func (s *Service) Policy(ctx context.Context, org uuid.UUID) (Policy, error) {
	var p Policy
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		p, err = policyTx(ctx, tx, org)
		return err
	})
	return p, err
}

func (s *Service) SetPolicy(ctx context.Context, org, by uuid.UUID, p Policy) error {
	if err := p.Validate(); err != nil {
		return InvalidError{err.Error()}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	raw, _ := json.Marshal(p.Rules)
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO approval_policies (organization_id, rules, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id) DO UPDATE SET rules = EXCLUDED.rules, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			org, raw, by); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "approval_policy.updated", ResourceType: "approval_policy", ResourceID: org.String(), Decision: audit.Allow,
			Details: map[string]string{"rules": string(raw)},
		})
		return err
	})
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
