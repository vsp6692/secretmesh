// Package execution runs approved change requests against providers (the
// worker side of gates 1-4, ADR-0006/0007).
//
// Before every provider call it rebuilds the policy input from the database,
// re-checking identity, authorization and approvals, and evaluates the OPA
// execution policy. It writes an intent row to the execution journal first,
// verifies the staged value against its approved MAC, uses the journal ID as
// the provider idempotency key, and records the result together with its
// audit event. After a crash or lost response, the journal lets it look up
// what the provider actually did before trying again.
package execution

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/policy"
	"github.com/secretmesh/secretmesh/internal/tenancy"
)

type Executor struct {
	pool     *pgxpool.Pool
	registry *connectors.Registry
	keyring  keys.Keyring
	policy   *policy.Engine
	logger   *slog.Logger
	Now      func() time.Time
}

func NewExecutor(pool *pgxpool.Pool, registry *connectors.Registry, keyring keys.Keyring, engine *policy.Engine, logger *slog.Logger) *Executor {
	return &Executor{pool: pool, registry: registry, keyring: keyring, policy: engine, logger: logger, Now: time.Now}
}

// plan is what the decision transaction hands to the provider phase.
type plan struct {
	req       approvals.ChangeRequest
	conn      inventory.Connection
	journalID uuid.UUID
	resume    bool
}

// Execute runs one change request. It is safe to call repeatedly and
// concurrently: only an approved request starts, and an executing one resumes
// through the journal. A returned error means "retry later".
func (e *Executor) Execute(ctx context.Context, org, id uuid.UUID) error {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})

	var p *plan
	var denied *denial
	err := postgres.Tx(ctx, e.pool, func(tx pgx.Tx) error {
		c, err := approvals.LoadTx(ctx, tx, org, id, true)
		if errors.Is(err, approvals.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		conn, err := inventory.ConnectionTx(ctx, tx, org, c.ConnectionID)
		if err != nil && !errors.Is(err, inventory.ErrNotFound) {
			return err
		}

		switch c.Status {
		case "approved":
			if errors.Is(err, inventory.ErrNotFound) {
				denied = &denial{code: "connection_unavailable"}
				return e.failTx(ctx, tx, c, uuid.Nil, *denied)
			}
			if d, err := e.check(ctx, tx, c, conn); err != nil || d != nil {
				if err != nil {
					return err
				}
				denied = d
				return e.failTx(ctx, tx, c, uuid.Nil, *d)
			}
			journalID := uuid.New()
			if _, err := tx.Exec(ctx, `INSERT INTO execution_journal (id, organization_id, change_request_id, operation, status)
				VALUES ($1, $2, $3, $4, 'intent')`, journalID, org, id, c.Operation); err != nil {
				return err
			}
			if ok, err := approvals.SetStatusTx(ctx, tx, org, id, "executing", []string{"approved"}, ""); err != nil || !ok {
				return errors.Join(err, errors.New("change request changed concurrently"))
			}
			if _, err := audit.Append(ctx, tx, org, audit.Event{
				Action: "change_request.execution_started", ResourceType: "secret", ResourceID: resourceID(c),
				Decision: audit.Allow, ChangeRequestID: id, Details: map[string]string{"journal_id": journalID.String()},
			}); err != nil {
				return err
			}
			p = &plan{req: c, conn: conn, journalID: journalID}
		case "executing":
			var journalID uuid.UUID
			var status string
			if err := tx.QueryRow(ctx, `SELECT id, status FROM execution_journal
				WHERE organization_id = $1 AND change_request_id = $2`, org, id).Scan(&journalID, &status); err != nil {
				return fmt.Errorf("journal for executing request: %w", err)
			}
			if status != "intent" {
				return nil // already settled
			}
			p = &plan{req: c, conn: conn, journalID: journalID, resume: true}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if denied != nil {
		e.logger.WarnContext(ctx, "change request denied at execution", "change_request_id", id, "code", denied.code, "reasons", strings.Join(denied.reasons, ","))
		e.discard(ctx, org, id)
		return nil
	}
	if p == nil {
		return nil
	}
	if err := e.run(ctx, *p); err != nil {
		return err
	}
	// The staged value is no longer needed whether the request succeeded or
	// failed. Done after commit so a provider error never undoes the result.
	e.discard(ctx, org, id)
	return nil
}

func (e *Executor) run(ctx context.Context, p plan) error {
	c := p.req
	store, err := e.registry.Store(connectors.Connection{ID: p.conn.ID, OrganizationID: c.OrganizationID, Provider: p.conn.Provider, Config: p.conn.Config})
	if err != nil {
		return e.fail(ctx, c, p.journalID, denial{code: "connection_unavailable"})
	}
	target := c.Target()

	if p.resume {
		res, found, err := store.LookupOperation(ctx, connectors.Operation{
			Kind: c.Operation, Target: target, Staged: c.Staged(), Key: p.journalID})
		if err != nil {
			return fmt.Errorf("look up provider operation: %w", err)
		}
		if found {
			return e.complete(ctx, c, p.journalID, res, true)
		}
		// Not applied. Only retry while the approval is still valid.
		if !e.Now().Before(c.ExpiresAt) {
			return e.fail(ctx, c, p.journalID, denial{code: "expired_during_execution"})
		}
	}

	var res connectors.Result
	if c.Operation == "delete" {
		res, err = store.Delete(ctx, target, p.journalID)
	} else {
		value, rerr := store.ReadStaged(ctx, c.Staged())
		if errors.Is(rerr, connectors.ErrNotFound) {
			return e.fail(ctx, c, p.journalID, denial{code: "staged_value_missing"})
		}
		if rerr != nil {
			return fmt.Errorf("read staged value: %w", rerr)
		}
		mac, merr := e.keyring.TenantMAC(ctx, c.OrganizationID, keys.PurposeValueMAC, value.Reveal())
		value.Wipe()
		if merr != nil {
			return merr
		}
		if !hmac.Equal(mac, c.ValueMAC) {
			return e.fail(ctx, c, p.journalID, denial{code: "staged_value_tampered"})
		}
		res, err = store.Promote(ctx, target, c.Staged(), p.journalID)
	}
	if err != nil {
		if errors.Is(err, connectors.ErrNotFound) {
			return e.fail(ctx, c, p.journalID, denial{code: "provider_target_missing"})
		}
		if errors.Is(err, connectors.ErrConflict) {
			return e.fail(ctx, c, p.journalID, denial{code: "provider_conflict"})
		}
		// Possibly applied: retry, which resumes through the journal.
		return fmt.Errorf("provider operation: %w", err)
	}
	return e.complete(ctx, c, p.journalID, res, false)
}

type denial struct {
	code    string
	reasons []string
}

// check evaluates gates 1-4 against current database state. It returns a
// denial when execution must not proceed.
func (e *Executor) check(ctx context.Context, tx pgx.Tx, c approvals.ChangeRequest, conn inventory.Connection) (*denial, error) {
	org := c.OrganizationID
	var in policy.Input
	in.Request.Operation = c.Operation
	in.Request.Expired = !e.Now().Before(c.ExpiresAt)
	in.Request.BindingValid = hmac.Equal(c.Binding().Hash(), c.BindingHash)
	in.Approval.Status = c.Status
	in.Resource.Classification = c.Classification
	in.Resource.Provider = conn.Provider

	// Resource state.
	var envKind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM environments WHERE organization_id = $1 AND id = $2`,
		org, c.EnvironmentID).Scan(&envKind); err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	in.Resource.Environment = envKind
	if c.Operation == "create" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM secrets WHERE organization_id = $1
			AND connection_id = $2 AND name = $3 AND status = 'active')`, org, c.ConnectionID, c.SecretName).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return &denial{code: "secret_exists"}, nil
		}
	} else {
		sec, err := inventory.SecretTx(ctx, tx, org, c.SecretID)
		if err != nil {
			return nil, err
		}
		if sec.Status != "active" || sec.ProviderRef != c.ProviderRef || sec.EnvironmentID != c.EnvironmentID {
			return &denial{code: "secret_changed"}, nil
		}
	}

	// Gate 1 and 2: the requester (or the token) still exists and may still
	// perform the operation here.
	requester := auth.Access{OrganizationID: org, Principal: auth.Principal{Kind: auth.KindUser, UserID: c.RequestedBy}}
	in.Identity.Kind = "user"
	in.Identity.MFAVerified = c.RequesterMFA
	var role string
	err := tx.QueryRow(ctx, `SELECT m.role FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active'`, org, c.RequestedBy).Scan(&role)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		in.Identity.Authenticated = false
	case err != nil:
		return nil, err
	default:
		in.Identity.Authenticated = true
		requester.Role = auth.Role(role)
	}
	if c.RequesterTokenID != uuid.Nil {
		in.Identity.Kind = "api_token"
		requester.Principal.Kind, requester.Principal.TokenID = auth.KindAPIToken, c.RequesterTokenID
		var scopes []string
		err := tx.QueryRow(ctx, `SELECT scopes FROM api_tokens WHERE organization_id = $1 AND id = $2
			AND revoked_at IS NULL AND expires_at > now()`, org, c.RequesterTokenID).Scan(&scopes)
		if errors.Is(err, pgx.ErrNoRows) {
			in.Identity.Authenticated = false
		} else if err != nil {
			return nil, err
		}
		for _, s := range scopes {
			requester.Principal.TokenScopes = append(requester.Principal.TokenScopes, auth.Permission(s))
		}
	}
	if in.Identity.Authenticated {
		if requester.Bindings, err = tenancy.BindingsTx(ctx, tx, org, c.RequestedBy); err != nil {
			return nil, err
		}
		in.Authorization.Allowed = requester.CanOn(approvals.Permission(c.Operation), c.EnvironmentID)
	}

	// Gate 3: count approvals that approved exactly this binding, by someone
	// other than the requester who may still approve here.
	pol, err := approvals.PolicyTx(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	in.Approval.Required = max(c.RequiredApprovals, pol.Required(envKind, c.Operation, c.Classification))
	if c.BreakGlass && in.Authorization.Allowed && requester.CanOn(auth.SecretBreakGlass, c.EnvironmentID) {
		in.Request.BreakGlass, in.Approval.Required = true, 0
	} else if c.BreakGlass {
		// Flagged but the requester lost the role: the flag grants nothing.
		in.Request.BreakGlass = true
		in.Identity.MFAVerified = false
	}
	allMFA := true
	for _, d := range c.Decisions {
		if d.Decision != "approve" || d.ApproverID == c.RequestedBy || !hmac.Equal(d.ApprovedHash, c.BindingHash) {
			continue
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
			WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active')`, org, d.ApproverID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		bindings, err := tenancy.BindingsTx(ctx, tx, org, d.ApproverID)
		if err != nil {
			return nil, err
		}
		approver := auth.Access{OrganizationID: org, Principal: auth.Principal{Kind: auth.KindUser, UserID: d.ApproverID}, Bindings: bindings}
		if !approver.CanOn(auth.ApprovalDecide, c.EnvironmentID) {
			continue
		}
		in.Approval.Count++
		allMFA = allMFA && d.ApproverMFA
	}
	in.Approval.ApproversMFAVerified = in.Approval.Count > 0 && allMFA

	if err := tx.QueryRow(ctx, `SELECT require_mfa FROM organizations WHERE id = $1`, org).Scan(&in.Organization.RequireMFA); err != nil {
		return nil, err
	}

	// Gate 4.
	dec, err := e.policy.Evaluate(ctx, in)
	if err != nil {
		e.logger.ErrorContext(ctx, "execution policy error", "change_request_id", c.ID, "error", err)
	}
	if !dec.Allow {
		return &denial{code: "policy_denied", reasons: dec.Reasons}, nil
	}
	return nil, nil
}

// complete records a provider result. It is idempotent: a journal entry that
// is no longer an intent was completed by someone else.
func (e *Executor) complete(ctx context.Context, c approvals.ChangeRequest, journalID uuid.UUID, res connectors.Result, reconciled bool) error {
	org := c.OrganizationID
	return postgres.Tx(ctx, e.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE execution_journal SET status = 'completed', provider_request_id = $3,
			provider_version_id = $4, completed_at = now() WHERE organization_id = $1 AND id = $2 AND status = 'intent'`,
			org, journalID, res.RequestID, res.VersionID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		secretID := c.SecretID
		switch c.Operation {
		case "create":
			// Discovery may have imported the new secret already; merge.
			err = tx.QueryRow(ctx, `INSERT INTO secrets (organization_id, connection_id, environment_id, name, provider_ref,
				classification, current_version) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (connection_id, name) WHERE status = 'active'
				DO UPDATE SET provider_ref = EXCLUDED.provider_ref, current_version = EXCLUDED.current_version, updated_at = now()
				RETURNING id`,
				org, c.ConnectionID, c.EnvironmentID, c.SecretName, res.ProviderRef, c.Classification, res.VersionID).Scan(&secretID)
		case "update":
			// A new value counts as a rotation (manual rotation, ADR-0011).
			err = inventory.MarkRotatedTx(ctx, tx, org, c.SecretID, e.Now(), res.VersionID)
		case "delete":
			_, err = tx.Exec(ctx, `UPDATE secrets SET status = 'deleted', updated_at = now()
				WHERE organization_id = $1 AND id = $2`, org, c.SecretID)
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = 'succeeded', secret_id = $3,
			provider_version_id = $4, cloud_request_id = $5, updated_at = now(), completed_at = now()
			WHERE organization_id = $1 AND id = $2 AND status = 'executing'`,
			org, c.ID, secretID, nullString(res.VersionID), nullString(res.RequestID)); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "change_request.executed", ResourceType: "secret", ResourceID: secretID.String(), Decision: audit.Allow,
			ChangeRequestID: c.ID, CloudRequestID: res.RequestID,
			Details: map[string]string{"operation": c.Operation, "version_id": res.VersionID, "reconciled": fmt.Sprint(reconciled)},
		})
		if err == nil {
			err = approvals.NotifyOutcomeTx(ctx, tx, c, "was applied", "")
		}
		if err == nil {
			e.logger.InfoContext(ctx, "change request executed", "change_request_id", c.ID, "operation", c.Operation, "reconciled", reconciled)
		}
		return err
	})
}

// fail marks the request failed in its own transaction and discards staging.
func (e *Executor) fail(ctx context.Context, c approvals.ChangeRequest, journalID uuid.UUID, d denial) error {
	err := postgres.Tx(ctx, e.pool, func(tx pgx.Tx) error { return e.failTx(ctx, tx, c, journalID, d) })
	if err != nil {
		return err
	}
	e.logger.WarnContext(ctx, "change request failed", "change_request_id", c.ID, "code", d.code)
	return nil
}

func (e *Executor) failTx(ctx context.Context, tx pgx.Tx, c approvals.ChangeRequest, journalID uuid.UUID, d denial) error {
	org := c.OrganizationID
	ok, err := approvals.SetStatusTx(ctx, tx, org, c.ID, "failed", []string{"approved", "executing"}, d.code)
	if err != nil || !ok {
		return err
	}
	if journalID != uuid.Nil {
		if _, err := tx.Exec(ctx, `UPDATE execution_journal SET status = 'failed', error_code = $3, completed_at = now()
			WHERE organization_id = $1 AND id = $2 AND status = 'intent'`, org, journalID, d.code); err != nil {
			return err
		}
	}
	details := map[string]string{"code": d.code}
	if len(d.reasons) > 0 {
		details["policy_reasons"] = strings.Join(d.reasons, ",")
	}
	if _, err = audit.Append(ctx, tx, org, audit.Event{
		Action: "change_request.execution_denied", ResourceType: "secret", ResourceID: resourceID(c), Decision: audit.Deny,
		ChangeRequestID: c.ID, Details: details,
	}); err != nil {
		return err
	}
	detail := d.code
	if len(d.reasons) > 0 {
		detail += " (" + strings.Join(d.reasons, ", ") + ")"
	}
	return approvals.NotifyOutcomeTx(ctx, tx, c, "failed", detail)
}

// discard destroys a terminal request's staged value; failures are left to
// the provider-side sweeper (tags/expiry, ADR-0003).
func (e *Executor) discard(ctx context.Context, org, id uuid.UUID) {
	if err := approvals.DiscardStaging(ctx, e.pool, e.registry, org, id); err != nil {
		e.logger.WarnContext(ctx, "discard staged value", "change_request_id", id, "error", err)
	}
}

// ReconcileStale resumes executions whose journal intent is older than
// olderThan, e.g. after a worker crash or a lost provider response.
func (e *Executor) ReconcileStale(ctx context.Context, olderThan time.Duration) (int, error) {
	rows, err := e.pool.Query(ctx, `SELECT organization_id, change_request_id FROM secretmesh_stale_executions($1, 100)`, olderThan)
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
	var errs []error
	for _, it := range items {
		if err := e.Execute(ctx, it.org, it.id); err != nil {
			errs = append(errs, fmt.Errorf("reconcile %s: %w", it.id, err))
		}
	}
	return len(items), errors.Join(errs...)
}

func resourceID(c approvals.ChangeRequest) string {
	if c.SecretID != uuid.Nil {
		return c.SecretID.String()
	}
	return "new:" + c.ConnectionID.String() + "/" + c.SecretName
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
