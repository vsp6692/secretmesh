package rotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/policy"
	"github.com/secretmesh/secretmesh/internal/tenancy"
)

// PendingError means the provider is still rotating; run again after After.
type PendingError struct{ After time.Duration }

func (e *PendingError) Error() string { return "rotation in progress" }

// snapshot is the database state one step needs.
type snapshot struct {
	org      uuid.UUID
	ex       Execution
	sec      inventory.Secret
	conn     inventory.Connection
	policy   *Policy
	decision *policy.Decision // set for scheduled executions
}

// Run advances one rotation as far as it can: scheduled -> rotating ->
// verifying -> succeeded/failed. Every transition is committed before the
// next provider call, and every provider call is idempotent for the
// execution ID, so Run may be repeated after a crash at any point (or run
// concurrently) without rotating twice. A returned error means "retry
// later"; *PendingError means the provider is still working.
func (s *Service) Run(ctx context.Context, org, id uuid.UUID) error {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	for range 4 {
		snap, err := s.load(ctx, org, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		if !snap.ex.Open() {
			return nil
		}
		if snap.policy == nil {
			return s.fail(ctx, snap, "no_rotation_policy", nil)
		}
		plugin, ok := s.plugins[snap.policy.Strategy]
		if !ok || !plugin.Automated() {
			return s.fail(ctx, snap, "unsupported_strategy", nil)
		}
		store, err := s.registry.Store(connectors.Connection{ID: snap.conn.ID, OrganizationID: org, Provider: snap.conn.Provider, Config: snap.conn.Config})
		if err != nil {
			return s.fail(ctx, snap, "connection_unavailable", nil)
		}
		t := target(snap.sec)

		switch snap.ex.Status {
		case "scheduled":
			if !snap.decision.Allow {
				return s.fail(ctx, snap, "policy_denied", snap.decision.Reasons)
			}
			if err := plugin.Validate(ctx, store, t); errors.Is(err, ErrNotConfigured) {
				return s.fail(ctx, snap, "not_configured", nil)
			} else if errors.Is(err, connectors.ErrNotFound) {
				return s.fail(ctx, snap, "provider_target_missing", nil)
			} else if err != nil {
				return fmt.Errorf("validate rotation: %w", err)
			}
			if err := s.advance(ctx, snap, "scheduled", "rotating", connectors.Result{}); err != nil {
				return err
			}

		case "rotating":
			// The attempt may already have started before a crash or a lost
			// response: ask the provider before starting it.
			state, version, err := plugin.Verify(ctx, store, t, id)
			if err != nil {
				return fmt.Errorf("look up rotation: %w", err)
			}
			res := connectors.Result{VersionID: version, RequestID: snap.ex.CloudRequestID}
			if state == connectors.RotationNotStarted {
				res, err = plugin.Rotate(ctx, store, t, id)
				switch {
				case errors.Is(err, connectors.ErrConflict):
					return s.fail(ctx, snap, "provider_conflict", nil)
				case errors.Is(err, connectors.ErrNotFound):
					return s.fail(ctx, snap, "provider_target_missing", nil)
				case errors.Is(err, connectors.ErrAccessDenied):
					return s.fail(ctx, snap, "provider_access_denied", nil)
				case err != nil:
					return fmt.Errorf("start rotation: %w", err)
				}
			}
			if err := s.advance(ctx, snap, "rotating", "verifying", res); err != nil {
				return err
			}

		case "verifying":
			state, version, err := plugin.Verify(ctx, store, t, id)
			if err != nil {
				return fmt.Errorf("verify rotation: %w", err)
			}
			switch state {
			case connectors.RotationDone:
				if version != "" {
					snap.ex.ProviderVersionID = version
				}
				return s.complete(ctx, snap)
			case connectors.RotationInProgress:
				started := snap.ex.UpdatedAt
				if snap.ex.RotateStartedAt != nil {
					started = *snap.ex.RotateStartedAt
				}
				if s.Now().Sub(started) < s.VerifyTimeout {
					return &PendingError{After: s.PollInterval}
				}
				if err := plugin.Recover(ctx, store, t, id); err != nil {
					return fmt.Errorf("recover rotation: %w", err)
				}
				return s.fail(ctx, snap, "verification_timeout", nil)
			case connectors.RotationFailed:
				if err := plugin.Recover(ctx, store, t, id); err != nil {
					return fmt.Errorf("recover rotation: %w", err)
				}
				return s.fail(ctx, snap, "rotation_failed", nil)
			default:
				return s.fail(ctx, snap, "rotation_lost", nil)
			}
		}
	}
	return nil
}

// load reads the execution and its context. For scheduled executions it
// also evaluates the rotation policy (gate 4) against current state.
func (s *Service) load(ctx context.Context, org, id uuid.UUID) (snapshot, error) {
	snap := snapshot{org: org}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		snap.ex, err = scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM rotation_executions
			WHERE organization_id = $1 AND id = $2`, org, id))
		if err != nil || !snap.ex.Open() {
			return err
		}
		if snap.sec, err = inventory.SecretTx(ctx, tx, org, snap.ex.SecretID); err != nil {
			return err
		}
		if snap.conn, err = inventory.ConnectionTx(ctx, tx, org, snap.sec.ConnectionID); err != nil && !errors.Is(err, inventory.ErrNotFound) {
			return err
		}
		p, err := policyTx(ctx, tx, org, snap.sec.ID, false)
		switch {
		case errors.Is(err, ErrNoPolicy):
		case err != nil:
			return err
		default:
			snap.policy = &p
		}
		if snap.ex.Status != "scheduled" {
			return nil
		}
		in, err := s.policyInput(ctx, tx, org, snap)
		if err != nil {
			return err
		}
		d, err := s.engine.Evaluate(ctx, in)
		if err != nil {
			s.logger.ErrorContext(ctx, "rotation policy error", "execution_id", id, "error", err)
		}
		snap.decision = &d
		return nil
	})
	return snap, err
}

func (s *Service) policyInput(ctx context.Context, tx pgx.Tx, org uuid.UUID, snap snapshot) (policy.RotationInput, error) {
	var in policy.RotationInput
	in.Trigger = snap.ex.Trigger
	in.Resource.Environment = string(snap.sec.EnvironmentKind)
	in.Resource.Classification = string(snap.sec.Classification)
	in.Resource.Provider = snap.conn.Provider
	in.Secret.Active = snap.sec.Status == "active"
	if snap.policy != nil {
		in.Policy.Exists, in.Policy.Enabled, in.Policy.Strategy = true, snap.policy.Enabled, snap.policy.Strategy
	}
	open, err := openChange(ctx, tx, org, snap.sec.ID)
	if err != nil {
		return in, err
	}
	in.Secret.ChangeInProgress = open
	if err := tx.QueryRow(ctx, `SELECT require_mfa FROM organizations WHERE id = $1`, org).Scan(&in.Organization.RequireMFA); err != nil {
		return in, err
	}
	if snap.ex.Trigger == "schedule" {
		in.Identity.Kind, in.Identity.Authenticated = "system", true
		return in, nil
	}
	// Rotate-now: the person who asked must still be a member who may manage
	// the secret.
	in.Identity.Kind, in.Identity.MFAVerified = "user", snap.ex.RequesterMFA
	if snap.ex.RequestedBy == nil {
		return in, nil
	}
	var role string
	err = tx.QueryRow(ctx, `SELECT m.role FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active'`, org, *snap.ex.RequestedBy).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, nil
	}
	if err != nil {
		return in, err
	}
	in.Identity.Authenticated = true
	bindings, err := tenancy.BindingsTx(ctx, tx, org, *snap.ex.RequestedBy)
	if err != nil {
		return in, err
	}
	requester := auth.Access{OrganizationID: org, Role: auth.Role(role), Bindings: bindings,
		Principal: auth.Principal{Kind: auth.KindUser, UserID: *snap.ex.RequestedBy}}
	in.Authorization.Allowed = requester.CanOn(auth.SecretManage, snap.sec.EnvironmentID)
	return in, nil
}

// advance moves the execution from one state to the next. It is a no-op
// (but not an error) if another worker got there first.
func (s *Service) advance(ctx context.Context, snap snapshot, from, to string, res connectors.Result) error {
	org := snap.org
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rotation_executions SET status = $4,
				rotate_started_at = CASE WHEN $4 = 'rotating' THEN now() ELSE rotate_started_at END,
				provider_version_id = coalesce(nullif($5, ''), provider_version_id),
				cloud_request_id = coalesce(nullif($6, ''), cloud_request_id), updated_at = now()
			WHERE organization_id = $1 AND id = $2 AND status = $3`, org, snap.ex.ID, from, to, res.VersionID, res.RequestID)
		if err != nil || tag.RowsAffected() == 0 || to != "rotating" {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation.started", ResourceType: "secret", ResourceID: snap.sec.ID.String(), Decision: audit.Allow,
			Details: map[string]string{"execution_id": snap.ex.ID.String(), "trigger": snap.ex.Trigger, "strategy": snap.policy.Strategy},
		})
		return err
	})
}

func (s *Service) complete(ctx context.Context, snap snapshot) error {
	org := snap.org
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rotation_executions SET status = 'succeeded', finished_at = now(), updated_at = now(),
				provider_version_id = coalesce(nullif($3, ''), provider_version_id)
			WHERE organization_id = $1 AND id = $2 AND status = 'verifying'`, org, snap.ex.ID, snap.ex.ProviderVersionID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		if err := inventory.MarkRotatedTx(ctx, tx, org, snap.sec.ID, s.Now(), snap.ex.ProviderVersionID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation.succeeded", ResourceType: "secret", ResourceID: snap.sec.ID.String(), Decision: audit.Allow,
			CloudRequestID: snap.ex.CloudRequestID,
			Details:        map[string]string{"execution_id": snap.ex.ID.String(), "version_id": snap.ex.ProviderVersionID},
		})
		return err
	})
	if err == nil {
		s.logger.InfoContext(ctx, "secret rotated", "secret_id", snap.sec.ID, "execution_id", snap.ex.ID)
	}
	return err
}

// fail ends the attempt and tells the owner and the security team.
func (s *Service) fail(ctx context.Context, snap snapshot, code string, reasons []string) error {
	org := snap.org
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rotation_executions SET status = 'failed', error_code = $3, finished_at = now(), updated_at = now()
			WHERE organization_id = $1 AND id = $2 AND status IN ('scheduled', 'rotating', 'verifying')`, org, snap.ex.ID, code)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		details := map[string]string{"execution_id": snap.ex.ID.String(), "code": code}
		if len(reasons) > 0 {
			details["policy_reasons"] = strings.Join(reasons, ",")
		}
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation.failed", ResourceType: "secret", ResourceID: snap.sec.ID.String(), Decision: audit.Deny, Details: details,
		}); err != nil {
			return err
		}
		recipients, err := escalationRecipients(ctx, tx, org, snap.sec, 1)
		if err != nil {
			return err
		}
		if snap.ex.RequestedBy != nil {
			recipients = append(recipients, *snap.ex.RequestedBy)
		}
		detail := code
		if len(reasons) > 0 {
			detail += " (" + strings.Join(reasons, ", ") + ")"
		}
		_, err = notify.Enqueue(ctx, tx, org, notify.Event{
			Kind: notify.RotationFailed, DedupeKey: "rotation.failed:" + snap.ex.ID.String(),
			Subject: "Rotation failed: " + snap.sec.Name,
			Body: fmt.Sprintf("Rotating %q (%s) failed: %s.\nThe current value was left in place.",
				snap.sec.Name, snap.sec.EnvironmentKind, detail),
			LinkPath:   fmt.Sprintf("/orgs/%s/secrets/%s", org, snap.sec.ID),
			Recipients: recipients,
		})
		return err
	})
	if err == nil {
		s.logger.WarnContext(ctx, "rotation failed", "secret_id", snap.sec.ID, "execution_id", snap.ex.ID, "code", code)
	}
	return err
}

// ReconcileStale resumes open executions not updated for olderThan, e.g.
// after the worker running them died.
func (s *Service) ReconcileStale(ctx context.Context, olderThan time.Duration) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT organization_id, execution_id FROM secretmesh_stale_rotations($1, 100)`, olderThan)
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
		var pending *PendingError
		if err := s.Run(ctx, it.org, it.id); err != nil && !errors.As(err, &pending) {
			errs = append(errs, fmt.Errorf("reconcile rotation %s: %w", it.id, err))
		}
	}
	return len(items), errors.Join(errs...)
}
