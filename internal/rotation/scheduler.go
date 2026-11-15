// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package rotation

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// Tick runs the scheduler once: it starts due native rotations and sends
// reminders and escalations. Every effect is deduplicated, so running it
// often, concurrently or after downtime is safe; after downtime only the
// most recent reminder or escalation step is sent.
func (s *Service) Tick(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT organization_id, policy_id FROM secretmesh_rotation_policies_due()`)
	if err != nil {
		return 0, err
	}
	type item struct{ org, policy uuid.UUID }
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var i item
		return i, r.Scan(&i.org, &i.policy)
	})
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, it := range items {
		if err := s.tickPolicy(ctx, it.org, it.policy); err != nil {
			errs = append(errs, fmt.Errorf("rotation policy %s: %w", it.policy, err))
		}
	}
	return len(items), errors.Join(errs...)
}

func (s *Service) tickPolicy(ctx context.Context, org, policyID uuid.UUID) error {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		p, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM rotation_policies
			WHERE organization_id = $1 AND id = $2 AND enabled FOR UPDATE SKIP LOCKED`, org, policyID))
		if errors.Is(err, ErrNoPolicy) {
			return nil
		}
		if err != nil {
			return err
		}
		sec, err := inventory.SecretTx(ctx, tx, org, p.SecretID)
		if err != nil || sec.Status != "active" {
			return err
		}
		plugin, ok := s.plugins[p.Strategy]
		if !ok {
			return fmt.Errorf("unknown strategy %q", p.Strategy)
		}
		now := s.Now()
		slot := p.NextRotationAt.UTC().Format(time.RFC3339)
		link := fmt.Sprintf("/orgs/%s/secrets/%s", org, sec.ID)
		where := fmt.Sprintf("%q (%s)", sec.Name, sec.EnvironmentKind)

		if now.Before(p.NextRotationAt) {
			if plugin.Automated() {
				return nil // native rotations need no reminders
			}
			// The closest reminder whose time has come.
			step := -1
			for _, d := range p.ReminderDays {
				if !now.Before(p.NextRotationAt.Add(-days(d))) && (step < 0 || d < step) {
					step = d
				}
			}
			if step < 0 {
				return nil
			}
			owners, err := owners(ctx, tx, org, sec)
			if err != nil {
				return err
			}
			_, err = notify.Enqueue(ctx, tx, org, notify.Event{
				Kind: notify.RotationReminder, DedupeKey: fmt.Sprintf("rotation.reminder:%s:%s:%d", p.ID, slot, step),
				Subject: "Rotation due soon: " + sec.Name,
				Body: fmt.Sprintf("The secret %s must be rotated by %s. Rotate it in the provider or submit a change with the new value.",
					where, p.NextRotationAt.UTC().Format("2006-01-02 15:04 UTC")),
				LinkPath: link, Recipients: owners,
			})
			return err
		}

		if plugin.Automated() {
			// One scheduled attempt per due date; none while another is open.
			var id uuid.UUID
			err := tx.QueryRow(ctx, `INSERT INTO rotation_executions (organization_id, secret_id, trigger, due_at)
				VALUES ($1, $2, 'schedule', $3) ON CONFLICT DO NOTHING RETURNING id`, org, sec.ID, p.NextRotationAt).Scan(&id)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			default:
				if _, err := audit.Append(ctx, tx, org, audit.Event{
					Action: "rotation.scheduled", ResourceType: "secret", ResourceID: sec.ID.String(), Decision: audit.Allow,
					Details: map[string]string{"execution_id": id.String(), "due_at": slot},
				}); err != nil {
					return err
				}
				if err := s.jobs.EnqueueRotation(ctx, tx, org, id); err != nil {
					return err
				}
			}
		}

		overdue := now.Sub(p.NextRotationAt)
		level, after := -1, 0
		for i, d := range p.EscalationDays {
			if overdue >= days(d) {
				level, after = i, d
			}
		}
		if level < 0 {
			if plugin.Automated() {
				return nil
			}
			owners, err := owners(ctx, tx, org, sec)
			if err != nil {
				return err
			}
			_, err = notify.Enqueue(ctx, tx, org, notify.Event{
				Kind: notify.RotationDue, DedupeKey: fmt.Sprintf("rotation.due:%s:%s", p.ID, slot),
				Subject:  "Rotation due: " + sec.Name,
				Body:     fmt.Sprintf("The secret %s is due for rotation now.", where),
				LinkPath: link, Recipients: owners,
			})
			return err
		}
		recipients, err := escalationRecipients(ctx, tx, org, sec, level)
		if err != nil {
			return err
		}
		created, err := notify.Enqueue(ctx, tx, org, notify.Event{
			Kind: notify.RotationOverdue, DedupeKey: fmt.Sprintf("rotation.overdue:%s:%s:%d", p.ID, slot, level),
			Subject: "Rotation overdue: " + sec.Name,
			Body: fmt.Sprintf("The secret %s was due for rotation on %s and is %d day(s) overdue (escalation step %d of %d).",
				where, p.NextRotationAt.UTC().Format("2006-01-02"), int(overdue/(24*time.Hour)), level+1, len(p.EscalationDays)),
			LinkPath: link, Recipients: recipients,
		})
		if err != nil || !created {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation.overdue", ResourceType: "secret", ResourceID: sec.ID.String(), Decision: audit.None,
			Details: map[string]string{"due_at": slot, "escalation_step": strconv.Itoa(level + 1), "after_days": strconv.Itoa(after)},
		})
		return err
	})
}

// owners is the secret's owner, or everyone who manages it if it has none
// (or the owner left).
func owners(ctx context.Context, tx pgx.Tx, org uuid.UUID, sec inventory.Secret) ([]uuid.UUID, error) {
	if sec.OwnerUserID != nil {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
			WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active')`, org, *sec.OwnerUserID).Scan(&active); err != nil {
			return nil, err
		}
		if active {
			return []uuid.UUID{*sec.OwnerUserID}, nil
		}
	}
	return notify.HoldersOf(ctx, tx, org, sec.EnvironmentID, auth.SecretManage)
}

// escalationRecipients widens with each step: the owner, then the security
// team, then organization admins (blueprint §7.4).
func escalationRecipients(ctx context.Context, tx pgx.Tx, org uuid.UUID, sec inventory.Secret, level int) ([]uuid.UUID, error) {
	out, err := owners(ctx, tx, org, sec)
	if err != nil || level < 1 {
		return out, err
	}
	security, err := notify.HoldersOf(ctx, tx, org, sec.EnvironmentID, auth.PolicyManage)
	if err != nil {
		return nil, err
	}
	out = append(out, security...)
	if level < 2 {
		return out, nil
	}
	admins, err := notify.OrgAdmins(ctx, tx, org)
	return append(out, admins...), err
}
