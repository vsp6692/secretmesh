// Package notify records notifications in an outbox, in the same transaction
// as the event they describe, and delivers them to the organization's
// channels with retries (ADR-0011).
//
// Notifications never contain secret values. A Slack channel stores only the
// ID of a secret in the organization's own vault holding the webhook URL;
// the URL is read from the provider at delivery time and never persisted.
package notify

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/secretmesh/secretmesh/internal/auth"
)

// Events.
const (
	RotationReminder        = "rotation.reminder"
	RotationDue             = "rotation.due"
	RotationOverdue         = "rotation.overdue"
	RotationFailed          = "rotation.failed"
	ChangeRequestPending    = "change_request.pending"
	ChangeRequestBreakGlass = "change_request.break_glass"
	ChangeRequestCompleted  = "change_request.completed"
	ChannelTest             = "channel.test"
)

// Event is one notification. DedupeKey makes enqueueing idempotent: a second
// event with the same key is dropped.
type Event struct {
	Kind      string
	DedupeKey string
	Subject   string
	Body      string
	// LinkPath is appended to the public URL, e.g. /orgs/<id>/secrets/<id>.
	LinkPath string
	// Recipients are users for email channels; chat channels post once.
	Recipients []uuid.UUID
	// ChannelID restricts delivery to one channel (tests of a channel).
	ChannelID uuid.UUID
}

// Enqueue records ev and one delivery per enabled channel. It reports false
// if an event with the same dedupe key exists.
func Enqueue(ctx context.Context, tx pgx.Tx, org uuid.UUID, ev Event) (bool, error) {
	if ev.DedupeKey == "" {
		ev.DedupeKey = ev.Kind + ":" + uuid.NewString()
	}
	if ev.Recipients == nil {
		ev.Recipients = []uuid.UUID{}
	}
	var id uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO notifications (organization_id, event, dedupe_key, subject, body, link_path, recipients)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (organization_id, dedupe_key) DO NOTHING RETURNING id`,
		org, ev.Kind, ev.DedupeKey, oneLine(ev.Subject, 200), ev.Body, ev.LinkPath, dedupe(ev.Recipients)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_deliveries (organization_id, notification_id, channel_id)
		SELECT $1, $2, c.id FROM notification_channels c
		WHERE c.organization_id = $1 AND c.enabled AND ($3::uuid IS NULL OR c.id = $3)
		  AND (c.kind <> 'email' OR cardinality($4::uuid[]) > 0)`,
		org, id, nullUUID(ev.ChannelID), dedupe(ev.Recipients))
	return true, err
}

// HoldersOf returns active members holding a binding that grants perm in env
// (or organization-wide).
func HoldersOf(ctx context.Context, tx pgx.Tx, org, env uuid.UUID, perm auth.Permission) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT b.user_id FROM role_bindings b
		JOIN users u ON u.id = b.user_id AND u.status = 'active'
		WHERE b.organization_id = $1 AND (b.environment_id IS NULL OR b.environment_id = $2) AND b.role = ANY($3)
		ORDER BY b.user_id`, org, env, auth.RolesWith(perm))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// OrgAdmins returns the organization's active admins.
func OrgAdmins(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT m.user_id FROM memberships m JOIN users u ON u.id = m.user_id AND u.status = 'active'
		WHERE m.organization_id = $1 AND m.role = 'org_admin' ORDER BY m.user_id`, org)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Without returns ids minus exclude (e.g. the requester of a change).
func Without(ids []uuid.UUID, exclude uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id != exclude {
			out = append(out, id)
		}
	}
	return out
}

// Channel kinds.
const (
	KindEmail = "email"
	KindSlack = "slack"
)

// Channel is a notification destination.
type Channel struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Kind           string
	Name           string
	// WebhookSecretID (Slack) is a secret in the organization's inventory
	// whose value is the webhook URL.
	WebhookSecretID uuid.UUID
	Enabled         bool
	CreatedAt       time.Time
}

var ErrChannelExists = errors.New("a channel with this name exists")

func Channels(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]Channel, error) {
	rows, err := tx.Query(ctx, `SELECT id, organization_id, kind, name, coalesce(config->>'webhook_secret_id', ''), enabled, created_at
		FROM notification_channels WHERE organization_id = $1 ORDER BY name`, org)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanChannel)
}

func ChannelTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (Channel, error) {
	rows, err := tx.Query(ctx, `SELECT id, organization_id, kind, name, coalesce(config->>'webhook_secret_id', ''), enabled, created_at
		FROM notification_channels WHERE organization_id = $1 AND id = $2`, org, id)
	if err != nil {
		return Channel{}, err
	}
	return pgx.CollectExactlyOneRow(rows, scanChannel)
}

func scanChannel(r pgx.CollectableRow) (Channel, error) {
	var c Channel
	var secret string
	err := r.Scan(&c.ID, &c.OrganizationID, &c.Kind, &c.Name, &secret, &c.Enabled, &c.CreatedAt)
	if err == nil && secret != "" {
		c.WebhookSecretID, err = uuid.Parse(secret)
	}
	return c, err
}

func CreateChannel(ctx context.Context, tx pgx.Tx, org uuid.UUID, c Channel, by uuid.UUID) (Channel, error) {
	cfg := map[string]string{}
	if c.Kind == KindSlack {
		cfg["webhook_secret_id"] = c.WebhookSecretID.String()
	}
	err := tx.QueryRow(ctx, `INSERT INTO notification_channels (organization_id, kind, name, config, enabled, created_by)
		VALUES ($1, $2, $3, $4, true, $5) RETURNING id, created_at`, org, c.Kind, c.Name, cfg, by).Scan(&c.ID, &c.CreatedAt)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return c, ErrChannelExists
	}
	c.OrganizationID, c.Enabled = org, true
	return c, err
}

func DeleteChannel(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM notification_channels WHERE organization_id = $1 AND id = $2`, org, id)
	return tag.RowsAffected() > 0, err
}

// oneLine strips line breaks (header injection) and truncates.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id != uuid.Nil && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// Delivery describes one pending delivery, for listing.
type Delivery struct {
	NotificationID uuid.UUID
	Event          string
	Subject        string
	ChannelName    string
	Status         string
	Attempts       int
	LastError      string
	CreatedAt      time.Time
	SentAt         *time.Time
}

// Recent lists the latest deliveries for the organization.
func Recent(ctx context.Context, tx pgx.Tx, org uuid.UUID, limit int) ([]Delivery, error) {
	rows, err := tx.Query(ctx, `SELECT n.id, n.event, n.subject, c.name, d.status, d.attempts, coalesce(d.last_error, ''),
			n.created_at, d.sent_at
		FROM notification_deliveries d
		JOIN notifications n ON n.organization_id = d.organization_id AND n.id = d.notification_id
		JOIN notification_channels c ON c.organization_id = d.organization_id AND c.id = d.channel_id
		WHERE d.organization_id = $1 ORDER BY n.created_at DESC, c.name LIMIT $2`, org, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) {
		var d Delivery
		return d, r.Scan(&d.NotificationID, &d.Event, &d.Subject, &d.ChannelName, &d.Status, &d.Attempts, &d.LastError, &d.CreatedAt, &d.SentAt)
	})
}
