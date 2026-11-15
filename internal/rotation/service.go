package rotation

import (
	"context"
	"errors"
	"log/slog"
	"slices"
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
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/policy"
	"github.com/secretmesh/secretmesh/internal/tenancy"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrForbidden  = errors.New("not permitted")
	ErrInProgress = errors.New("a rotation of this secret is already in progress")
	ErrNoPolicy   = errors.New("the secret has no rotation policy")
	// ErrChangeInProgress: an open change request targets the secret.
	ErrChangeInProgress = errors.New("an open change request targets this secret")
	ErrMFARequired      = errors.New("rotating production secrets requires an MFA sign-in")
)

// InvalidError reports invalid input.
type InvalidError struct{ Msg string }

func (e InvalidError) Error() string { return e.Msg }

// Jobs enqueues rotation work in the caller's transaction.
type Jobs interface {
	EnqueueRotation(ctx context.Context, tx pgx.Tx, org, execution uuid.UUID) error
}

type Policy struct {
	ID             uuid.UUID
	SecretID       uuid.UUID
	Strategy       string
	IntervalDays   int
	ReminderDays   []int
	EscalationDays []int
	Enabled        bool
	NextRotationAt time.Time
	UpdatedBy      *uuid.UUID
	UpdatedAt      time.Time
}

type Execution struct {
	ID                uuid.UUID
	SecretID          uuid.UUID
	Trigger           string
	RequestedBy       *uuid.UUID
	RequesterMFA      bool
	Status            string
	DueAt             time.Time
	ProviderVersionID string
	CloudRequestID    string
	ErrorCode         string
	RotateStartedAt   *time.Time
	FinishedAt        *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Open reports whether the execution has not finished.
func (e Execution) Open() bool {
	return e.Status == "scheduled" || e.Status == "rotating" || e.Status == "verifying"
}

type Service struct {
	pool     *pgxpool.Pool
	registry *connectors.Registry
	plugins  Plugins
	engine   *policy.Engine
	jobs     Jobs
	logger   *slog.Logger
	Now      func() time.Time
	// VerifyTimeout bounds how long a provider rotation may stay in
	// progress before it is abandoned and reported as failed.
	VerifyTimeout time.Duration
	// PollInterval is how soon an in-progress rotation is checked again.
	PollInterval time.Duration
}

func NewService(pool *pgxpool.Pool, registry *connectors.Registry, plugins Plugins, engine *policy.Engine, logger *slog.Logger) *Service {
	return &Service{pool: pool, registry: registry, plugins: plugins, engine: engine, logger: logger, Now: time.Now,
		VerifyTimeout: 30 * time.Minute, PollInterval: 30 * time.Second}
}

// SetJobs breaks the construction cycle with the job queue.
func (s *Service) SetJobs(j Jobs) { s.jobs = j }

const policyColumns = `id, secret_id, strategy, interval_days, reminder_days, escalation_days, enabled, next_rotation_at,
	updated_by, updated_at`

func scanPolicy(r pgx.Row) (Policy, error) {
	var p Policy
	var rem, esc []int32
	err := r.Scan(&p.ID, &p.SecretID, &p.Strategy, &p.IntervalDays, &rem, &esc, &p.Enabled, &p.NextRotationAt,
		&p.UpdatedBy, &p.UpdatedAt)
	for _, d := range rem {
		p.ReminderDays = append(p.ReminderDays, int(d))
	}
	for _, d := range esc {
		p.EscalationDays = append(p.EscalationDays, int(d))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNoPolicy
	}
	return p, err
}

func policyTx(ctx context.Context, tx pgx.Tx, org, secretID uuid.UUID, lock bool) (Policy, error) {
	q := `SELECT ` + policyColumns + ` FROM rotation_policies WHERE organization_id = $1 AND secret_id = $2`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanPolicy(tx.QueryRow(ctx, q, org, secretID))
}

// readable loads an active secret the caller may read. Secrets in
// environments the caller cannot read are reported as not found.
func readable(ctx context.Context, tx pgx.Tx, access auth.Access, id uuid.UUID) (inventory.Secret, error) {
	s, err := inventory.SecretTx(ctx, tx, access.OrganizationID, id)
	if errors.Is(err, inventory.ErrNotFound) || (err == nil && (s.Status != "active" || !access.CanOn(auth.SecretRead, s.EnvironmentID))) {
		return s, ErrNotFound
	}
	return s, err
}

// Policy returns the secret's rotation policy, or ErrNoPolicy.
func (s *Service) Policy(ctx context.Context, access auth.Access, secretID uuid.UUID) (Policy, error) {
	var p Policy
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := readable(ctx, tx, access, secretID); err != nil {
			return err
		}
		var err error
		p, err = policyTx(ctx, tx, access.OrganizationID, secretID, false)
		return err
	})
	return p, err
}

// PolicyInput sets a rotation policy.
type PolicyInput struct {
	Strategy       string
	IntervalDays   int
	ReminderDays   []int
	EscalationDays []int
	Enabled        bool
}

func (in *PolicyInput) validate(plugins Plugins) error {
	if _, ok := plugins[in.Strategy]; !ok {
		return InvalidError{"strategy must be native or manual"}
	}
	if in.IntervalDays < 1 || in.IntervalDays > 3650 {
		return InvalidError{"interval_days must be between 1 and 3650"}
	}
	if in.ReminderDays == nil {
		in.ReminderDays = []int{7, 3, 1}
	}
	if in.EscalationDays == nil {
		in.EscalationDays = []int{1, 3, 7}
	}
	if len(in.ReminderDays) > 10 || len(in.EscalationDays) > 3 {
		return InvalidError{"at most 10 reminders and 3 escalation steps"}
	}
	for _, d := range append(slices.Clone(in.ReminderDays), in.EscalationDays...) {
		if d < 0 || d > 365 {
			return InvalidError{"reminder and escalation days must be between 0 and 365"}
		}
	}
	in.ReminderDays = sortedUnique(in.ReminderDays)
	in.EscalationDays = sortedUnique(in.EscalationDays)
	return nil
}

func sortedUnique(d []int) []int {
	out := slices.Clone(d)
	slices.Sort(out)
	return slices.Compact(out)
}

// SetPolicy creates or replaces the secret's rotation policy. The next due
// date counts from the last rotation (or the provider's last change, or
// now). A native policy is checked against the provider first.
func (s *Service) SetPolicy(ctx context.Context, access auth.Access, secretID uuid.UUID, in PolicyInput) (Policy, error) {
	org := access.OrganizationID
	if err := in.validate(s.plugins); err != nil {
		return Policy{}, err
	}
	var sec inventory.Secret
	var conn inventory.Connection
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if sec, err = readable(ctx, tx, access, secretID); err != nil {
			return err
		}
		if !access.CanOn(auth.SecretManage, sec.EnvironmentID) {
			return ErrForbidden
		}
		conn, err = inventory.ConnectionTx(ctx, tx, org, sec.ConnectionID)
		return err
	})
	if err != nil {
		return Policy{}, err
	}
	if in.Strategy == Native {
		store, err := s.registry.Store(connectors.Connection{ID: conn.ID, OrganizationID: org, Provider: conn.Provider, Config: conn.Config})
		if err != nil {
			return Policy{}, err
		}
		if err := s.plugins[Native].Validate(ctx, store, target(sec)); err != nil {
			return Policy{}, err
		}
	}

	base := s.Now()
	if sec.LastRotatedAt != nil {
		base = *sec.LastRotatedAt
	} else if t, err := time.Parse(time.RFC3339, sec.ProviderMetadata["last_changed"]); err == nil {
		base = t
	}
	next := base.AddDate(0, 0, in.IntervalDays).UTC().Truncate(time.Microsecond)

	var p Policy
	err = postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		p, err = scanPolicy(tx.QueryRow(ctx, `INSERT INTO rotation_policies (organization_id, secret_id, strategy, interval_days,
				reminder_days, escalation_days, enabled, next_rotation_at, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
			ON CONFLICT (secret_id) DO UPDATE SET strategy = EXCLUDED.strategy, interval_days = EXCLUDED.interval_days,
				reminder_days = EXCLUDED.reminder_days, escalation_days = EXCLUDED.escalation_days, enabled = EXCLUDED.enabled,
				next_rotation_at = EXCLUDED.next_rotation_at, updated_by = EXCLUDED.updated_by, updated_at = now()
			RETURNING `+policyColumns,
			org, secretID, in.Strategy, in.IntervalDays, in.ReminderDays, in.EscalationDays, in.Enabled, next, access.Principal.UserID))
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation_policy.set", ResourceType: "secret", ResourceID: secretID.String(), Decision: audit.Allow,
			Details: map[string]string{
				"strategy": in.Strategy, "interval_days": strconv.Itoa(in.IntervalDays), "enabled": strconv.FormatBool(in.Enabled),
				"next_rotation_at": next.Format(time.RFC3339),
			},
		})
		return err
	})
	return p, err
}

func (s *Service) DeletePolicy(ctx context.Context, access auth.Access, secretID uuid.UUID) error {
	org := access.OrganizationID
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		sec, err := readable(ctx, tx, access, secretID)
		if err != nil {
			return err
		}
		if !access.CanOn(auth.SecretManage, sec.EnvironmentID) {
			return ErrForbidden
		}
		tag, err := tx.Exec(ctx, `DELETE FROM rotation_policies WHERE organization_id = $1 AND secret_id = $2`, org, secretID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNoPolicy
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation_policy.deleted", ResourceType: "secret", ResourceID: secretID.String(), Decision: audit.Allow,
		})
		return err
	})
}

// SetOwner sets (or, with uuid.Nil, clears) the person responsible for the
// secret. The owner must be a member who may read it.
func (s *Service) SetOwner(ctx context.Context, access auth.Access, secretID, owner uuid.UUID) error {
	org := access.OrganizationID
	var ownerArg *uuid.UUID
	if owner != uuid.Nil {
		ownerArg = &owner
	}
	return postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		sec, err := readable(ctx, tx, access, secretID)
		if err != nil {
			return err
		}
		if !access.CanOn(auth.SecretManage, sec.EnvironmentID) {
			return ErrForbidden
		}
		if owner != uuid.Nil {
			bindings, err := tenancy.BindingsTx(ctx, tx, org, owner)
			if err != nil {
				return err
			}
			var member bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
				WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active')`, org, owner).Scan(&member); err != nil {
				return err
			}
			oa := auth.Access{OrganizationID: org, Bindings: bindings, Principal: auth.Principal{Kind: auth.KindUser, UserID: owner}}
			if !member || !oa.CanOn(auth.SecretRead, sec.EnvironmentID) {
				return InvalidError{"the owner must be a member who can read this secret"}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE secrets SET owner_user_id = $3, updated_at = now() WHERE organization_id = $1 AND id = $2`,
			org, secretID, ownerArg); err != nil {
			return err
		}
		details := map[string]string{"owner_user_id": ""}
		if owner != uuid.Nil {
			details["owner_user_id"] = owner.String()
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "secret.owner_set", ResourceType: "secret", ResourceID: secretID.String(), Decision: audit.Allow, Details: details,
		})
		return err
	})
}

// RotateNow starts a native rotation outside the schedule. The caller must
// have re-authenticated recently (checked by the API).
func (s *Service) RotateNow(ctx context.Context, access auth.Access, secretID uuid.UUID) (Execution, error) {
	org := access.OrganizationID
	var ex Execution
	if access.Principal.Kind != auth.KindUser {
		return ex, ErrForbidden
	}
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		sec, err := readable(ctx, tx, access, secretID)
		if err != nil {
			return err
		}
		if !access.CanOn(auth.SecretManage, sec.EnvironmentID) {
			return ErrForbidden
		}
		if sec.EnvironmentKind == inventory.Production && !access.Principal.SessionMFA {
			return ErrMFARequired
		}
		p, err := policyTx(ctx, tx, org, secretID, false)
		if err != nil {
			return err
		}
		if !s.plugins[p.Strategy].Automated() {
			return InvalidError{"this secret is rotated manually: submit a change with the new value"}
		}
		if open, err := openChange(ctx, tx, org, secretID); err != nil {
			return err
		} else if open {
			return ErrChangeInProgress
		}
		ex, err = insertExecution(ctx, tx, org, secretID, "manual", s.Now(), &access.Principal.UserID, access.Principal.SessionMFA)
		if err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "rotation.requested", ResourceType: "secret", ResourceID: secretID.String(), Decision: audit.Allow,
			Details: map[string]string{"execution_id": ex.ID.String(), "trigger": "manual"},
		}); err != nil {
			return err
		}
		return s.jobs.EnqueueRotation(ctx, tx, org, ex.ID)
	})
	return ex, err
}

func openChange(ctx context.Context, tx pgx.Tx, org, secretID uuid.UUID) (bool, error) {
	var open bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM change_requests WHERE organization_id = $1 AND secret_id = $2
		AND status IN ('pending', 'approved', 'executing'))`, org, secretID).Scan(&open)
	return open, err
}

const executionColumns = `id, secret_id, trigger, requested_by, requester_mfa, status, due_at, coalesce(provider_version_id, ''),
	coalesce(cloud_request_id, ''), coalesce(error_code, ''), rotate_started_at, finished_at, created_at, updated_at`

func scanExecution(r pgx.Row) (Execution, error) {
	var e Execution
	err := r.Scan(&e.ID, &e.SecretID, &e.Trigger, &e.RequestedBy, &e.RequesterMFA, &e.Status, &e.DueAt, &e.ProviderVersionID,
		&e.CloudRequestID, &e.ErrorCode, &e.RotateStartedAt, &e.FinishedAt, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// insertExecution records a new attempt; ErrInProgress if one is open.
func insertExecution(ctx context.Context, tx pgx.Tx, org, secretID uuid.UUID, trigger string, due time.Time, by *uuid.UUID, mfa bool) (Execution, error) {
	ex, err := scanExecution(tx.QueryRow(ctx, `INSERT INTO rotation_executions (organization_id, secret_id, trigger, requested_by,
			requester_mfa, due_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+executionColumns,
		org, secretID, trigger, by, mfa, due))
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ex, ErrInProgress
	}
	return ex, err
}

// Executions lists the latest rotation attempts for a secret.
func (s *Service) Executions(ctx context.Context, access auth.Access, secretID uuid.UUID) ([]Execution, error) {
	var out []Execution
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := readable(ctx, tx, access, secretID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+executionColumns+` FROM rotation_executions
			WHERE organization_id = $1 AND secret_id = $2 ORDER BY created_at DESC LIMIT 50`, access.OrganizationID, secretID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Execution, error) { return scanExecution(r) })
		return err
	})
	return out, err
}

// Execution returns one attempt (for tests and the API).
func (s *Service) Execution(ctx context.Context, org, id uuid.UUID) (Execution, error) {
	var ex Execution
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	err := postgres.Tx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		ex, err = scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM rotation_executions
			WHERE organization_id = $1 AND id = $2`, org, id))
		return err
	})
	return ex, err
}

func target(s inventory.Secret) connectors.Target {
	return connectors.Target{ConnectionID: s.ConnectionID, Name: s.Name, ProviderRef: s.ProviderRef}
}

func days(d int) time.Duration { return time.Duration(d) * 24 * time.Hour }
