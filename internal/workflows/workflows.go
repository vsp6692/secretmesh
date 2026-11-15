// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package workflows runs background jobs on a PostgreSQL-backed queue
// (River, ADR-0005). Job arguments carry identifiers only, never secret
// values; workers re-read everything they need from the database.
package workflows

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auditexport"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/execution"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/rotation"
)

// Unique while not finished, so duplicate enqueues (e.g. from the reconciler)
// collapse into one job.
var unfinished = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
	rivertype.JobStateRunning, rivertype.JobStateScheduled,
}

type ExecuteArgs struct {
	OrganizationID  uuid.UUID `json:"organization_id"`
	ChangeRequestID uuid.UUID `json:"change_request_id"`
}

func (ExecuteArgs) Kind() string { return "execute_change_request" }
func (ExecuteArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: unfinished}}
}

type DiscardArgs struct {
	OrganizationID  uuid.UUID `json:"organization_id"`
	ChangeRequestID uuid.UUID `json:"change_request_id"`
}

func (DiscardArgs) Kind() string { return "discard_staged_value" }
func (DiscardArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: unfinished}}
}

type ExpireArgs struct{}

func (ExpireArgs) Kind() string { return "expire_change_requests" }

type ReconcileArgs struct{}

func (ReconcileArgs) Kind() string { return "reconcile_executions" }

type CheckpointArgs struct{}

func (CheckpointArgs) Kind() string { return "audit_checkpoint" }

type SyncArgs struct{}

func (SyncArgs) Kind() string { return "sync_connections" }

type ExportArgs struct{}

func (ExportArgs) Kind() string { return "audit_export" }

type RotateArgs struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	ExecutionID    uuid.UUID `json:"execution_id"`
}

func (RotateArgs) Kind() string { return "rotate_secret" }
func (RotateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: unfinished}}
}

type RotationTickArgs struct{}

func (RotationTickArgs) Kind() string { return "rotation_scheduler" }

type RotationReconcileArgs struct{}

func (RotationReconcileArgs) Kind() string { return "reconcile_rotations" }

type DeliverArgs struct{}

func (DeliverArgs) Kind() string { return "deliver_notifications" }

// Config controls which work this process does.
type Config struct {
	// Work starts workers and periodic jobs; otherwise the client only inserts.
	Work      bool
	Executor  *execution.Executor
	Approvals *approvals.Service
	Registry  *connectors.Registry
	Discovery *inventory.Discovery
	// Exporter copies checkpointed audit batches off-database; nil disables it.
	Exporter           *auditexport.Exporter
	SyncInterval       time.Duration
	Rotation           *rotation.Service
	Deliverer          *notify.Deliverer
	Keyring            keys.Keyring
	ReconcileAfter     time.Duration
	CheckpointInterval time.Duration
	Logger             *slog.Logger
}

type Client struct {
	river *river.Client[pgx.Tx]
}

func New(pool *pgxpool.Pool, cfg Config) (*Client, error) {
	if cfg.ReconcileAfter == 0 {
		cfg.ReconcileAfter = 5 * time.Minute
	}
	if cfg.CheckpointInterval == 0 {
		cfg.CheckpointInterval = 5 * time.Minute
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 15 * time.Minute
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, j *river.Job[ExecuteArgs]) error {
		return cfg.Executor.Execute(ctx, j.Args.OrganizationID, j.Args.ChangeRequestID)
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, j *river.Job[DiscardArgs]) error {
		return approvals.DiscardStaging(ctx, pool, cfg.Registry, j.Args.OrganizationID, j.Args.ChangeRequestID)
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[ExpireArgs]) error {
		_, err := cfg.Approvals.ExpireDue(ctx)
		return err
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[ReconcileArgs]) error {
		_, err := cfg.Executor.ReconcileStale(ctx, cfg.ReconcileAfter)
		return err
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[CheckpointArgs]) error {
		_, err := audit.CheckpointDue(ctx, pool, cfg.Keyring)
		return err
	}))

	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[SyncArgs]) error {
		if cfg.Discovery == nil {
			return nil
		}
		return cfg.Discovery.SyncDue(ctx, cfg.SyncInterval)
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[ExportArgs]) error {
		if cfg.Exporter == nil {
			return nil
		}
		_, err := cfg.Exporter.ExportDue(ctx)
		return err
	}))

	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, j *river.Job[RotateArgs]) error {
		err := cfg.Rotation.Run(ctx, j.Args.OrganizationID, j.Args.ExecutionID)
		var pending *rotation.PendingError
		if errors.As(err, &pending) {
			return river.JobSnooze(pending.After)
		}
		return err
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[RotationTickArgs]) error {
		if cfg.Rotation == nil {
			return nil
		}
		_, err := cfg.Rotation.Tick(ctx)
		return err
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[RotationReconcileArgs]) error {
		if cfg.Rotation == nil {
			return nil
		}
		_, err := cfg.Rotation.ReconcileStale(ctx, cfg.ReconcileAfter)
		return err
	}))
	river.AddWorker(workers, river.WorkFunc(func(ctx context.Context, _ *river.Job[DeliverArgs]) error {
		if cfg.Deliverer == nil {
			return nil
		}
		_, err := cfg.Deliverer.DeliverDue(ctx)
		return err
	}))

	rc := &river.Config{
		Workers:     workers,
		MaxAttempts: 10,
		Logger:      slog.New(&levelFloor{h: cfg.Logger.Handler(), min: slog.LevelWarn}),
	}
	if cfg.Work {
		rc.Queues = map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 10}}
		every := func(d time.Duration, args river.JobArgs) *river.PeriodicJob {
			return river.NewPeriodicJob(river.PeriodicInterval(d),
				func() (river.JobArgs, *river.InsertOpts) { return args, nil },
				&river.PeriodicJobOpts{RunOnStart: true})
		}
		rc.PeriodicJobs = []*river.PeriodicJob{
			every(time.Minute, ExpireArgs{}),
			every(time.Minute, ReconcileArgs{}),
			every(cfg.CheckpointInterval, CheckpointArgs{}),
			every(time.Minute, SyncArgs{}),
			every(time.Minute, RotationTickArgs{}),
			every(time.Minute, RotationReconcileArgs{}),
			every(15*time.Second, DeliverArgs{}),
		}
		if cfg.Exporter != nil {
			rc.PeriodicJobs = append(rc.PeriodicJobs, every(cfg.CheckpointInterval, ExportArgs{}))
		}
	}
	rc2, err := river.NewClient(riverpgxv5.New(pool), rc)
	if err != nil {
		return nil, err
	}
	return &Client{river: rc2}, nil
}

func (c *Client) Start(ctx context.Context) error { return c.river.Start(ctx) }
func (c *Client) Stop(ctx context.Context) error  { return c.river.Stop(ctx) }

// EnqueueExecution implements approvals.Jobs.
func (c *Client) EnqueueExecution(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) error {
	_, err := c.river.InsertTx(ctx, tx, ExecuteArgs{OrganizationID: org, ChangeRequestID: id}, nil)
	return err
}

// EnqueueRotation implements rotation.Jobs.
func (c *Client) EnqueueRotation(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) error {
	_, err := c.river.InsertTx(ctx, tx, RotateArgs{OrganizationID: org, ExecutionID: id}, nil)
	return err
}

// EnqueueDiscard implements approvals.Jobs.
func (c *Client) EnqueueDiscard(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) error {
	_, err := c.river.InsertTx(ctx, tx, DiscardArgs{OrganizationID: org, ChangeRequestID: id}, nil)
	return err
}

// levelFloor drops River's records below min (it is chatty at Info).
type levelFloor struct {
	h   slog.Handler
	min slog.Level
}

func (l *levelFloor) Enabled(ctx context.Context, lvl slog.Level) bool {
	return lvl >= l.min && l.h.Enabled(ctx, lvl)
}
func (l *levelFloor) Handle(ctx context.Context, r slog.Record) error { return l.h.Handle(ctx, r) }
func (l *levelFloor) WithAttrs(a []slog.Attr) slog.Handler {
	return &levelFloor{h: l.h.WithAttrs(a), min: l.min}
}
func (l *levelFloor) WithGroup(n string) slog.Handler {
	return &levelFloor{h: l.h.WithGroup(n), min: l.min}
}
