// Package auditexport copies signed audit batches to write-once storage
// (S3 Object Lock), outside the reach of SecretMesh's database and its
// owner (blueprint §10.2, ADR-0010).
//
// Each object holds the events since the previous export up to and including
// a signed checkpoint, one JSON document per line, ending with the checkpoint.
// The chain can be re-verified from the objects alone.
package auditexport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// ObjectStore writes objects that cannot be changed or deleted before
// retainUntil.
type ObjectStore interface {
	PutLocked(ctx context.Context, key string, body []byte, retainUntil time.Time) (location, version string, err error)
}

type Exporter struct {
	pool      *pgxpool.Pool
	store     ObjectStore
	retention time.Duration
	logger    *slog.Logger
}

func New(pool *pgxpool.Pool, store ObjectStore, retention time.Duration, logger *slog.Logger) *Exporter {
	return &Exporter{pool: pool, store: store, retention: retention, logger: logger}
}

type line struct {
	Type            string            `json:"type"`
	OrganizationID  string            `json:"organization_id"`
	Seq             int64             `json:"seq"`
	ID              string            `json:"id,omitempty"`
	OccurredAt      string            `json:"occurred_at,omitempty"`
	ActorType       string            `json:"actor_type,omitempty"`
	ActorID         string            `json:"actor_id,omitempty"`
	ActorTokenID    string            `json:"actor_token_id,omitempty"`
	Action          string            `json:"action,omitempty"`
	ResourceType    string            `json:"resource_type,omitempty"`
	ResourceID      string            `json:"resource_id,omitempty"`
	Decision        string            `json:"decision,omitempty"`
	ChangeRequestID string            `json:"change_request_id,omitempty"`
	CloudRequestID  string            `json:"cloud_request_id,omitempty"`
	Details         map[string]string `json:"details,omitempty"`
	PrevHash        string            `json:"prev_hash,omitempty"`
	Hash            string            `json:"hash,omitempty"`
	// Checkpoint fields.
	HeadHash  string `json:"head_hash,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func idString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// ExportDue exports every organization with a checkpoint newer than its last
// export. It returns the number of objects written.
func (e *Exporter) ExportDue(ctx context.Context) (int, error) {
	rows, err := e.pool.Query(ctx, `SELECT organization_id FROM secretmesh_audit_exports_due()`)
	if err != nil {
		return 0, err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, org := range orgs {
		if err := e.export(ctx, org); err != nil {
			errs = append(errs, fmt.Errorf("export %s: %w", org, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (e *Exporter) export(ctx context.Context, org uuid.UUID) error {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	return postgres.Tx(ctx, e.pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(to_seq), 0) + 1 FROM audit_exports WHERE organization_id = $1`,
			org).Scan(&from); err != nil {
			return err
		}
		var cp line
		var head, sig []byte
		var created time.Time
		err := tx.QueryRow(ctx, `SELECT seq, head_hash, created_at, key_id, signature FROM audit_checkpoints
			WHERE organization_id = $1 AND seq >= $2 ORDER BY seq DESC LIMIT 1`, org, from).
			Scan(&cp.Seq, &head, &created, &cp.KeyID, &sig)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		events, err := audit.Range(ctx, tx, org, from, cp.Seq)
		if err != nil {
			return err
		}
		if int64(len(events)) != cp.Seq-from+1 {
			return fmt.Errorf("audit events %d-%d incomplete (%d found); refusing to export a gap", from, cp.Seq, len(events))
		}

		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, r := range events {
			if err := enc.Encode(line{
				Type: "event", OrganizationID: org.String(), Seq: r.Seq, ID: r.ID.String(),
				OccurredAt: r.OccurredAt.UTC().Format(time.RFC3339Nano), ActorType: r.ActorType,
				ActorID: idString(r.ActorID), ActorTokenID: idString(r.ActorTokenID), Action: r.Action,
				ResourceType: r.ResourceType, ResourceID: r.ResourceID, Decision: string(r.Decision),
				ChangeRequestID: idString(r.ChangeRequestID), CloudRequestID: r.CloudRequestID, Details: r.Details,
				PrevHash: hex.EncodeToString(r.PrevHash), Hash: hex.EncodeToString(r.Hash),
			}); err != nil {
				return err
			}
		}
		cp.Type, cp.OrganizationID = "checkpoint", org.String()
		cp.HeadHash, cp.CreatedAt = hex.EncodeToString(head), created.UTC().Format(time.RFC3339Nano)
		cp.Signature = base64.StdEncoding.EncodeToString(sig)
		if err := enc.Encode(cp); err != nil {
			return err
		}

		key := fmt.Sprintf("%s/%012d-%012d.jsonl", org, from, cp.Seq)
		retain := time.Now().Add(e.retention).UTC().Truncate(time.Second)
		location, version, err := e.store.PutLocked(ctx, key, buf.Bytes(), retain)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_exports (organization_id, from_seq, to_seq, location, object_version, retain_until)
			VALUES ($1, $2, $3, $4, $5, $6)`, org, from, cp.Seq, location, version, retain)
		if err == nil {
			e.logger.InfoContext(ctx, "audit exported", "organization_id", org, "from_seq", from, "to_seq", cp.Seq)
		}
		return err
	})
}
