package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// Discovery tags let customers place secrets without touching SecretMesh.
const (
	TagEnvironment    = "secretmesh:environment"
	TagClassification = "secretmesh:classification"
)

// ErrDiscoveryUnsupported is returned for providers that cannot list secrets.
var ErrDiscoveryUnsupported = errors.New("provider does not support discovery")

// SyncResult summarizes one discovery run.
type SyncResult struct {
	// Rotated counts known secrets whose current version changed.
	Rotated    int
	Imported   int
	Updated    int
	Removed    int
	Unassigned int
}

// Discovery synchronizes secret metadata from providers. It reads metadata
// only (ListSecrets); values never leave the provider.
type Discovery struct {
	pool     *pgxpool.Pool
	registry *connectors.Registry
	logger   *slog.Logger
}

func NewDiscovery(pool *pgxpool.Pool, registry *connectors.Registry, logger *slog.Logger) *Discovery {
	return &Discovery{pool: pool, registry: registry, logger: logger}
}

// Sync imports new secrets, refreshes known ones and marks secrets that
// disappeared from the provider as deleted.
//
// New secrets go to the environment named by their secretmesh:environment tag,
// or the connection's default environment; without either they are counted
// as unassigned and skipped. Classification comes from the
// secretmesh:classification tag (default confidential). Existing secrets keep
// their environment and classification.
func (d *Discovery) Sync(ctx context.Context, org, connID uuid.UUID) (SyncResult, error) {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	var res SyncResult
	var conn Connection
	var envs map[string]uuid.UUID
	var started time.Time
	err := postgres.Tx(ctx, d.pool, func(tx pgx.Tx) error {
		var err error
		if conn, err = ConnectionTx(ctx, tx, org, connID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&started); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT name, id FROM environments WHERE organization_id = $1`, org)
		if err != nil {
			return err
		}
		envs = map[string]uuid.UUID{}
		for rows.Next() {
			var name string
			var id uuid.UUID
			if err := rows.Scan(&name, &id); err != nil {
				return err
			}
			envs[name] = id
		}
		return rows.Err()
	})
	if err != nil {
		return res, err
	}

	store, err := d.registry.Store(connectors.Connection{ID: conn.ID, OrganizationID: org, Provider: conn.Provider, Config: conn.Config})
	if err != nil {
		return res, err
	}
	if !store.Capabilities().Discovery {
		return res, ErrDiscoveryUnsupported
	}
	var found []connectors.SecretInfo
	if err := store.List(ctx, func(s connectors.SecretInfo) error { found = append(found, s); return nil }); err != nil {
		d.recordFailure(ctx, org, connID, err)
		return res, err
	}

	err = postgres.Tx(ctx, d.pool, func(tx pgx.Tx) error {
		for _, s := range found {
			meta := map[string]string{"kms_key_id": s.KMSKeyID, "rotation_enabled": strconv.FormatBool(s.RotationEnabled)}
			if s.LastChanged != nil {
				meta["last_changed"] = s.LastChanged.UTC().Format(time.RFC3339)
			}
			var id uuid.UUID
			var changed bool
			err := tx.QueryRow(ctx, `WITH old AS (
					SELECT id, current_version FROM secrets
					WHERE organization_id = $1 AND connection_id = $2 AND provider_ref = $3 AND status = 'active' FOR UPDATE)
				UPDATE secrets s SET description = $4, tags = $5, provider_metadata = $6,
					current_version = nullif($7, ''), last_seen_at = now(), updated_at = now()
				FROM old WHERE s.id = old.id
				RETURNING s.id, old.current_version IS NOT NULL AND old.current_version IS DISTINCT FROM s.current_version`,
				org, connID, s.ProviderRef, s.Description, s.Tags, meta, s.CurrentVersion).Scan(&id, &changed)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				res.Updated++
				if changed {
					// Changed outside SecretMesh (e.g. the provider's own
					// rotation schedule): counts as rotated.
					at := time.Now()
					if s.LastChanged != nil {
						at = *s.LastChanged
					}
					if err := MarkRotatedTx(ctx, tx, org, id, at, ""); err != nil {
						return err
					}
					res.Rotated++
				}
				continue
			}
			env, ok := envs[s.Tags[TagEnvironment]]
			if !ok && conn.DefaultEnvironmentID != nil {
				env, ok = *conn.DefaultEnvironmentID, true
			}
			if !ok {
				res.Unassigned++
				continue
			}
			class := Classification(s.Tags[TagClassification])
			if !class.Valid() {
				class = Confidential
			}
			tag, err := tx.Exec(ctx, `INSERT INTO secrets (organization_id, connection_id, environment_id, name, provider_ref,
					classification, current_version, origin, description, tags, provider_metadata, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, nullif($7, ''), 'discovered', $8, $9, $10, now())
				ON CONFLICT DO NOTHING`,
				org, connID, env, s.Name, s.ProviderRef, class, s.CurrentVersion, s.Description, s.Tags, meta)
			if err != nil {
				return err
			}
			res.Imported += int(tag.RowsAffected())
		}
		// Secrets that existed before this run and were not listed are gone.
		tag, err := tx.Exec(ctx, `UPDATE secrets SET status = 'deleted', updated_at = now()
			WHERE organization_id = $1 AND connection_id = $2 AND status = 'active'
			  AND created_at < $3 AND (last_seen_at IS NULL OR last_seen_at < $3)`, org, connID, started)
		if err != nil {
			return err
		}
		res.Removed = int(tag.RowsAffected())
		if _, err := tx.Exec(ctx, `UPDATE connections SET last_synced_at = now(), last_sync_error = NULL
			WHERE organization_id = $1 AND id = $2`, org, connID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, org, audit.Event{
			Action: "connection.synced", ResourceType: "connection", ResourceID: connID.String(), Decision: audit.Allow,
			Details: map[string]string{
				"imported": strconv.Itoa(res.Imported), "updated": strconv.Itoa(res.Updated),
				"removed": strconv.Itoa(res.Removed), "unassigned": strconv.Itoa(res.Unassigned), "rotated": strconv.Itoa(res.Rotated),
			},
		})
		return err
	})
	return res, err
}

func (d *Discovery) recordFailure(ctx context.Context, org, connID uuid.UUID, cause error) {
	msg := "provider error"
	switch {
	case errors.Is(cause, connectors.ErrAccessDenied):
		msg = "access denied: check the role's trust policy, ExternalId and permissions"
	case errors.Is(cause, connectors.ErrTransient):
		msg = "provider temporarily unavailable"
	}
	err := postgres.Tx(ctx, d.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE connections SET last_synced_at = now(), last_sync_error = $3
			WHERE organization_id = $1 AND id = $2`, org, connID, msg); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, org, audit.Event{
			Action: "connection.sync_failed", ResourceType: "connection", ResourceID: connID.String(),
			Decision: audit.Deny, Details: map[string]string{"error": msg},
		})
		return err
	})
	if err != nil {
		d.logger.WarnContext(ctx, "record sync failure", "connection_id", connID, "error", err)
	}
	d.logger.WarnContext(ctx, "discovery failed", "connection_id", connID, "error", cause)
}

// SyncDue syncs every active connection not synced within interval.
func (d *Discovery) SyncDue(ctx context.Context, interval time.Duration) error {
	rows, err := d.pool.Query(ctx, `SELECT organization_id, connection_id FROM secretmesh_connections_to_sync($1)`, interval)
	if err != nil {
		return err
	}
	type item struct{ org, conn uuid.UUID }
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var i item
		return i, r.Scan(&i.org, &i.conn)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, it := range items {
		if _, err := d.Sync(ctx, it.org, it.conn); err != nil && !errors.Is(err, ErrDiscoveryUnsupported) {
			errs = append(errs, fmt.Errorf("sync %s: %w", it.conn, err))
		}
	}
	return errors.Join(errs...)
}
