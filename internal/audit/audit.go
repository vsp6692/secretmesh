// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package audit maintains the per-organization, hash-chained security event
// ledger (blueprint §10.2, ADR-0009).
//
// Each event is hashed together with its predecessor's hash. Periodic
// checkpoints sign the chain head, so rewriting history, even by the database
// owner, is detectable. Events never contain secret values: details are flat
// string maps and keys that look sensitive are rejected.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/pkg/telemetry"
)

type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
	None  Decision = "none"
)

// Event is what callers record.
type Event struct {
	Action          string // e.g. "change_request.approved"
	ResourceType    string
	ResourceID      string
	Decision        Decision
	ChangeRequestID uuid.UUID
	CloudRequestID  string
	Details         map[string]string
}

// Record is a stored event.
type Record struct {
	Event
	OrganizationID uuid.UUID
	Seq            int64
	ID             uuid.UUID
	OccurredAt     time.Time
	ActorType      string
	ActorID        uuid.UUID
	ActorTokenID   uuid.UUID
	PrevHash       []byte
	Hash           []byte
}

// ErrSensitiveDetail is returned when an event detail key could carry secret material.
var ErrSensitiveDetail = errors.New("audit details must not contain sensitive keys")

// Append adds ev to org's chain within tx, so the event commits or rolls back
// together with the change it records. The actor is taken from ctx (the
// authenticated principal); without one, the actor is "system".
func Append(ctx context.Context, tx pgx.Tx, org uuid.UUID, ev Event) (Record, error) {
	for k := range ev.Details {
		if telemetry.IsSensitiveKey(k) {
			return Record{}, fmt.Errorf("%w: %q", ErrSensitiveDetail, k)
		}
	}
	if ev.Decision == "" {
		ev.Decision = None
	}
	if ev.Details == nil {
		ev.Details = map[string]string{}
	}
	r := Record{
		Event:          ev,
		OrganizationID: org,
		ID:             uuid.New(),
		OccurredAt:     time.Now().UTC().Truncate(time.Microsecond),
		ActorType:      "system",
	}
	if p, ok := auth.PrincipalFrom(ctx); ok {
		switch p.Kind {
		case auth.KindUser:
			r.ActorType, r.ActorID = "user", p.UserID
		case auth.KindAPIToken:
			r.ActorType, r.ActorID, r.ActorTokenID = "api_token", p.UserID, p.TokenID
		}
	}

	genesis := Genesis(org)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_heads (organization_id, seq, hash) VALUES ($1, 0, $2)
		ON CONFLICT (organization_id) DO NOTHING`, org, genesis[:]); err != nil {
		return Record{}, fmt.Errorf("audit head: %w", err)
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE organization_id = $1 FOR UPDATE`,
		org).Scan(&seq, &r.PrevHash); err != nil {
		return Record{}, fmt.Errorf("lock audit head: %w", err)
	}
	r.Seq = seq + 1
	r.Hash = r.computeHash()

	details, _ := json.Marshal(r.Details)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (organization_id, seq, id, occurred_at, actor_type, actor_id, actor_token_id,
			action, resource_type, resource_id, decision, change_request_id, cloud_request_id, details, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		r.OrganizationID, r.Seq, r.ID, r.OccurredAt, r.ActorType, nullUUID(r.ActorID), nullUUID(r.ActorTokenID),
		r.Action, r.ResourceType, r.ResourceID, string(r.Decision), nullUUID(r.ChangeRequestID), r.CloudRequestID,
		details, r.PrevHash, r.Hash); err != nil {
		return Record{}, fmt.Errorf("insert audit event: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_heads SET seq = $2, hash = $3 WHERE organization_id = $1`,
		org, r.Seq, r.Hash); err != nil {
		return Record{}, fmt.Errorf("advance audit head: %w", err)
	}
	return r, nil
}

// Genesis is the predecessor hash of an organization's first event.
func Genesis(org uuid.UUID) [32]byte {
	return sha256.Sum256([]byte("secretmesh/audit/v1/genesis/" + org.String()))
}

// canonical is the hashed representation. Field order is fixed by the struct;
// Details is a map, which encoding/json serializes with sorted keys.
type canonical struct {
	V               int               `json:"v"`
	OrganizationID  string            `json:"organization_id"`
	Seq             int64             `json:"seq"`
	ID              string            `json:"id"`
	OccurredAt      string            `json:"occurred_at"`
	ActorType       string            `json:"actor_type"`
	ActorID         string            `json:"actor_id"`
	ActorTokenID    string            `json:"actor_token_id"`
	Action          string            `json:"action"`
	ResourceType    string            `json:"resource_type"`
	ResourceID      string            `json:"resource_id"`
	Decision        string            `json:"decision"`
	ChangeRequestID string            `json:"change_request_id"`
	CloudRequestID  string            `json:"cloud_request_id"`
	Details         map[string]string `json:"details"`
}

func (r Record) computeHash() []byte {
	b, _ := json.Marshal(canonical{
		V:               1,
		OrganizationID:  r.OrganizationID.String(),
		Seq:             r.Seq,
		ID:              r.ID.String(),
		OccurredAt:      r.OccurredAt.UTC().Format(time.RFC3339Nano),
		ActorType:       r.ActorType,
		ActorID:         uuidString(r.ActorID),
		ActorTokenID:    uuidString(r.ActorTokenID),
		Action:          r.Action,
		ResourceType:    r.ResourceType,
		ResourceID:      r.ResourceID,
		Decision:        string(r.Decision),
		ChangeRequestID: uuidString(r.ChangeRequestID),
		CloudRequestID:  r.CloudRequestID,
		Details:         r.Details,
	})
	h := sha256.New()
	h.Write(r.PrevHash)
	h.Write(b)
	return h.Sum(nil)
}

func uuidString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

const recordColumns = `seq, id, occurred_at, actor_type, actor_id, actor_token_id, action, resource_type,
	resource_id, decision, change_request_id, cloud_request_id, details, prev_hash, hash`

func scanRecord(org uuid.UUID, row pgx.Row) (Record, error) {
	r := Record{OrganizationID: org}
	var actorID, tokenID, crID *uuid.UUID
	var decision string
	err := row.Scan(&r.Seq, &r.ID, &r.OccurredAt, &r.ActorType, &actorID, &tokenID, &r.Action, &r.ResourceType,
		&r.ResourceID, &decision, &crID, &r.CloudRequestID, &r.Details, &r.PrevHash, &r.Hash)
	r.Decision = Decision(decision)
	if actorID != nil {
		r.ActorID = *actorID
	}
	if tokenID != nil {
		r.ActorTokenID = *tokenID
	}
	if crID != nil {
		r.ChangeRequestID = *crID
	}
	return r, err
}

// List returns up to limit events with seq < before (0: newest), newest first.
func List(ctx context.Context, tx pgx.Tx, org uuid.UUID, before int64, limit int) ([]Record, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := tx.Query(ctx, `SELECT `+recordColumns+` FROM audit_events
		WHERE organization_id = $1 AND seq < $2 ORDER BY seq DESC LIMIT $3`, org, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) { return scanRecord(org, row) })
}

// Range returns events from..to (inclusive), oldest first.
func Range(ctx context.Context, tx pgx.Tx, org uuid.UUID, from, to int64) ([]Record, error) {
	rows, err := tx.Query(ctx, `SELECT `+recordColumns+` FROM audit_events
		WHERE organization_id = $1 AND seq BETWEEN $2 AND $3 ORDER BY seq`, org, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) { return scanRecord(org, row) })
}
