package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// Report is the result of verifying an organization's chain.
type Report struct {
	Valid               bool
	EventsChecked       int64
	HeadSeq             int64
	HeadHash            []byte
	CheckpointsVerified int
	LastCheckpointSeq   int64
	FirstInvalidSeq     int64
	Problem             string
}

// Verify recomputes the whole chain and checks every checkpoint signature and
// head hash. It reports the first problem found.
func Verify(ctx context.Context, tx pgx.Tx, kr keys.Keyring, org uuid.UUID) (Report, error) {
	rep := Report{Valid: true}
	fail := func(seq int64, format string, args ...any) {
		if rep.Valid {
			rep.Valid, rep.FirstInvalidSeq, rep.Problem = false, seq, fmt.Sprintf(format, args...)
		}
	}

	rows, err := tx.Query(ctx, `SELECT `+recordColumns+` FROM audit_events WHERE organization_id = $1 ORDER BY seq`, org)
	if err != nil {
		return rep, err
	}
	genesis := Genesis(org)
	prev := genesis[:]
	hashes := map[int64][]byte{}
	var expected int64 = 1
	for rows.Next() {
		r, err := scanRecord(org, rows)
		if err != nil {
			rows.Close()
			return rep, err
		}
		rep.EventsChecked++
		switch {
		case r.Seq != expected:
			fail(expected, "event %d is missing", expected)
		case !bytes.Equal(r.PrevHash, prev):
			fail(r.Seq, "event %d does not link to its predecessor", r.Seq)
		case !bytes.Equal(r.computeHash(), r.Hash):
			fail(r.Seq, "event %d content does not match its hash", r.Seq)
		}
		hashes[r.Seq] = r.Hash
		prev, expected = r.Hash, r.Seq+1
		rep.HeadSeq, rep.HeadHash = r.Seq, r.Hash
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}

	var headSeq int64
	var headHash []byte
	err = tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE organization_id = $1`, org).Scan(&headSeq, &headHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return rep, err
	}
	if err == nil && (headSeq != rep.HeadSeq || !bytes.Equal(headHash, rep.HeadHash)) {
		fail(rep.HeadSeq+1, "chain head (seq %d) does not match the last event (seq %d)", headSeq, rep.HeadSeq)
	}

	cps, err := tx.Query(ctx, `SELECT seq, head_hash, created_at, key_id, signature FROM audit_checkpoints
		WHERE organization_id = $1 ORDER BY seq`, org)
	if err != nil {
		return rep, err
	}
	defer cps.Close()
	for cps.Next() {
		var seq int64
		var head, sig []byte
		var created time.Time
		var keyID string
		if err := cps.Scan(&seq, &head, &created, &keyID, &sig); err != nil {
			return rep, err
		}
		if err := kr.Verify(ctx, keyID, checkpointMessage(org, seq, head, created), sig); err != nil {
			fail(seq, "checkpoint at seq %d has an invalid signature", seq)
			continue
		}
		if h, ok := hashes[seq]; !ok || !bytes.Equal(h, head) {
			fail(seq, "checkpoint at seq %d does not match the chain", seq)
			continue
		}
		rep.CheckpointsVerified++
		rep.LastCheckpointSeq = seq
	}
	return rep, cps.Err()
}

func checkpointMessage(org uuid.UUID, seq int64, head []byte, created time.Time) []byte {
	return []byte("secretmesh/audit-checkpoint/v1\n" + org.String() + "\n" + strconv.FormatInt(seq, 10) + "\n" +
		hex.EncodeToString(head) + "\n" + created.UTC().Format(time.RFC3339Nano))
}

// Checkpoint signs the current chain head if it moved since the last
// checkpoint. It reports whether a checkpoint was written.
func Checkpoint(ctx context.Context, tx pgx.Tx, kr keys.Keyring, org uuid.UUID) (bool, error) {
	var seq int64
	var head []byte
	err := tx.QueryRow(ctx, `
		SELECT h.seq, h.hash FROM audit_heads h
		WHERE h.organization_id = $1
		  AND h.seq > coalesce((SELECT max(seq) FROM audit_checkpoints WHERE organization_id = $1), 0)
		FOR UPDATE`, org).Scan(&seq, &head)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	created := time.Now().UTC().Truncate(time.Microsecond)
	keyID, sig, err := kr.Sign(ctx, checkpointMessage(org, seq, head, created))
	if err != nil {
		return false, fmt.Errorf("sign checkpoint: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_checkpoints (organization_id, seq, head_hash, created_at, key_id, signature)
		VALUES ($1, $2, $3, $4, $5, $6)`, org, seq, head, created, keyID, sig)
	return err == nil, err
}

// CheckpointDue writes a checkpoint for every organization whose chain moved
// since its last checkpoint. Organizations are found through a SECURITY
// DEFINER function; each checkpoint is written under its own scope.
func CheckpointDue(ctx context.Context, pool *pgxpool.Pool, kr keys.Keyring) (int, error) {
	rows, err := pool.Query(ctx, `SELECT organization_id FROM secretmesh_audit_checkpoints_due()`)
	if err != nil {
		return 0, err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	n := 0
	for _, org := range orgs {
		ctx := postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
		err := postgres.Tx(ctx, pool, func(tx pgx.Tx) error {
			ok, err := Checkpoint(ctx, tx, kr, org)
			if ok {
				n++
			}
			return err
		})
		if err != nil {
			return n, fmt.Errorf("checkpoint %s: %w", org, err)
		}
	}
	return n, nil
}
