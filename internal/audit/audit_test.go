package audit_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/platform/postgres/pgtest"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func newOrg(t *testing.T, owner *pgxpool.Pool, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(context.Background(),
		`INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func appendN(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, n int) {
	t.Helper()
	ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: org})
	for i := range n {
		err := postgres.Tx(ctx, pool, func(tx pgx.Tx) error {
			_, err := audit.Append(ctx, tx, org, audit.Event{
				Action: "test.event", ResourceType: "thing", ResourceID: uuid.NewString(),
				Decision: audit.Allow, Details: map[string]string{"n": string(rune('a' + i))},
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, pool *pgxpool.Pool, kr keys.Keyring, org uuid.UUID) audit.Report {
	t.Helper()
	ctx := postgres.WithScope(context.Background(), postgres.Scope{OrganizationID: org})
	var rep audit.Report
	err := postgres.Tx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		rep, err = audit.Verify(ctx, tx, kr, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestAuditChain(t *testing.T) {
	db := pgtest.New(t)
	kr, _ := keys.NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{3}, 32)))
	ctx := context.Background()
	org, other := newOrg(t, db.Owner, "org-a"), newOrg(t, db.Owner, "org-b")

	appendN(t, db.App, org, 5)
	appendN(t, db.App, other, 2)
	if n, err := audit.CheckpointDue(ctx, db.App, kr); err != nil || n != 2 {
		t.Fatalf("checkpoints: %d %v", n, err)
	}
	appendN(t, db.App, org, 2)

	rep := verify(t, db.App, kr, org)
	if !rep.Valid || rep.EventsChecked != 7 || rep.CheckpointsVerified != 1 || rep.LastCheckpointSeq != 5 {
		t.Fatalf("fresh chain: %+v", rep)
	}
	if r := verify(t, db.App, kr, other); !r.Valid || r.EventsChecked != 2 {
		t.Fatalf("chains are per organization: %+v", r)
	}

	t.Run("sensitive detail keys are refused", func(t *testing.T) {
		scoped := postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
		err := postgres.Tx(scoped, db.App, func(tx pgx.Tx) error {
			_, err := audit.Append(scoped, tx, org, audit.Event{Action: "x", ResourceType: "x", ResourceID: "x",
				Details: map[string]string{"secret_value": "nope"}})
			return err
		})
		if !errors.Is(err, audit.ErrSensitiveDetail) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("runtime role cannot change or delete events", func(t *testing.T) {
		// RLS has no UPDATE/DELETE policy for the ledger, so these match no
		// rows; the append-only triggers back that up for any role that can
		// see the rows.
		scoped := postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
		for _, stmt := range []string{
			`UPDATE audit_events SET action = 'hidden' WHERE seq = 1`,
			`DELETE FROM audit_events WHERE seq = 7`,
			`UPDATE audit_checkpoints SET seq = 6`,
			`DELETE FROM audit_checkpoints`,
		} {
			err := postgres.Tx(scoped, db.App, func(tx pgx.Tx) error {
				tag, err := tx.Exec(scoped, stmt)
				if err == nil && tag.RowsAffected() != 0 {
					t.Errorf("%q changed %d rows", stmt, tag.RowsAffected())
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.App.Exec(ctx, `TRUNCATE audit_events`); err == nil {
			t.Error("truncate succeeded")
		}
		if r := verify(t, db.App, kr, org); !r.Valid || r.EventsChecked != 7 {
			t.Fatalf("ledger changed: %+v", r)
		}
	})

	t.Run("triggers block changes even by a role that sees the rows", func(t *testing.T) {
		for _, stmt := range []string{
			`UPDATE audit_events SET action = 'hidden' WHERE seq = 1`,
			`DELETE FROM audit_checkpoints`,
		} {
			if _, err := db.Owner.Exec(ctx, stmt); err == nil {
				t.Errorf("%q succeeded without disabling the trigger", stmt)
			}
		}
	})

	// The schema owner can bypass the triggers. Verification must still catch it.
	ownerTamper := func(t *testing.T, stmts ...string) {
		t.Helper()
		tx, err := db.Owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, s := range []string{
			`ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`,
			`ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_append_only`,
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s, org); err != nil {
				t.Fatal(err)
			}
		}
		// Verify inside the (rolled back) tampering transaction.
		r, err := audit.Verify(ctx, tx, kr, org)
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid {
			t.Fatalf("tampering not detected: %+v", r)
		}
		t.Logf("detected at seq %d: %s", r.FirstInvalidSeq, r.Problem)
	}

	t.Run("edited event is detected", func(t *testing.T) {
		ownerTamper(t, `UPDATE audit_events SET details = '{"n":"z"}' WHERE organization_id = $1 AND seq = 3`)
	})
	t.Run("deleted event is detected", func(t *testing.T) {
		ownerTamper(t, `DELETE FROM audit_events WHERE organization_id = $1 AND seq = 4`)
	})
	t.Run("rewritten tail is caught by the signed checkpoint", func(t *testing.T) {
		// Delete everything after seq 2 and the head, as if rebuilding history;
		// the checkpoint at seq 5 no longer matches.
		ownerTamper(t,
			`DELETE FROM audit_events WHERE organization_id = $1 AND seq > 2`,
			`UPDATE audit_heads SET seq = 2, hash = (SELECT hash FROM audit_events WHERE organization_id = $1 AND seq = 2) WHERE organization_id = $1`)
	})
	t.Run("forged checkpoint signature is detected", func(t *testing.T) {
		ownerTamper(t, `UPDATE audit_checkpoints SET signature = '\x00' WHERE organization_id = $1`)
	})

	if r := verify(t, db.App, kr, org); !r.Valid {
		t.Fatalf("rolled-back tampering left damage: %+v", r)
	}
}
