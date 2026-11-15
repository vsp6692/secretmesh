// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package auditexport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auditexport"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/platform/postgres/pgtest"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func TestExportToObjectLock(t *testing.T) {
	endpoint := os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECRETMESH_TEST_AWS_ENDPOINT not set")
	}
	db := pgtest.New(t)
	ctx := context.Background()
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})

	plain := "plain-" + uuid.NewString()[:8]
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(plain)}); err != nil {
		t.Fatal(err)
	}
	if _, err := auditexport.NewS3(ctx, client, plain, "", "COMPLIANCE"); err == nil {
		t.Fatal("bucket without Object Lock accepted")
	}
	bucket := "audit-" + uuid.NewString()[:8]
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket), ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	store, err := auditexport.NewS3(ctx, client, bucket, "secretmesh-audit", "COMPLIANCE")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	exporter := auditexport.New(db.App, store, 24*time.Hour, logger)
	kr, _ := keys.NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{5}, 32)))

	var org uuid.UUID
	if err := db.Owner.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ('exp', 'Exp') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	scoped := postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	appendEvents := func(n int) {
		for range n {
			if err := postgres.Tx(scoped, db.App, func(tx pgx.Tx) error {
				_, err := audit.Append(scoped, tx, org, audit.Event{Action: "test", ResourceType: "x", ResourceID: "y"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := audit.CheckpointDue(ctx, db.App, kr); err != nil {
			t.Fatal(err)
		}
	}

	appendEvents(3)
	if n, err := exporter.ExportDue(ctx); err != nil || n != 1 {
		t.Fatalf("export: %d %v", n, err)
	}
	if n, err := exporter.ExportDue(ctx); err != nil || n != 0 {
		t.Fatalf("re-export without new checkpoint: %d %v", n, err)
	}
	appendEvents(2)
	if n, err := exporter.ExportDue(ctx); err != nil || n != 1 {
		t.Fatalf("second export: %d %v", n, err)
	}

	var exports []struct {
		from, to int64
		loc, ver string
	}
	err = postgres.Tx(scoped, db.App, func(tx pgx.Tx) error {
		rows, err := tx.Query(scoped, `SELECT from_seq, to_seq, location, object_version FROM audit_exports ORDER BY to_seq`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e struct {
				from, to int64
				loc, ver string
			}
			if err := rows.Scan(&e.from, &e.to, &e.loc, &e.ver); err != nil {
				return err
			}
			exports = append(exports, e)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 2 || exports[0].from != 1 || exports[0].to != 3 || exports[1].from != 4 || exports[1].to != 5 {
		t.Fatalf("exports: %+v", exports)
	}

	key := strings.TrimPrefix(exports[0].loc, "s3://"+bucket+"/")
	obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(obj.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 3 events + checkpoint, got %d lines", len(lines))
	}
	var last struct {
		Type      string `json:"type"`
		Signature string `json:"signature"`
		HeadHash  string `json:"head_hash"`
	}
	_ = json.Unmarshal([]byte(lines[3]), &last)
	if last.Type != "checkpoint" || last.Signature == "" || last.HeadHash == "" {
		t.Fatalf("last line: %s", lines[3])
	}
	if obj.ObjectLockMode != s3types.ObjectLockModeCompliance || obj.ObjectLockRetainUntilDate == nil {
		t.Fatalf("object not locked: mode %q until %v", obj.ObjectLockMode, obj.ObjectLockRetainUntilDate)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key),
		VersionId: aws.String(exports[0].ver)}); err == nil {
		t.Fatal("locked audit object was deleted")
	}

	// The runtime role cannot rewrite the export ledger either.
	err = postgres.Tx(scoped, db.App, func(tx pgx.Tx) error {
		tag, err := tx.Exec(scoped, `DELETE FROM audit_exports`)
		if err == nil && tag.RowsAffected() != 0 {
			t.Error("export records deleted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
