// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package auditexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Store writes to a bucket with Object Lock enabled.
type S3Store struct {
	client *s3.Client
	bucket string
	prefix string
	mode   s3types.ObjectLockMode
}

// NewS3 verifies that the bucket has Object Lock enabled. mode is COMPLIANCE
// (no one can shorten retention, not even the account root) or GOVERNANCE.
func NewS3(ctx context.Context, client *s3.Client, bucket, prefix, mode string) (*S3Store, error) {
	m := s3types.ObjectLockMode(strings.ToUpper(mode))
	if m != s3types.ObjectLockModeCompliance && m != s3types.ObjectLockModeGovernance {
		return nil, errors.New("object lock mode must be COMPLIANCE or GOVERNANCE")
	}
	out, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return nil, fmt.Errorf("audit export bucket %s: %w", bucket, err)
	}
	if out.ObjectLockConfiguration == nil || out.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		return nil, fmt.Errorf("audit export bucket %s does not have Object Lock enabled", bucket)
	}
	return &S3Store{client: client, bucket: bucket, prefix: strings.Trim(prefix, "/"), mode: m}, nil
}

func (s *S3Store) PutLocked(ctx context.Context, key string, body []byte, retainUntil time.Time) (string, string, error) {
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	out, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(body),
		ContentType: aws.String("application/x-ndjson"), ObjectLockMode: s.mode,
		ObjectLockRetainUntilDate: aws.Time(retainUntil), ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
	})
	if err != nil {
		return "", "", fmt.Errorf("put audit object: %w", err)
	}
	return "s3://" + s.bucket + "/" + key, aws.ToString(out.VersionId), nil
}
